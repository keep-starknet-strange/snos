use std::collections::{HashMap, VecDeque};

use cairo_vm::types::errors::math_errors::MathError;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::Felt252;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use crate::starkware_utils::commitment_tree::base_types::{DescentMap, Height, NodePath};
use crate::starkware_utils::commitment_tree::update_tree::{TreeUpdate, UpdateTree};

type Preimage = HashMap<Felt252, Vec<Felt252>>;
type Triplet = (Felt252, Felt252, Felt252);

fn empty_triplet() -> Triplet {
    (Felt252::ZERO, Felt252::ZERO, Felt252::ZERO)
}

#[derive(thiserror::Error, Debug)]
pub enum DescentError {
    #[error("Key not found in preimage: {0}")]
    PreimageNotFound(Felt252),

    #[error("Expected a branch")]
    IsNotBranch,

    #[error("The heights of the trees do not match")]
    TreeHeightMismatch,

    #[error(transparent)]
    Math(#[from] MathError),
}

impl From<DescentError> for HintError {
    fn from(descent_error: DescentError) -> Self {
        match descent_error {
            DescentError::Math(e) => HintError::Math(e),
            other => HintError::CustomHint(other.to_string().into_boxed_str()),
        }
    }
}

/// Retrieves the children of a node. Assumes canonic representation.
fn get_children(preimage: &Preimage, node: &Triplet) -> Result<(Triplet, Triplet), DescentError> {
    let length = node.0;
    let word = node.1;
    let node_hash = node.2;

    if length == Felt252::ZERO {
        let (left, right) = if node_hash == Felt252::ZERO {
            (Felt252::ZERO, Felt252::ZERO)
        } else {
            let node_preimage = preimage.get(&node_hash).ok_or(DescentError::PreimageNotFound(node_hash))?;
            (node_preimage[0], node_preimage[1])
        };

        return Ok((canonic(preimage, left), canonic(preimage, right)));
    }

    let length_u64 = length.to_u64().ok_or(MathError::Felt252ToU64Conversion(Box::new(length)))?;

    if word.to_biguint() >> (length_u64 - 1) == BigUint::from(0u64) {
        return Ok(((length - 1, word, node_hash), empty_triplet()));
    }

    Ok((empty_triplet(), (length - 1, word - (1 << (length_u64 - 1)), node_hash)))
}

enum PreimageNode<'preimage> {
    Leaf,
    Branch { left: Option<PreimageNodeIterator<'preimage>>, right: Option<PreimageNodeIterator<'preimage>> },
}

struct PreimageNodeIterator<'preimage> {
    height: Height,
    preimage: &'preimage Preimage,
    queue: VecDeque<PreimageNode<'preimage>>,
}
impl<'preimage> PreimageNodeIterator<'preimage> {
    fn new(height: Height, preimage: &'preimage Preimage, node: &Triplet) -> Result<Self, DescentError> {
        let mut iter = Self { height, preimage, queue: VecDeque::new() };
        iter.fill_queue(node)?;
        Ok(iter)
    }

    fn fill_queue(&mut self, node: &Triplet) -> Result<(), DescentError> {
        // Check for children
        if self.height.0 == 0 {
            self.queue.push_back(PreimageNode::Leaf);
            return Ok(());
        }
        let (left, right) = get_children(self.preimage, node)?;
        let empty_node = empty_triplet();

        let left_child = if left == empty_node {
            None
        } else {
            Some(PreimageNodeIterator::new(self.height - 1, self.preimage, &left)?)
        };
        let right_child = if right == empty_node {
            None
        } else {
            Some(PreimageNodeIterator::new(self.height - 1, self.preimage, &right)?)
        };

        self.queue.push_back(PreimageNode::Branch { left: left_child, right: right_child });

        Ok(())
    }
}

impl<'preimage> Iterator for PreimageNodeIterator<'preimage> {
    type Item = PreimageNode<'preimage>;

    fn next(&mut self) -> Option<Self::Item> {
        self.queue.pop_front()
    }
}

/// Builds a tree structure similar to build_update_tree(), from a root hash, and a preimage
/// dictionary.
/// The Python implementation returns a generator as follows:
/// * if node is a leaf: [0]
/// * Otherwise: [left, right] where each child is either None if empty or a generator defined
/// recursively.
/// Note that this does not necessarily traverse the entire tree. The caller may open the branches
/// as they wish.
fn preimage_tree<'preimage>(
    height: Height,
    preimage: &'preimage Preimage,
    node: &Triplet,
) -> Result<PreimageNodeIterator<'preimage>, DescentError> {
    PreimageNodeIterator::new(height, preimage, node)
}

/// Builds a descent map given multiple trees.
/// A descent is a maximal subpath s.t.
/// 1. In each tree, the authentication subpath consists of empty nodes.
/// 2. The subpath is longer than 1.
///
/// Returns descents as a map: (height, path_to_upper_node) -> (subpath_length, subpath).
/// The function does not return descents that begin at an empty node in the first tree.
///
/// Note: This function will be called with 3 trees:
///   The modifications tree, previous tree, new tree.
///
/// Args:
/// height - height of the current node. The length of a path from the node to a leaf.
/// path - path from the root to the current node.
/// nodes - a list of 'node' structures, similar to build_update_tree().
///   In particular, it is assumed that a non empty node cannot have two empty children.
fn get_descents<LF>(
    mut height: Height,
    mut path: NodePath,
    mut update_tree: &UpdateTree<LF>,
    mut previous_tree: Option<PreimageNodeIterator>,
    mut new_tree: Option<PreimageNodeIterator>,
) -> Result<DescentMap, DescentError>
where
    LF: Clone,
{
    let mut descent_map = DescentMap::new();

    if update_tree.is_none() || height.0 == 0 {
        return Ok(descent_map);
    }

    // Find longest edge.
    let orig_height = height;
    let orig_path = path.clone();

    // Traverse all the trees simultaneously, as long as they all satisfy the descent condition,
    // to find the maximal descent subpath.
    // Compared to the Python implementation, we unroll the loop to avoid having to Box<dyn>
    // everything to emulate duck-typing.
    let (lefts, rights) = loop {
        let (update_left, update_right) = match update_tree {
            None => return Err(DescentError::TreeHeightMismatch),

            Some(TreeUpdate::Leaf(_)) => {
                return Err(DescentError::IsNotBranch);
            }
            Some(TreeUpdate::Tuple(left, right)) => (left.as_ref(), right.as_ref()),
        };

        let (previous_left, previous_right) = match previous_tree {
            None => (None, None),
            Some(mut iter) => match iter.next().ok_or(DescentError::TreeHeightMismatch)? {
                PreimageNode::Leaf => {
                    return Err(DescentError::IsNotBranch);
                }
                PreimageNode::Branch { left, right } => (left, right),
            },
        };

        let (new_left, new_right) = match new_tree {
            None => (None, None),
            Some(mut iter) => match iter.next().ok_or(DescentError::TreeHeightMismatch)? {
                PreimageNode::Leaf => {
                    return Err(DescentError::IsNotBranch);
                }
                PreimageNode::Branch { left, right } => (left, right),
            },
        };

        // Note: we decrement height in each branch to avoid having to clone the nodes.
        // This results in a bit of (ugly) duplication.
        if update_left.is_none() && previous_left.is_none() && new_left.is_none() {
            path = NodePath(path.0 * 2u64 + 1u64);
            height = Height(height.0 - 1);
            if height.0 == 0 {
                break ((update_left, previous_left, new_left), (update_right, previous_right, new_right));
            }

            update_tree = update_right;
            previous_tree = previous_right;
            new_tree = new_right;
        } else if update_right.is_none() && previous_right.is_none() && new_right.is_none() {
            path = NodePath(path.0 * 2u64);
            height = Height(height.0 - 1);
            if height.0 == 0 {
                break ((update_left, previous_left, new_left), (update_right, previous_right, new_right));
            }

            update_tree = update_left;
            previous_tree = previous_left;
            new_tree = new_left;
        } else {
            break ((update_left, previous_left, new_left), (update_right, previous_right, new_right));
        }
    };

    let length = orig_height.0 - height.0;
    // length <= 1 is not a descent.
    if length > 1 {
        descent_map.insert(
            (Felt252::from(orig_height.0), Felt252::from(orig_path.0)),
            vec![Felt252::from(length), Felt252::from(&path.0 % (BigUint::from(1u64) << length))],
        );
    }

    if height.0 > 0 {
        let next_height = Height(height.0 - 1);
        descent_map.extend(get_descents(next_height, NodePath(&path.0 * 2u64), lefts.0, lefts.1, lefts.2)?);
        descent_map.extend(get_descents(next_height, NodePath(path.0 * 2u64 + 1u64), rights.0, rights.1, rights.2)?);
    }

    Ok(descent_map)
}

/// Returns the canonic encoding of a node hash as a triplet.
/// This implies that if the returned encoding is (0, 0, node_hash), then node_hash is not an edge
/// node.
fn canonic(preimage: &Preimage, node_hash: Felt252) -> Triplet {
    if let Some(back) = preimage.get(&node_hash) {
        if back.len() == 3 {
            return (back[0], back[1], back[2]);
        }
    }
    (Felt252::ZERO, Felt252::ZERO, node_hash)
}

/// Builds a descent map for a Patricia update. See get_descents().
/// node - The modification tree for the patricia update, given by build_update_tree().
pub fn patricia_guess_descents<LF>(
    height: Height,
    node: UpdateTree<LF>,
    preimage: &Preimage,
    prev_root: BigUint,
    new_root: BigUint,
) -> Result<DescentMap, DescentError>
where
    LF: Clone,
{
    let node_prev = preimage_tree(height, preimage, &canonic(preimage, Felt252::from(prev_root)))?;
    let node_new = preimage_tree(height, preimage, &canonic(preimage, Felt252::from(new_root)))?;

    get_descents::<LF>(height, NodePath(BigUint::from(0u64)), &node, Some(node_prev), Some(node_new))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::starkware_utils::commitment_tree::base_types::TreeIndex;
    use crate::starkware_utils::commitment_tree::update_tree::build_update_tree;
    use crate::storage::storage_utils::SimpleLeafFact;

    type LF = SimpleLeafFact;

    fn build_full_tree(height: Height, path: NodePath) -> UpdateTree<LF> {
        if height.0 == 0 {
            return Some(TreeUpdate::Leaf(LF::new(Felt252::from(path.0))));
        }
        Some(TreeUpdate::Tuple(
            Box::new(build_full_tree(Height(height.0 - 1), NodePath(path.0.clone() * 2u64))),
            Box::new(build_full_tree(Height(height.0 - 1), NodePath(path.0 * 2u64 + 1u64))),
        ))
    }

    fn build_full_preimage(height: Height, root_hash: Felt252) -> Preimage {
        let mut preimage = Preimage::new();
        let left_child_hash = root_hash * Felt252::TWO;
        let right_child_hash = root_hash * Felt252::TWO + Felt252::ONE;
        preimage.insert(root_hash, vec![left_child_hash, right_child_hash]);

        // We can stop at height 1, the leaf nodes are not relevant.
        if height.0 > 1 {
            let next_height = Height(height.0 - 1);
            preimage.extend(build_full_preimage(next_height, left_child_hash));
            preimage.extend(build_full_preimage(next_height, right_child_hash));
        }
        preimage
    }

    fn print_descent_map(descent_map: &DescentMap) {
        for (key, value) in descent_map {
            println!(
                "{}-{}: {:?}",
                key.0.to_biguint(),
                key.1.to_biguint(),
                value.iter().map(|x| x.to_biguint()).collect::<Vec<_>>()
            )
        }
    }

    #[test]
    fn test_get_descents_empty() {
        let descent_map = get_descents::<LF>(Height(1), NodePath(BigUint::from(0u64)), &None, None, None).unwrap();
        assert!(descent_map.is_empty());
    }

    /// The descent map for a full tree should be empty.
    #[rstest]
    fn test_guess_descents_full_tree() {
        // Create a full tree of height 3
        let height = Height(3);
        let update_tree = build_full_tree(height, NodePath(0u64.into()));

        let prev_root = BigUint::from(1u64);
        let new_root = BigUint::from(100u64);
        let preimage = {
            let mut preimage = build_full_preimage(height, Felt252::from(prev_root.clone()));
            preimage.extend(build_full_preimage(height, Felt252::from(new_root.clone())));
            preimage
        };

        let descent_map = patricia_guess_descents::<LF>(height, update_tree, &preimage, prev_root, new_root).unwrap();
        assert!(descent_map.is_empty());
    }

    /// Tests generating a descent map for an update tree of one element, against
    /// an empty tree. The new tree is also empty to have the descent map reflect
    /// the structure of the update tree and nothing else.
    #[rstest]
    fn test_guess_descents_update_one_leaf() {
        let height = Height(3);

        // The update tree should look like this:
        //        0
        //    0       0
        //  0   0   0   0
        // 0 u 0 0 0 0 0 0
        // Resulting in a descent of 3.
        let update_tree = build_update_tree(height, vec![(TreeIndex::from(1u64), LF::new(Felt252::from(128)))]);

        // Start from an empty tree
        let prev_root = BigUint::from(0u64);
        // Setting an empty tree as end state works for testing the function.
        // The descent map will then only depend on the structure of the update tree.
        // Of course this does not make any sense in a real-setting.
        let new_root = BigUint::from(0u64);

        let preimage = Preimage::new();

        let descent_map = patricia_guess_descents::<LF>(height, update_tree, &preimage, prev_root, new_root).unwrap();
        print_descent_map(&descent_map);
        assert_eq!(
            descent_map,
            DescentMap::from([((Felt252::from(3), Felt252::from(0)), vec![Felt252::from(3), Felt252::from(1)])]),
        );
    }

    /// Tests generating a descent map for an update tree of two adjacent leaves, against
    /// an empty tree. The new tree is also empty to have the descent map reflect
    /// the structure of the update tree and nothing else.
    #[rstest]
    fn test_guess_descents_update_two_adjacent_leaves() {
        let height = Height(3);

        // The update tree should look like this:
        //        0
        //    0       0
        //  0   0   0   0
        // u u 0 0 0 0 0 0
        // Resulting in a descent of 2.
        let update_tree = build_update_tree(
            height,
            vec![
                (TreeIndex::from(0u64), LF::new(Felt252::from(127))),
                (TreeIndex::from(1u64), LF::new(Felt252::from(128))),
            ],
        );

        // Start from an empty tree
        let prev_root = BigUint::from(0u64);
        // Setting an empty tree as end state works for testing the function.
        // The descent map will then only depend on the structure of the update tree.
        // Of course this does not make any sense in a real-setting.
        let new_root = BigUint::from(0u64);

        let preimage = Preimage::new();

        let descent_map = patricia_guess_descents::<LF>(height, update_tree, &preimage, prev_root, new_root).unwrap();
        print_descent_map(&descent_map);
        assert_eq!(
            descent_map,
            DescentMap::from([((Felt252::from(3), Felt252::from(0)), vec![Felt252::from(2), Felt252::from(0)])]),
        );
    }

    /// Tests generating a descent map for an update tree of two leaves, against
    /// an empty tree. The new tree is also empty to have the descent map reflect
    /// the structure of the update tree and nothing else.
    #[rstest]
    fn test_guess_descents_update_two_leaves() {
        let height = Height(3);

        // The update tree should look like this:
        //        0
        //    0       0
        //  0   0   0   0
        // 0 u 0 0 u 0 0 0
        // Resulting in two descents of 3.
        let update_tree = build_update_tree(
            height,
            vec![
                (TreeIndex::from(1u64), LF::new(Felt252::from(128))),
                (TreeIndex::from(4u64), LF::new(Felt252::from(129))),
            ],
        );

        // Start from an empty tree
        let prev_root = BigUint::from(0u64);
        // Setting an empty tree as end state works for testing the function.
        // The descent map will then only depend on the structure of the update tree.
        // Of course this does not make any sense in a real-setting.
        let new_root = BigUint::from(0u64);

        let preimage = Preimage::new();

        let descent_map = patricia_guess_descents::<LF>(height, update_tree, &preimage, prev_root, new_root).unwrap();
        print_descent_map(&descent_map);
        assert_eq!(
            descent_map,
            DescentMap::from([
                ((Felt252::from(2), Felt252::from(0)), vec![Felt252::from(2), Felt252::from(1)]),
                ((Felt252::from(2), Felt252::from(1)), vec![Felt252::from(2), Felt252::from(0)]),
            ]),
        );
    }
}
