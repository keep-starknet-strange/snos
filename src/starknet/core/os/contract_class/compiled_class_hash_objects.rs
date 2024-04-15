use cairo_vm::Felt252;

use crate::starkware_utils::commitment_tree::base_types::Length;

/// Represents the structure of the bytecode to allow loading it partially into the OS memory.
/// See the documentation of the OS function `bytecode_hash_node` in `compiled_class.cairo`
/// for more details.
pub trait BytecodeSegmentStructure {}

/// All types implementing BytecodeSegmentStructure.
///
/// We use an enum to avoid Box<dyn BytecodeSegmentStructure>. We need structs in this module
/// to implement Clone and `BytecodeSegment.inner_structure` can refer to any struct implementing
/// `BytecodeSegmentStructure`.
#[derive(Clone, Debug)]
pub enum BytecodeSegmentStructureImpl {
    SegmentedNode(BytecodeSegmentedNode),
    Leaf(BytecodeLeaf),
}

/// Represents a child of BytecodeSegmentedNode.
#[derive(Clone, Debug)]
pub struct BytecodeSegment {
    /// The length of the segment.
    pub segment_length: Length,
    /// Should the segment (or part of it) be loaded to memory.
    /// In other words, is the segment used during the execution.
    /// Note that if is_used is False, the entire segment is not loaded to memory.
    /// If is_used is True, it is possible that part of the segment will be skipped (according
    /// to the "is_used" field of the child segments).
    pub is_used: bool,
    /// The inner structure of the segment.
    pub inner_structure: BytecodeSegmentStructureImpl,
}

#[derive(Clone, Debug)]
pub struct BytecodeSegmentedNode {
    pub segments: Vec<BytecodeSegment>,
}

/// Represents a leaf in the bytecode segment tree.
#[derive(Clone, Debug)]
pub struct BytecodeLeaf {
    pub data: Vec<Felt252>,
}
