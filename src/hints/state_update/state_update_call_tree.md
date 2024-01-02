

## `state_update` call tree
* [os](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/os.cairo#L31)
  * [hint](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/os.cairo#L49)
  * [state_update](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L143)
    * [contract_state_update](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L305)
      * [hash_state_changes](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L399)
        * [hint](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L419)
        * [patricia_update_using_update_constants](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L468)
          * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L481)
          * [traverse_node](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L388)
            * [traverse_empty](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L81)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L94)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L102)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L106)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L112)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L135C41-L135C48)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L142)
            * [traverse_non_empty](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L401)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L404)
              * [open_edge](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L23)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L29)
              * [traverse_edge](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L154)
                * traverse_binary_or_leaf
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L164)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L173)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L180)
                * traverse_edge
                * traverse_empty
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L211)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L217)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L236)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L252)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L292)
              * [traverse_binary_of_leaf](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L307)
                * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L328)
                * traverse_non_empty
          * [traverse_node](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L539)
            * ...
        * [get_contract_state_hash](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L372)
        * [serialize_da_changes](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L73)
      * [hint](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L344)
      * patricia_update_using_update_constants
    * [contract_class_update](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L197)
      * similar to contract_state_update but not the same
  * [calculate_global_state_root](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L120)
## data structures
[StateEntry]()
```
  struct StateEntry {
    class_hash: felt,
    storage_ptr: DictAccess*,
    nonce: felt,
  }
```
* 