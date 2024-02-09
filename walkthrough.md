# SNOS
![Architecture](/home/maciejka/Downloads/snos.png)

## Data Structures
### OsHints
  * [OsHints](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/os_input.py#L50)
  * [StarknetOsInput](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/os_input.py#L29)
  * [CommitmentInfo](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/storage/starknet_storage.py#L29)
  * [OsExecutionHelper](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/syscall_handler.py#L1133)
  * [OsSingleStarknetStorage](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/storage/starknet_storage.py#L92)
  * [TransactionExecutionInfo](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/business_logic/execution/objects.py#L458)
  * [CallInfo](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/business_logic/execution/objects.py#L255)
### State Changes
  * [initialize_state_changes](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/os.cairo#L141)


## Code Walkthrough
* [main](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/os.cairo#L31)
### Transaction Reexecution
  * [execute_transactions](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L111)
    * [execute_transactions_inner](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L193C6-L193C32)
    * [execute_invoke_function_transaction](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L335)
  * [select_execute_entry_point_func](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_entry_point.cairo#L205)
    * [deprecated_execute_entry_point - contract call](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_entry_point.cairo#L168)
      * call contract
        * [syscalls - call contract](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/common/syscalls.cairo#L42)
          * [deprecated_syscall_handler - call contract](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/deprecated_syscall_handler.py#L781)
      * storage read
        * [syscalls - storage_read](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/common/syscalls.cairo#L352)
          * [_storage_read](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/deprecated_syscall_handler.py#L801)
    * [back to deprecated_execute_entry_point](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_entry_point.cairo#L194)
    * [execute_deprecated_syscalls](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_syscalls.cairo#L397)
      * call contract
        * [execute_deprecated_syscalls - call contract](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_syscalls.cairo#L451)
        * [contract_call_helper](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_syscalls.cairo#L82)
      * storage read
        * [execute_deprecated_syscalls - read storage](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_syscalls.cairo#L415)
        * [execute_storage_read](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_syscalls.cairo#L304)
### State Update
  * [state_update](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L143)
    * interesting hints:
      * [compute_storage_commitments](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/syscall_handler.py#L1223)
        * [compute_commitment](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/storage/starknet_storage.py#L138)
          * [update_tree](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starkware_utils/commitment_tree/update_tree.py#L23)
    * [contract_state_update](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L305)
      * [hash_state_changes](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/state.cairo#L399)
        * [patricia_update_using_update_constants](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L468)
          * interesting hints:
            * [build modifications list](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L481)
            * [build_update_tree](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/python/merkle_tree.py#L4)
            * [patricia_guess_descents](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia_utils.py#L242)
            * [get_descents](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia_utils.py#L126)
          * [traverse_node](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L388)
            * [traverse_edge](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L154)
            * [traverse_binary_of_leaf](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L307)
            * [open_edge](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/cairo/common/patricia.cairo#L23)


### Output
  * [os_output_serialize](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/output.cairo#L41)
  