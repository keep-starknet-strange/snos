## `contract call` call tree 
* [main](https://github.com/starkware-libs/cairo-lang/blob/27a157d761ae49b242026bcbe5fca6e60c1e98bd/src/starkware/starknet/core/os/os.cairo#L31)
  * [execute_transactions](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L111)
    * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L145)
    * [execute_transactions_inner](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L193)
      * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L208)
      * [execute_invoke_function_transaction](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L335)
        * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L354)
        * [many small hints](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L367)
        * [compute_invoke_transaction_hash](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/transaction_hash/transaction_hash.cairo#L169)
          * [deprecated_get_transaction_hash](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/transaction_hash/transaction_hash.cairo#L68)
        * [update_builtin_ptrs](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/builtins.cairo#L104)
          * ...
        * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L404C7-L404C7)
        * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L414)
        * [check_and_increment_nonce](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L630)
          * ...
        * [run_validate](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L669)
          * [select_execute_entry_point_func](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_entry_point.cairo#L205){#select_execute_entry_point_func}
            * [deprecated_execute_entry_point](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_entry_point.cairo#L102)
              * ...
            * [execute_entry_point](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_entry_point.cairo#L138)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_entry_point.cairo#L180)
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_entry_point.cairo#L215)
              * `call abs contract_entry_point;` - syscall_handler is set to either:
                * syscall_handler - see [below](#how-syscall_handler-does-contract-calls)
                * deprecated_syscall_handler
              * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_entry_point.cairo#L234)
              * [call_execute_syscalls](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_entry_point.cairo#L73)
                * `jmp abs block_context.execute_syscalls_ptr` - which is:
                  * [execute_syscalls](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_syscalls.cairo#L166) - see [below](#how-execute_syscalls-works)
                  * [execute_deprecated_syscalls](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_syscalls.cairo#L397) - ...
          * [hint](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L705)
        * [update_class_hash_in_execution_context](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L596) - why it is updated _after_ run_validate?
        * [select_execute_entry_point](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_transactions.cairo#L455)

## how `syscall_handler` does contract calls
Cairo 1 syscalls are invoked via hints generated by the compiler: `syscall_handler.syscall(syscall_ptr={})` ([see](https://github.com/starkware-libs/cairo/blob/e611d09d3d957cea09c4e7964bcf8975d980d4b4/crates/cairo-lang-casm/src/hints/mod.rs#L772)):
* [syscall](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/syscall_handler.py#L263)
  * [call_contract](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/syscall_handler.py#L297)
    * [call_contract_helper](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/syscall_handler.py#L307)
      * [_call_contract_helper](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/syscall_handler.py#L1360) - result is only read here, no actual execution

## how `deprecated_syscall_handler` does contract calls
Deprecated syscalls are called via [syscalls.cairo](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/common/syscalls.cairo#L42):
* ...

## how `execute_syscalls` works
* [execute_syscalls](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_syscalls.cairo#L166)
  * [execute_call_contract](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_syscalls.cairo#L383)
    * [contract_call_helper](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/execute_syscalls.cairo#L475)
     * [select_execute_entry_point_func](https://github.com/starkware-libs/cairo-lang/blob/caba294d82eeeccc3d86a158adb8ba209bf2d8fc/src/starkware/starknet/core/os/execution/deprecated_execute_entry_point.cairo#L205)