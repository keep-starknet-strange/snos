#[cfg(test)]
#[macro_use]
pub mod test_utils {

    // #[macro_export]
    // macro_rules! bigint {
    //     ($val : expr) => {
    //         Into::<num_bigint::BigInt>::into($val)
    //     };
    // }
    // pub(crate) use bigint;
    //
    // #[macro_export]
    // macro_rules! bigint_str {
    //     ($val: expr) => {
    //         num_bigint::BigInt::parse_bytes($val.as_bytes(), 10).expect("Couldn't parse bytes")
    //     };
    //     ($val: expr, $opt: expr) => {
    //         num_bigint::BigInt::parse_bytes($val.as_bytes(), $opt).expect("Couldn't parse bytes")
    //     };
    // }
    // pub(crate) use bigint_str;

    // #[macro_export]
    // macro_rules! biguint {
    //     ($val : expr) => {
    //         Into::<num_bigint::BigUint>::into($val as u128)
    //     };
    // }
    // pub(crate) use biguint;

    // #[macro_export]
    // macro_rules! biguint_str {
    //     ($val: expr) => {
    //         num_bigint::BigUint::parse_bytes($val.as_bytes(), 10).expect("Couldn't parse bytes")
    //     };
    //     ($val: expr, $opt: expr) => {
    //         num_bigint::BigUint::parse_bytes($val.as_bytes(), $opt).expect("Couldn't parse bytes")
    //     };
    // }
    // pub(crate) use biguint_str;

    // impl From<(&str, u8)> for MaybeRelocatable {
    //     fn from((string, radix): (&str, u8)) -> Self {
    //         MaybeRelocatable::Int(felt::felt_str!(string, radix))
    //     }
    // }

    macro_rules! segments {
        ($( (($si:expr, $off:expr), $val:tt) ),* $(,)? ) => {
            {
                let mut msm = cairo_vm::vm::vm_memory::memory_segments::MemorySegmentManager::new();
                memory!(msm, $( (($si, $off), $val) ),*);
                msm
            }

        };
    }
    pub(crate) use segments;

    macro_rules! memory {
        ($msm: expr, $( (($si:expr, $off:expr), $val:tt) ),* ) => {
            {
                memory_from_memory!($msm, ( $( (($si, $off), $val) ),* ));
            }
        };
    }
    pub(crate) use memory;

    macro_rules! memory_from_memory {
        ($msm: expr, ( $( (($si:expr, $off:expr), $val:tt) ),* )) => {
            {
                $(
                    memory_inner!($msm, ($si, $off), $val);
                )*
            }
        };
    }
    pub(crate) use memory_from_memory;

    macro_rules! memory_inner {
        ($msm:expr,($si:expr, $off:expr),($sival:expr, $offval:expr)) => {
            let (k, v) = (($si, $off).into(), mayberelocatable!($sival, $offval));
            let mut res = $msm.load_data(k, &vec![v.clone()]);
            while matches!(res, Err(cairo_vm::vm::errors::memory_errors::MemoryError::UnallocatedSegment(_))) {
                if $si < 0 {
                    $msm.add_temporary_segment();
                } else {
                    $msm.add();
                }
                res = $msm.load_data(k, &vec![v.clone()]);
            }
        };
        ($msm:expr,($si:expr, $off:expr), $val:expr) => {
            let (k, v) = (($si, $off).into(), mayberelocatable!($val));
            let mut res = $msm.load_data(k, &vec![v.clone()]);
            while matches!(res, Err(cairo_vm::vm::errors::memory_errors::MemoryError::UnallocatedSegment(_))) {
                if $si < 0 {
                    $msm.add_temporary_segment();
                } else {
                    $msm.add();
                }
                res = $msm.load_data(k, &vec![v.clone()]);
            }
        };
    }
    pub(crate) use memory_inner;

    // macro_rules! check_memory {
    //     ( $mem: expr, $( (($si:expr, $off:expr), $val:tt) ),* $(,)? ) => {
    //         $(
    //             check_memory_address!($mem, ($si, $off), $val);
    //         )*
    //     };
    // }
    // pub(crate) use check_memory;

    // macro_rules! check_memory_address {
    //     ($mem:expr, ($si:expr, $off:expr), ($sival:expr, $offval: expr)) => {
    //         assert_eq!(
    //             $mem.get(&mayberelocatable!($si, $off)).unwrap().as_ref(),
    //             &mayberelocatable!($sival, $offval)
    //         )
    //     };
    //     ($mem:expr, ($si:expr, $off:expr), $val:expr) => {
    //         assert_eq!(
    //             $mem.get(&mayberelocatable!($si, $off)).unwrap().as_ref(),
    //             &mayberelocatable!($val)
    //         )
    //     };
    // }
    // pub(crate) use check_memory_address;

    macro_rules! mayberelocatable {
        ($val1:expr, $val2:expr) => {
            cairo_vm::types::relocatable::MaybeRelocatable::from(($val1, $val2))
        };
        ($val1:expr) => {
            cairo_vm::types::relocatable::MaybeRelocatable::from(cairo_vm::Felt252::from($val1 as i128))
        };
    }
    pub(crate) use mayberelocatable;

    macro_rules! references {
        ($num:expr) => {{
            let mut references = HashMap::<usize, HintReference>::new();
            for i in 0..$num {
                references.insert(i as usize, HintReference::new_simple((i as i32 - $num)));
            }
            references
        }};
    }
    pub(crate) use references;

    // macro_rules! vm_with_range_check {
    //     () => {{
    //         let mut vm = VirtualMachine::new(false);
    //         vm.builtin_runners = vec![
    //             $crate::vm::runners::builtin_runner::RangeCheckBuiltinRunner::new(Some(8), 8, true)
    //                 .into(),
    //         ];
    //         vm
    //     }};
    // }
    // pub(crate) use vm_with_range_check;

    // macro_rules! cairo_runner {
    //     ($program:expr) => {
    //         CairoRunner::new(&$program, "all_cairo", false).unwrap()
    //     };
    //     ($program:expr, $layout:expr) => {
    //         CairoRunner::new(&$program, $layout, false).unwrap()
    //     };
    //     ($program:expr, $layout:expr, $proof_mode:expr) => {
    //         CairoRunner::new(&$program, $layout, $proof_mode).unwrap()
    //     };
    //     ($program:expr, $layout:expr, $proof_mode:expr) => {
    //         CairoRunner::new(&program, $layout.to_string(), proof_mode).unwrap()
    //     };
    // }
    // pub(crate) use cairo_runner;

    // pub(crate) use cairo_vm::stdlib::{collections::BTreeMap, sync::Arc};
    // pub(crate) use cairo_vm::types::program::HintsCollection;
    // pub(crate) use cairo_vm::types::program::Program;
    // pub(crate) use cairo_vm::types::program::SharedProgramData;
    // macro_rules! program {
    //     //Empty program
    //     () => {
    //         Program::default()
    //     };
    //     //Program with builtins
    //     ( $( $builtin_name: expr ),* ) => {{
    //         let shared_program_data = SharedProgramData {
    //             data: crate::stdlib::vec::Vec::new(),
    //             hints_collection: HintsCollection::new(&BTreeMap::new(), 0).unwrap(),
    //             main: None,
    //             start: None,
    //             end: None,
    //             error_message_attributes: crate::stdlib::vec::Vec::new(),
    //             instruction_locations: None,
    //             identifiers: crate::stdlib::collections::HashMap::new(),
    //             reference_manager: Program::get_reference_list(&ReferenceManager {
    //                 references: crate::stdlib::vec::Vec::new(),
    //             }),
    //         };
    //         Program {
    //             shared_program_data: Arc::new(shared_program_data),
    //             constants: crate::stdlib::collections::HashMap::new(),
    //             builtins: vec![$( $builtin_name ),*],
    //         }
    //     }};
    //     ($($field:ident = $value:expr),* $(,)?) => {{
    //
    //         let program_flat = crate::utils::test_utils::ProgramFlat {
    //             $(
    //                 $field: $value,
    //             )*
    //             ..Default::default()
    //         };
    //
    //         Into::<Program>::into(program_flat)
    //     }};
    // }
    //
    // pub(crate) use program;

    // pub(crate) struct ProgramFlat {
    //     pub(crate) data: crate::utils::Vec<MaybeRelocatable>,
    //     pub(crate) hints: crate::stdlib::collections::BTreeMap<
    //         usize,
    //         crate::utils::Vec<crate::serde::deserialize_program::HintParams>,
    //     >,
    //     pub(crate) main: Option<usize>,
    //     //start and end labels will only be used in proof-mode
    //     pub(crate) start: Option<usize>,
    //     pub(crate) end: Option<usize>,
    //     pub(crate) error_message_attributes:
    //     crate::utils::Vec<crate::serde::deserialize_program::Attribute>,
    //     pub(crate) instruction_locations: Option<
    //         crate::stdlib::collections::HashMap<
    //             usize,
    //             crate::serde::deserialize_program::InstructionLocation,
    //         >,
    //     >,
    //     pub(crate) identifiers: crate::stdlib::collections::HashMap<
    //         crate::stdlib::string::String,
    //         crate::serde::deserialize_program::Identifier,
    //     >,
    //     pub(crate) constants: crate::stdlib::collections::HashMap<
    //         crate::stdlib::string::String,
    //         crate::utils::Felt252,
    //     >,
    //     pub(crate) builtins: crate::utils::Vec<crate::serde::deserialize_program::BuiltinName>,
    //     pub(crate) reference_manager: crate::serde::deserialize_program::ReferenceManager,
    // }
    //
    // impl Default for ProgramFlat {
    //     fn default() -> Self {
    //         Self {
    //             data: Default::default(),
    //             hints: Default::default(),
    //             main: Default::default(),
    //             start: Default::default(),
    //             end: Default::default(),
    //             error_message_attributes: Default::default(),
    //             instruction_locations: Default::default(),
    //             identifiers: Default::default(),
    //             constants: Default::default(),
    //             builtins: Default::default(),
    //             reference_manager: crate::serde::deserialize_program::ReferenceManager {
    //                 references: crate::utils::Vec::new(),
    //             },
    //         }
    //     }
    // }
    //
    // impl From<ProgramFlat> for Program {
    //     fn from(val: ProgramFlat) -> Self {
    //         // NOTE: panics if hints have PCs higher than the program length
    //         let hints_collection =
    //             HintsCollection::new(&val.hints, val.data.len()).expect("hints are valid");
    //         Program {
    //             shared_program_data: Arc::new(SharedProgramData {
    //                 data: val.data,
    //                 hints_collection,
    //                 main: val.main,
    //                 start: val.start,
    //                 end: val.end,
    //                 error_message_attributes: val.error_message_attributes,
    //                 instruction_locations: val.instruction_locations,
    //                 identifiers: val.identifiers,
    //                 reference_manager: Program::get_reference_list(&val.reference_manager),
    //             }),
    //             constants: val.constants,
    //             builtins: val.builtins,
    //         }
    //     }
    // }

    // macro_rules! vm {
    //     () => {{
    //         VirtualMachine::new(false)
    //     }};
    //
    //     ($use_trace:expr) => {{
    //         VirtualMachine::new($use_trace)
    //     }};
    // }
    // pub(crate) use vm;

    // macro_rules! run_context {
    //     ( $vm: expr, $pc: expr, $ap: expr, $fp: expr ) => {
    //         $vm.run_context.pc = Relocatable::from((0, $pc));
    //         $vm.run_context.ap = $ap;
    //         $vm.run_context.fp = $fp;
    //     };
    // }
    // pub(crate) use run_context;

    macro_rules! ids_data {
        ( $( $name: expr ),* ) => {
            {
                let ids_names = vec![$( $name ),*];
                let references = references!(ids_names.len() as i32);
                let mut ids_data = HashMap::<String, HintReference>::new();
                for (i, name) in ids_names.iter().enumerate() {
                    ids_data.insert(ToString::to_string(name), references.get(&i).unwrap().clone());
                }
                ids_data
            }
        };
    }
    pub(crate) use ids_data;

    // macro_rules! non_continuous_ids_data {
    //     ( $( ($name: expr, $offset:expr) ),* $(,)? ) => {
    //         {
    //             let mut ids_data =
    // crate::stdlib::collections::HashMap::<crate::stdlib::string::String, HintReference>::new();
    //             $(
    //                 ids_data.insert(crate::stdlib::string::String::from($name),
    // HintReference::new_simple($offset));             )*
    //             ids_data
    //         }
    //     };
    // }
    // pub(crate) use non_continuous_ids_data;

    // #[track_caller]
    // pub(crate) fn trace_check(
    //     actual: &[TraceEntry],
    //     expected: &[(cairo_vm::utils::Relocatable, usize, usize)],
    // ) {
    //     assert_eq!(actual.len(), expected.len());
    //     for (entry, expected) in actual.iter().zip(expected.iter()) {
    //         assert_eq!(&(entry.pc, entry.ap, entry.fp), expected);
    //     }
    // }

    macro_rules! exec_scopes_ref {
        () => {
            &mut ExecutionScopes::new()
        };
    }
    pub(crate) use exec_scopes_ref;

    macro_rules! run_sn_hint {
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr, $constants:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let mut hint_processor = SnosHintProcessor::default();
            hint_processor.execute_hint_extensive(&mut $vm, $exec_scopes, &any_box!(hint_data), $constants)
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr) => {{
            let hint_data =
                HintProcessorData::new_default(crate::stdlib::string::ToString::to_string($hint_code), $ids_data);
            let mut hint_processor = SnosHintProcessor::default();
            hint_processor.execute_hint_extensive(&mut $vm, $exec_scopes, &any_box!(hint_data), &HashMap::new())
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr) => {{
            let hint_data = HintProcessorData::new_default(ToString::to_string($hint_code), $ids_data);
            let mut hint_processor = SnosHintProcessor::default();
            hint_processor.execute_hint_extensive(&mut $vm, exec_scopes_ref!(), &any_box!(hint_data), &HashMap::new())
        }};
    }
    pub(crate) use run_sn_hint;

    // macro_rules! add_segments {
    //     ($vm:expr, $n:expr) => {
    //         for _ in 0..$n {
    //             $vm.segments.add();
    //         }
    //     };
    // }
    // pub(crate) use add_segments;

    // macro_rules! check_scope {
    //     ( $exec_scope: expr, [ $( ($name: expr, $val: expr)),*$(,)? ] $(,)? ) => {
    //         $(
    //             check_scope_value($exec_scope, $name, $val);
    //         )*
    //     };
    // }
    // pub(crate) use check_scope;

    // macro_rules! scope {
    //     () => { ExecutionScopes::new() };
    //     (  $( ($name: expr, $val: expr)),* $(,)?  ) => {
    //         {
    //             let mut exec_scopes = ExecutionScopes::new();
    //             $(
    //                 exec_scopes.assign_or_update_variable(
    //                     $name,
    //                     any_box!($val),
    //                 );
    //             )*
    //             exec_scopes
    //         }
    //     };
    // }
    // pub(crate) use scope;

    // macro_rules! check_dictionary {
    //     ( $exec_scopes: expr, $tracker_num:expr, $( ($key:expr, $val:expr )),* ) => {
    //         $(
    //             assert_matches::assert_matches!(
    //                 $exec_scopes
    //                     .get_dict_manager()
    //                     .unwrap()
    //                     .borrow_mut()
    //                     .trackers
    //                     .get_mut(&$tracker_num)
    //                     .unwrap()
    //                     .get_value(&MaybeRelocatable::from($key)),
    //                 Ok(x) if x == &MaybeRelocatable::from($val)
    //             ));
    //         *
    //     };
    // }
    // pub(crate) use check_dictionary;

    // macro_rules! check_dict_ptr {
    //     ($exec_scopes: expr, $tracker_num: expr, ($i:expr, $off:expr)) => {
    //         assert_eq!(
    //             $exec_scopes
    //                 .get_dict_manager()
    //                 .unwrap()
    //                 .borrow()
    //                 .trackers
    //                 .get(&$tracker_num)
    //                 .unwrap()
    //                 .current_ptr,
    //             relocatable!($i, $off)
    //         );
    //     };
    // }
    // pub(crate) use check_dict_ptr;

    // macro_rules! dict_manager {
    //     ($exec_scopes:expr, $tracker_num:expr, $( ($key:expr, $val:expr )),* ) => {
    //         let mut tracker = DictTracker::new_empty(relocatable!($tracker_num, 0));
    //         $(
    //         tracker.insert_value(&MaybeRelocatable::from($key), &MaybeRelocatable::from($val));
    //         )*
    //         let mut dict_manager = DictManager::new();
    //         dict_manager.trackers.insert(2, tracker);
    //         $exec_scopes.insert_value("dict_manager",
    // crate::stdlib::rc::Rc::new(core::cell::RefCell::new(dict_manager)))     };
    //     ($exec_scopes:expr, $tracker_num:expr) => {
    //         let  tracker = DictTracker::new_empty(relocatable!($tracker_num, 0));
    //         let mut dict_manager = DictManager::new();
    //         dict_manager.trackers.insert(2, tracker);
    //         $exec_scopes.insert_value("dict_manager",
    // crate::stdlib::rc::Rc::new(core::cell::RefCell::new(dict_manager)))     };
    //
    // }
    // pub(crate) use dict_manager;

    // macro_rules! dict_manager_default {
    //     ($exec_scopes:expr, $tracker_num:expr,$default:expr, $( ($key:expr, $val:expr )),* ) => {
    //         let mut tracker = DictTracker::new_default_dict(relocatable!($tracker_num, 0),
    // &MaybeRelocatable::from($default), None);         $(
    //         tracker.insert_value(&MaybeRelocatable::from($key), &MaybeRelocatable::from($val));
    //         )*
    //         let mut dict_manager = DictManager::new();
    //         dict_manager.trackers.insert(2, tracker);
    //         $exec_scopes.insert_value("dict_manager",
    // crate::stdlib::rc::Rc::new(core::cell::RefCell::new(dict_manager)))     };
    //     ($exec_scopes:expr, $tracker_num:expr,$default:expr) => {
    //         let tracker = DictTracker::new_default_dict(relocatable!($tracker_num, 0),
    // &MaybeRelocatable::from($default), None);         let mut dict_manager =
    // DictManager::new();         dict_manager.trackers.insert(2, tracker);
    //         $exec_scopes.insert_value("dict_manager",
    // crate::stdlib::rc::Rc::new(core::cell::RefCell::new(dict_manager)))     };
    // }
    // pub(crate) use dict_manager_default;

    // macro_rules! vec_data {
    //     ( $( ($val:tt) ),* ) => {
    //         vec![$( vec_data_inner!($val) ),*]
    //     };
    // }
    // pub(crate) use vec_data;

    // macro_rules! vec_data_inner {
    //     (( $val1:expr, $val2:expr )) => {
    //         mayberelocatable!($val1, $val2)
    //     };
    //     ( $val:expr ) => {
    //         mayberelocatable!($val)
    //     };
    // }
    // pub(crate) use vec_data_inner;

    // pub fn check_scope_value<T: core::fmt::Debug + core::cmp::PartialEq + 'static>(
    //     scopes: &ExecutionScopes,
    //     name: &str,
    //     value: T,
    // ) {
    //     let scope_value = scopes.get_any_boxed_ref(name).unwrap();
    //     assert_eq!(scope_value.downcast_ref::<T>(), Some(&value));
    // }
}
