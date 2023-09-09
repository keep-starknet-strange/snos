use snos::pie::{serialize_memory, zip_pie};

mod common;

use cairo_vm::vm::runners::builtin_runner::OUTPUT_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_pie::{
    BuiltinAdditionalData, CairoPieMemory, OutputBuiltinAdditionalData, SegmentInfo,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use std::collections::HashMap;

#[test]
fn pie_metadata_ok() {
    let (pie, _) = common::setup_pie();
    let pie_metadata = pie.metadata;

    assert_eq!(pie_metadata.ret_pc_segment, SegmentInfo::from((4, 0)));
    assert_eq!(pie_metadata.ret_fp_segment, SegmentInfo::from((3, 0)));
    let expected_builtin_segments =
        HashMap::from([(String::from("output"), SegmentInfo::from((2, 3)))]);
    assert_eq!(pie_metadata.builtin_segments, expected_builtin_segments);
    assert_eq!(pie_metadata.program_segment, SegmentInfo::from((0, 12)));
    assert_eq!(pie_metadata.execution_segment, SegmentInfo::from((1, 7)));

    let metadata_s = serde_json::to_string_pretty(&pie_metadata);
    assert!(metadata_s.is_ok());
}

#[test]
fn pie_additional_data_ok() {
    let (pie, _) = common::setup_pie();
    let additional_data = pie.additional_data;

    let expected_additional_data = HashMap::from([(
        OUTPUT_BUILTIN_NAME.to_string(),
        BuiltinAdditionalData::Output(OutputBuiltinAdditionalData {
            pages: HashMap::new(),
            attributes: HashMap::new(),
        }),
    )]);

    assert_eq!(additional_data, expected_additional_data);
    let additional_data_s = serde_json::to_string_pretty(&additional_data);
    assert!(additional_data_s.is_ok());
}

#[test]
fn pie_execution_resources_ok() {
    let (pie, _) = common::setup_pie();
    let execution_resources = pie.execution_resources;

    let expected_execution_resources = ExecutionResources {
        n_steps: 8,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(OUTPUT_BUILTIN_NAME.to_string(), 3)]),
    };
    assert_eq!(execution_resources, expected_execution_resources);

    let execution_resources_s = serde_json::to_string_pretty(&execution_resources);
    assert!(execution_resources_s.is_ok());
}

#[test]
fn pie_memory_ok() {
    let (pie, relocated_memory) = common::setup_pie();
    let memory: CairoPieMemory = pie.memory;

    let memory_bin = serialize_memory(memory, relocated_memory);

    let expected_mem = String::from("00000000000000800080ff7f018006400000000000000000000000000000000000000000000000000100000000000080640000000000000000000000000000000000000000000000000000000000000002000000000000800080fd7f0080024800000000000000000000000000000000000000000000000003000000000000800080ff7f018006400000000000000000000000000000000000000000000000000400000000000080c80000000000000000000000000000000000000000000000000000000000000005000000000000800080fd7f0180024800000000000000000000000000000000000000000000000006000000000000800080ff7f0180064000000000000000000000000000000000000000000000000007000000000000802c0100000000000000000000000000000000000000000000000000000000000008000000000000800080fd7f0280024800000000000000000000000000000000000000000000000009000000000000800080fd7f018026480000000000000000000000000000000000000000000000000a0000000000008003000000000000000000000000000000000000000000000000000000000000000b00000000000080fe7fff7fff7f8b2000000000000000000000000000000000000000000000000000000000008000800000000000000100000000000000000000000000000000000000000000000080010000000080008000000000008001000000000000000000000000000000000000000000000000800200000000800080000000000000020000000000000000000000000000000000000000000000008003000000008000806400000000000000000000000000000000000000000000000000000000000000000000000000018064000000000000000000000000000000000000000000000000000000000000000400000000800080c8000000000000000000000000000000000000000000000000000000000000000100000000000180c80000000000000000000000000000000000000000000000000000000000000005000000008000802c0100000000000000000000000000000000000000000000000000000000000002000000000001802c0100000000000000000000000000000000000000000000000000000000000006000000008000800300000000000100000000000000000000000000000000000000000000000080");
    assert_eq!(expected_mem, hex::encode(memory_bin));
}

#[test]
fn zip_pie_ok() {
    zip_pie("contracts/build");
}
