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
    let pie_metadata = common::setup_pie().metadata;

    assert_eq!(pie_metadata.ret_pc_segment, SegmentInfo::from((4, 0)));
    assert_eq!(pie_metadata.ret_fp_segment, SegmentInfo::from((3, 0)));
    let expected_builtin_segments =
        HashMap::from([(String::from("output"), SegmentInfo::from((2, 3)))]);
    assert_eq!(pie_metadata.builtin_segments, expected_builtin_segments);
    assert_eq!(pie_metadata.program_segment, SegmentInfo::from((0, 12)));
    assert_eq!(pie_metadata.execution_segment, SegmentInfo::from((1, 7)));

    let metadata_s = serde_json::to_string_pretty(&pie_metadata);
    assert!(metadata_s.is_ok());
    // print!("META: {}", metadata_s.unwrap());
}

#[test]
fn pie_additional_data_ok() {
    let additional_data = common::setup_pie().additional_data;

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
    // print!("ADD: {}", additional_data_s.unwrap());
}

#[test]
fn pie_execution_resources_ok() {
    let execution_resources = common::setup_pie().execution_resources;

    let expected_execution_resources = ExecutionResources {
        n_steps: 8,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(OUTPUT_BUILTIN_NAME.to_string(), 3)]),
    };
    assert_eq!(execution_resources, expected_execution_resources);

    let execution_resources_s = serde_json::to_string_pretty(&execution_resources);
    assert!(execution_resources_s.is_ok());
    // print!("EXEC: {}", execution_resources_s.unwrap())
}

#[test]
fn pie_memory_ok() {
    let memory: CairoPieMemory = common::setup_pie().memory;

    let memory_bin = serialize_memory(memory);
    println!("Memory bin: {:?}", memory_bin);

    // let memory_s = serde_json::to_string_pretty(&memory);
    // assert!(memory_s.is_ok());
    // let memoryChecksum: u128 = 0x0;
    // assert_eq!(0x39b6a444d0487c64616c6066bda42f24, memoryChecksum);
}

#[test]
fn zip_pie_ok() {
    zip_pie("contracts/build");
}
