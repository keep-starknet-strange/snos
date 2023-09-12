use snos::pie::serialize_memory;

mod common;

use cairo_vm::vm::runners::builtin_runner::OUTPUT_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_pie::{
    BuiltinAdditionalData, CairoPieMemory, OutputBuiltinAdditionalData, SegmentInfo,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use std::collections::HashMap;

#[test]
fn pie_metadata_ok() {
    let pie = common::setup_pie();
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
    let pie = common::setup_pie();
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
    let pie = common::setup_pie();
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
    let pie = common::setup_pie();
    let memory: CairoPieMemory = pie.memory;

    let _memory_bin = serialize_memory(memory);
}

// #[test]
// fn zip_pie_ok() {
//     zip_pie("build");
// }
