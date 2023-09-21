mod common;

use common::setup_pie;
use rstest::*;
use serde_json::json;
use snos::pie::{encode_pie, encode_pie_mem};
use std::path::Path;

use cairo_vm::vm::runners::builtin_runner::OUTPUT_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_pie::{
    BuiltinAdditionalData, CairoPie, OutputBuiltinAdditionalData, SegmentInfo,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use std::collections::HashMap;

#[rstest]
fn pie_metadata_ok(setup_pie: CairoPie) {
    let pie_metadata = setup_pie.metadata;

    assert_eq!(pie_metadata.ret_pc_segment, SegmentInfo::from((4, 0)));
    assert_eq!(pie_metadata.ret_fp_segment, SegmentInfo::from((3, 0)));
    let expected_builtin_segments =
        HashMap::from([(String::from("output"), SegmentInfo::from((2, 3)))]);
    assert_eq!(pie_metadata.builtin_segments, expected_builtin_segments);
    assert_eq!(pie_metadata.program_segment, SegmentInfo::from((0, 12)));
    assert_eq!(pie_metadata.execution_segment, SegmentInfo::from((1, 7)));

    let metadata_s = serde_json::to_value(&pie_metadata);
    assert!(metadata_s.is_ok());
}

#[rstest]
fn pie_additional_data_ok(setup_pie: CairoPie) {
    let additional_data = setup_pie.additional_data;

    let expected_additional_data = HashMap::from([(
        OUTPUT_BUILTIN_NAME.to_string(),
        BuiltinAdditionalData::Output(OutputBuiltinAdditionalData {
            pages: HashMap::new(),
            attributes: HashMap::new(),
        }),
    )]);

    assert_eq!(additional_data, expected_additional_data);
    let additional_data_s = serde_json::to_value(&additional_data).unwrap();
    assert_eq!(
        additional_data_s,
        json!({"output_builtin": {"pages": {}, "attributes": {}}})
    );
}

#[rstest]
fn pie_execution_resources_ok(setup_pie: CairoPie) {
    let execution_resources = setup_pie.execution_resources;

    let expected_execution_resources = ExecutionResources {
        n_steps: 8,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(OUTPUT_BUILTIN_NAME.to_string(), 3)]),
    };
    assert_eq!(execution_resources, expected_execution_resources);

    let execution_resources_s = serde_json::to_value(&execution_resources).unwrap();
    assert_eq!(
        execution_resources_s,
        json!({"n_steps": 8, "n_memory_holes": 0, "builtin_instance_counter": {"output_builtin": 3}})
    );
}

#[rstest]
fn pie_version_ok(setup_pie: CairoPie) {
    let version = setup_pie.version;

    let version_s = serde_json::to_value(&version).unwrap();
    assert_eq!(version_s, json!({"cairo_pie": "1.1"}));
}

#[rstest]
fn pie_memory_ok(setup_pie: CairoPie) {
    let pie_s = serde_json::to_value(&setup_pie).unwrap();
    assert_eq!(pie_s["memory"], "00000000000000800080ff7f018006400000000000000000000000000000000000000000000000000100000000000080640000000000000000000000000000000000000000000000000000000000000002000000000000800080fd7f0080024800000000000000000000000000000000000000000000000003000000000000800080ff7f018006400000000000000000000000000000000000000000000000000400000000000080c80000000000000000000000000000000000000000000000000000000000000005000000000000800080fd7f0180024800000000000000000000000000000000000000000000000006000000000000800080ff7f0180064000000000000000000000000000000000000000000000000007000000000000802c0100000000000000000000000000000000000000000000000000000000000008000000000000800080fd7f0280024800000000000000000000000000000000000000000000000009000000000000800080fd7f018026480000000000000000000000000000000000000000000000000a0000000000008003000000000000000000000000000000000000000000000000000000000000000b00000000000080fe7fff7fff7f8b20000000000000000000000000000000000000000000000000000000000080008000000000000001000000000000000000000000000000000000000000000000800100000000800080000000000080010000000000000000000000000000000000000000000000008002000000008000800000000000000200000000000000000000000000000000000000000000000080030000000080008064000000000000000000000000000000000000000000000000000000000000000400000000800080c80000000000000000000000000000000000000000000000000000000000000005000000008000802c0100000000000000000000000000000000000000000000000000000000000006000000008000800300000000000100000000000000000000000000000000000000000000000080000000000000018064000000000000000000000000000000000000000000000000000000000000000100000000000180c80000000000000000000000000000000000000000000000000000000000000002000000000001802c01000000000000000000000000000000000000000000000000000000000000");
}

#[rstest]
fn prepare_pie_ok(setup_pie: CairoPie) {
    let disk_b64 = encode_pie(setup_pie.clone(), &Path::new("build/test.zip"));
    assert!(disk_b64.is_ok());

    let mem_b64 = encode_pie_mem(setup_pie);
    assert!(mem_b64.is_ok());
    assert_eq!(disk_b64.unwrap(), mem_b64.unwrap());
}
