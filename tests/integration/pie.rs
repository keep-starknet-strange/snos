use std::collections::HashMap;
use std::path::Path;

use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::vm::runners::cairo_pie::{
    BuiltinAdditionalData, CairoPie, CairoPieAdditionalData, OutputBuiltinAdditionalData, SegmentInfo,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use rstest::rstest;
use serde_json::json;
use starknet_os::sharp::pie::{decode_base64_to_unzipped, PIE_FILES};

use crate::common::{os_pie_string, setup_pie};

#[rstest]
fn pie_metadata_ok(setup_pie: CairoPie) {
    let pie_metadata = setup_pie.metadata;

    assert_eq!(pie_metadata.ret_pc_segment, SegmentInfo::from((4, 0)));
    assert_eq!(pie_metadata.ret_fp_segment, SegmentInfo::from((3, 0)));
    let expected_builtin_segments = HashMap::from([(BuiltinName::output, SegmentInfo::from((2, 3)))]);
    assert_eq!(pie_metadata.builtin_segments, expected_builtin_segments);
    assert_eq!(pie_metadata.program_segment, SegmentInfo::from((0, 12)));
    assert_eq!(pie_metadata.execution_segment, SegmentInfo::from((1, 7)));

    let metadata_s = serde_json::to_value(&pie_metadata);
    assert!(metadata_s.is_ok());
}

#[rstest]
fn pie_additional_data_ok(setup_pie: CairoPie) {
    let additional_data = setup_pie.additional_data;

    let expected_additional_data = CairoPieAdditionalData(HashMap::from([(
        BuiltinName::output,
        BuiltinAdditionalData::Output(OutputBuiltinAdditionalData {
            pages: HashMap::new(),
            attributes: HashMap::new(),
        }),
    )]));

    assert_eq!(additional_data, expected_additional_data);
    let additional_data_s = serde_json::to_value(&additional_data).unwrap();
    assert_eq!(additional_data_s, json!({"output_builtin": {"pages": {}, "attributes": {}}}));
}

#[rstest]
fn pie_execution_resources_ok(setup_pie: CairoPie) {
    let execution_resources = setup_pie.execution_resources;

    let expected_execution_resources = ExecutionResources {
        n_steps: 8,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(BuiltinName::output, 3)]),
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

    let version_s = serde_json::to_value(version).unwrap();
    assert_eq!(version_s, json!({"cairo_pie": "1.1"}));
}

#[rstest]
fn pie_memory_ok(setup_pie: CairoPie) {
    let expected_memory_bin = include_bytes!("common/data/memory.bin");
    let expected_memory_bin = expected_memory_bin.iter().fold(String::new(), |acc, i| acc + &format!("{i:02x?}"));

    let pie_s = serde_json::to_value(setup_pie).unwrap();
    assert_eq!(expected_memory_bin, pie_s["memory"]);
}

#[rstest]
fn convert_b64_to_raw(os_pie_string: String) {
    let dst = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("build").join("pie");

    decode_base64_to_unzipped(&os_pie_string, dst.to_string_lossy().as_ref()).unwrap();

    for file in PIE_FILES {
        let file_path = dst.join(format!("{file:}.{:}", if file != "memory" { "json" } else { "bin" }));
        assert!(file_path.exists(), "Missing file {:}", file_path.to_string_lossy());
    }
}
