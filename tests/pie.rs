use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::builtin_runner::OUTPUT_BUILTIN_NAME;
use cairo_vm::vm::runners::cairo_pie::{
    BuiltinAdditionalData, CairoPieMemory, OutputBuiltinAdditionalData, SegmentInfo,
};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[test]
fn pie_ok() {
    let file = File::open(Path::new("contracts/build/fact.json")).expect("Couldn't load file");
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::<u8>::new();
    reader.read_to_end(&mut buffer).expect("Couldn't read file");

    let mut hint_processor = BuiltinHintProcessor::new_empty();
    //Run the cairo program
    let result = cairo_run(
        &buffer,
        &CairoRunConfig {
            layout: "small",
            ..Default::default()
        },
        &mut hint_processor,
    );
    assert!(result.is_ok());
    let (runner, vm) = result.unwrap();
    let result = runner.get_cairo_pie(&vm);
    assert!(result.is_ok());
    let cairo_pie = result.unwrap();

    let pie_metadata = cairo_pie.metadata;
    assert_eq!(pie_metadata.ret_pc_segment, SegmentInfo::from((4, 0)));
    assert_eq!(pie_metadata.ret_fp_segment, SegmentInfo::from((3, 0)));
    let expected_builtin_segments =
        HashMap::from([(String::from("output"), SegmentInfo::from((2, 3)))]);
    assert_eq!(pie_metadata.builtin_segments, expected_builtin_segments);
    assert_eq!(pie_metadata.program_segment, SegmentInfo::from((0, 12)));
    assert_eq!(pie_metadata.execution_segment, SegmentInfo::from((1, 7)));

    let expected_execution_resources = ExecutionResources {
        n_steps: 8,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(OUTPUT_BUILTIN_NAME.to_string(), 3)]),
    };
    assert_eq!(cairo_pie.execution_resources, expected_execution_resources);

    
    // memory
    // assert_eq!(
    //     cairo_pie.memory,
    //     Into::<CairoPieMemory>::into(&vm.segments.memory)
    // );
}
