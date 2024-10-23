use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::Felt252;
use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use prove_block::{prove_block, get_memory_segment, debug_prove_error};
use cairo_vm::types::layout_name::LayoutName;

#[tokio::test(flavor = "multi_thread")]
async fn run_test() {
    // fetch_pie_from_remote;
    let reference_pie_bytes = include_bytes!("../reference-pies/173404.zip").to_vec();
    let reference_pie = CairoPie::from_bytes(&reference_pie_bytes).expect("reference PIE");
    reference_pie.run_validity_checks().expect("Valid reference PIE");

    let block_number: u64 = felt_to_usize(&get_pie_block_number(&reference_pie))
        .unwrap()
        .try_into()
        .expect("Block number is too big");

    let endpoint = "http://localhost:9545";
    let (snos_pie, _snos_output) = prove_block(block_number, &endpoint, LayoutName::all_cairo, true)
        .await
        .map_err(debug_prove_error)
        .expect("OS generate Cairo PIE");

    snos_pie.run_validity_checks().expect("Valid SNOS PIE");

    let output_segment_index = 2;
    assert_eq!(
        get_memory_segment(&reference_pie, output_segment_index),
        get_memory_segment(&snos_pie, output_segment_index)
    );
}


fn get_pie_block_number(cairo_pie: &CairoPie) -> Felt252 {
    // We know that current block number is on position (2,3)
    // Output segment, position 3.
    let output_segment_index = 2_usize;
    let current_block_index = 3_usize;
    let block_number = cairo_pie
        .memory.0.iter()
        .find(|((segment_index, offset), _value)| *segment_index == output_segment_index && *offset == current_block_index) 
        .map(|((_segment_index, _offset), value)| value.clone()).expect("Block number not found in CairoPie memory.");

    block_number.get_int().expect("Block number is a Int")
}

#[test]
fn test_get_pie_block_number_fail() {
    let reference_pie_bytes = include_bytes!("../reference-pies/173404.zip").to_vec();
    let reference_pie = CairoPie::from_bytes(&reference_pie_bytes).expect("reference PIE");
    reference_pie.run_validity_checks().expect("Valid reference PIE");

    let block_number = get_pie_block_number(&reference_pie);
    assert_ne!(block_number, Felt252::from(173403));
}

#[test]
fn test_get_pie_block_number() {
    let reference_pie_bytes = include_bytes!("../reference-pies/173404.zip").to_vec();
    let reference_pie = CairoPie::from_bytes(&reference_pie_bytes).expect("reference PIE");
    reference_pie.run_validity_checks().expect("Valid reference PIE");

    let block_number = get_pie_block_number(&reference_pie);
    assert_eq!(block_number, Felt252::from(173404));
}