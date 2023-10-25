mod common;

use rstest::*;
use snos::sharp::SharpClient;

const _TEST_CAIRO_JOB_ID: &str = "3a24bbca-ad75-49d5-8ced-12796c6c0738";
const NEW_CAIRO_JOB: &str = "59b5138d-4c6e-49d3-9234-6495223acb43";

// #[rstest]
// fn sharp_client_submit(setup_pie: CairoPie) {
//     // TODO: implement mocks here, so as to not overwhelm the SHARP
//     let sharp_client = SharpClient::default();
//     let submit_resp = sharp_client.submit_pie(setup_pie).unwrap();
//     assert_eq!(submit_resp.cairo_job_key.unwrap().as_bytes().len(), 16);
// }

#[rstest]
fn sharp_client_status() {
    let sharp_client = SharpClient::default();
    let submit_resp = sharp_client.get_status(NEW_CAIRO_JOB).unwrap();
    println!("{submit_resp:?}");

    assert_eq!(submit_resp.version.unwrap(), 1);
    assert!(submit_resp.validation_done.unwrap());
}

#[rstest]
fn prove_os_run() {
    let sharp_client = SharpClient::default();
    let pie = std::fs::read_to_string("tests/common/data/output_pie.b64").unwrap();
    let submit_resp = sharp_client.submit_pie(snos::sharp::SharPie::EncodedPie(pie)).unwrap();
    println!("{submit_resp:?}");
}
