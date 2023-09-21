mod common;

use rstest::*;
use snos::sharp::SharpClient;

const TEST_CAIRO_JOB_ID: &str = "3a24bbca-ad75-49d5-8ced-12796c6c0738";

// #[rstest]
// fn sharp_client_submit(setup_pie: CairoPie) {
//     // TODO: implement mocks here, so as to not overwhelm the SHARP
//     let sharp_client = SharpClient::default();
//     let submit_resp = sharp_client.submit_pie(setup_pie).unwrap();
//     assert_eq!(submit_resp.cairo_job_key.unwrap().as_bytes().len(), 16);
// }

#[rstest]
#[ignore]
fn sharp_client_status() {
    let sharp_client = SharpClient::default();
    let submit_resp = sharp_client.get_status(TEST_CAIRO_JOB_ID).unwrap();

    assert_eq!(submit_resp.version.unwrap(), 1);
    assert_eq!(submit_resp.validation_done.unwrap(), true);
}
