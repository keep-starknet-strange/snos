mod common;

use common::os_pie_string;
use rstest::rstest;
use snos::sharp::{CairoJobStatus, InvalidReason, SharpClient, SharpPie};
use uuid::uuid;

#[rstest]
#[ignore]
fn real_sharp_submit_pie(os_pie_string: String) {
    // CAREFUL NOT TO OVERWHELM SHARP
    let sharp_client = SharpClient::default();
    let submit_resp = sharp_client.submit_pie(SharpPie::EncodedPie(os_pie_string)).unwrap();
    println!("Submission Response:\n\t{submit_resp:?}");

    assert_eq!(1, submit_resp.version);
    assert!(submit_resp.cairo_job_key.is_some());

    let job_id = submit_resp.cairo_job_key.unwrap();
    let status_resp = sharp_client.get_status(&job_id).unwrap();
    println!("Status Response:\n\t{status_resp:?}");
}

#[rstest]
#[ignore]
fn sharp_get_status() {
    let good_cairo_job_id = uuid!("3a24bbca-ad75-49d5-8ced-12796c6c0738");

    let sharp_client = SharpClient::default();
    let status_resp = sharp_client.get_status(&good_cairo_job_id).unwrap();

    assert_eq!(1, status_resp.version);
    assert_eq!(CairoJobStatus::PROCESSED, status_resp.status);
}

#[rstest]
#[ignore]
fn sharp_get_status_err() {
    let bad_cairo_job_id = uuid!("43454c8e-8f43-444f-aab2-edab05bef512");

    let sharp_client = SharpClient::default();
    let status_resp = sharp_client.get_status(&bad_cairo_job_id).unwrap();

    assert_eq!(1, status_resp.version);
    assert_eq!(CairoJobStatus::INVALID, status_resp.status);
    assert_eq!(InvalidReason::SECURITY_CHECK_FAILURE, status_resp.invalid_reason.unwrap());
}
