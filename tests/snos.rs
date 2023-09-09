use snos::SnOsRunner;

#[test]
fn snos_ok() {
    let snos_runner = SnOsRunner::default();
    let _runner_res = snos_runner.run();
    assert_eq!(4, 4);
}
