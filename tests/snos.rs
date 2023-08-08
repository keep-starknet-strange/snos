#[cfg(test)]
mod tests {
    use snos::run_os;

    #[test]
    fn snos_ok() {
        run_os();
        assert_eq!(4, 4);
    }
}
