use std::env;
use std::path;
use std::process;

const CAIRO_COMPILE_CMD: &str = "cairo-compile";
const SNOS_PATH_ENV: &str = "SNOS_PATH";

// Defaults
const DEFAULT_SNOS_PATH: &str = "build/os_latest.json";

fn main() {
    let os_path_raw = env::var(SNOS_PATH_ENV).unwrap_or(DEFAULT_SNOS_PATH.into());
    println!("cargo:rerun-if-changed={os_path_raw}");
    println!("cargo:rerun-if-env-changed={SNOS_PATH_ENV}");

    let os_path = path::Path::new(&os_path_raw);

    if !os_path.exists() {
        // Check for `cairo-compile`
        if let Err(ver_err) = process::Command::new(CAIRO_COMPILE_CMD).arg("-v").output() {
            println!("cargo:warning=cairo-compile-unnavailable-{ver_err:?}");
            process::exit(1);
        }

        // Compile the Starknet OS
        if let Err(err) = process::Command::new(CAIRO_COMPILE_CMD)
            .args([
                "cairo-lang/src/starkware/starknet/core/os/os.cairo",
                "--output",
                os_path.to_str().unwrap(),
                "--cairo_path",
                "cairo-lang/src",
                "--no_debug_info",
            ])
            .output()
        {
            println!("cargo:warning=cairo-compile-{err:?}");
            process::exit(1);
        };
    }
}
