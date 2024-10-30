use std::fs::{self, read_to_string};
use std::io::Write;
use std::process::Command;

use cairo_vm::hint_processor::hint_processor_utils::felt_to_usize;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::Felt252;
use clap::Parser;
use prove_block::{debug_prove_error, get_memory_segment, prove_block};

#[derive(Parser, Debug)]
struct Args {
    /// sftp to fetch data from
    /// format <user>@<host>:path/to/dir.
    #[arg(long = "sftp-path")]
    sftp_path: String,
}

fn init_logging() {
    let target = Box::new(
        std::fs::File::create("crates/bin/output_segment/result-logs/all_logs.log").expect("Can't create file"),
    );

    env_logger::Builder::new()
        .format(|buf, record| {
            writeln!(buf, "[{} {}] - {}", record.level(), record.module_path().unwrap_or("unknown"), record.args())
        })
        .target(env_logger::Target::Pipe(target))
        .filter(None, log::LevelFilter::Debug)
        .init();
}

#[tokio::main]
async fn main() {
    init_logging();
    let args = Args::parse();

    for line in read_to_string("crates/bin/output_segment/reference-pies/pie_list.txt").unwrap().lines() {
        let file = line.trim();

        // Runs the sftp command to read a pie
        log::info!("Fething pie from server: {}", file);
        let host: String = args.sftp_path.to_owned() + file;

        let dest: String = "/tmp/".to_owned() + file;
        let _command = Command::new("sftp").args([host + " " + &dest]).output().unwrap();

        // Loads the pie as bytes
        let reference_pie_bytes = fs::read(&dest).unwrap();
        let reference_pie = CairoPie::from_bytes(&reference_pie_bytes).expect("reference PIE");
        reference_pie.run_validity_checks().expect("Valid reference PIE");

        let block_number: u64 =
            felt_to_usize(&get_pie_block_number(&reference_pie)).unwrap().try_into().expect("Block number is too big");

        log::info!("Running SNOS for block number: {}", block_number);

        let endpoint = "http://81.16.176.130:9545";
        let (snos_pie, _snos_output) = prove_block(block_number, endpoint, LayoutName::all_cairo, true)
            .await
            .map_err(debug_prove_error)
            .expect("OS generate Cairo PIE");

        snos_pie.run_validity_checks().expect("Valid SNOS PIE");

        let output_segment_index = 2;

        let mut output_file: std::fs::File;

        if get_memory_segment(&reference_pie, output_segment_index)
            == get_memory_segment(&snos_pie, output_segment_index)
        {
            log::info!("SNOS Pie has the same output as reference pie");

            output_file = std::fs::File::create("crates/bin/output_segment/result-logs/SUCCESS - ".to_owned() + file)
                .expect("Can't create file");
        } else {
            log::info!("SNOS Pie has a different output as reference pie");

            output_file = std::fs::File::create("crates/bin/output_segment/result-logs/FAILURE - ".to_owned() + file)
                .expect("Can't create file");
        }

        let mut begin_copy = false;

        for log_line in read_to_string("crates/bin/output_segment/result-logs/all_logs.log").unwrap().lines() {
            if log_line.contains(file) {
                begin_copy = true;
            }

            let write_line = log_line.to_owned() + "\n";

            if begin_copy {
                let _ = output_file.write(write_line.as_bytes());
            }
        }

        fs::remove_file(dest).unwrap();
    }
}

fn get_pie_block_number(cairo_pie: &CairoPie) -> Felt252 {
    // We know that current block number is on position (2,3)
    // Output segment, position 3.
    let output_segment_index = 2_usize;
    let current_block_index = 3_usize;
    let block_number = cairo_pie
        .memory
        .0
        .iter()
        .find(|((segment_index, offset), _value)| {
            *segment_index == output_segment_index && *offset == current_block_index
        })
        .map(|((_segment_index, _offset), value)| value.clone())
        .expect("Block number not found in CairoPie memory.");

    block_number.get_int().expect("Block number is a Int")
}
