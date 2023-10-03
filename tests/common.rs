use cairo_vm::cairo_run::{cairo_run, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::vm::runners::cairo_pie::CairoPie;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use cairo_vm::vm::vm_core::VirtualMachine;
use snos::fact_state::shared::BlockInfo;
use snos::utils::definitions::general_config::StarknetGeneralConfig;
use starknet_core::{crypto::compute_hash_on_elements, types::FieldElement};
use starknet_api::{class_hash, contract_address};
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress};
use starknet_api::hash::StarkHash;


use std::fs;
use std::path;
use std::process;
use std::collections::HashMap;

use rstest::*;

// TODO: more specific
use blockifier::execution::contract_class::ContractClassV0;
use blockifier::test_utils::*;

const BUILD_DIR: &str = "build/";
const CAIRO_COMPILE_CMD: &str = "cairo-compile";
const STARKNET_COMPILE_CMD: &str = "starknet-compile-deprecated";
const TEST_CONTRACTS_DIR: &str = "tests/contracts/";
const TEST_PROGRAMS_DIR: &str = "tests/programs/";

#[fixture]
#[once]
pub fn compile_contracts() {
    let contracts = fs::read_dir(TEST_CONTRACTS_DIR).unwrap();

    for contract in contracts {
        let contract_path = contract.unwrap().path();
        let stem = contract_path.file_stem().unwrap();

        let contract_out_fmt = format!("{BUILD_DIR}{}.json", stem.to_str().unwrap());
        let contract_out = path::PathBuf::from(&contract_out_fmt);

        if !contract_out.exists() {
            let cmd_check = process::Command::new(STARKNET_COMPILE_CMD).arg("-v").output();
            assert!(cmd_check.is_ok());

            let out = process::Command::new(STARKNET_COMPILE_CMD)
                .args([
                    contract_path.to_str().unwrap(),
                    "--output",
                    contract_out.to_str().unwrap(),
                    "--no_debug_info",
                    "--cairo_path",
                    "cairo-lang/src",
                ])
                .output();
            assert!(out.is_ok());
        }
    }
}

#[fixture]
#[once]
pub fn compile_programs() {
    let programs = fs::read_dir(TEST_PROGRAMS_DIR).unwrap();

    for program in programs {
        let program_path = program.unwrap().path();
        let stem = program_path.file_stem().unwrap();

        let program_out_fmt = format!("{BUILD_DIR}{}.json", stem.to_str().unwrap());
        let program_out = path::PathBuf::from(&program_out_fmt);

        if !program_out.exists() {
            let cmd_check = process::Command::new(CAIRO_COMPILE_CMD).arg("-v").output();
            assert!(cmd_check.is_ok());

            let out = process::Command::new(CAIRO_COMPILE_CMD)
                .args([
                    program_path.to_str().unwrap(),
                    "--output",
                    program_out.to_str().unwrap(),
                    "--no_debug_info",
                ])
                .output();
            assert!(out.is_ok());
        }
    }
}

#[fixture]
pub fn setup_runner(_compile_programs: ()) -> (CairoRunner, VirtualMachine) {
    let program_content = fs::read("build/fact.json").unwrap();

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    // Run the program
    cairo_run(
        &program_content,
        &CairoRunConfig {
            entrypoint: "main",
            trace_enabled: true,
            relocate_mem: true,
            layout: "small",
            proof_mode: false,
            secure_run: Some(true),
            disable_trace_padding: false,
        },
        &mut hint_processor,
    )
    .unwrap()
}

#[fixture]
pub fn setup_pie(setup_runner: (CairoRunner, VirtualMachine)) -> CairoPie {
    // Run the runner
    let (runner, vm) = setup_runner;

    runner.get_cairo_pie(&vm).unwrap()
}

#[allow(unused)]
pub fn check_output_vs_python(program: &str, mut vm: VirtualMachine) {
    let mut rs_output = String::new();
    vm.write_output(&mut rs_output).unwrap();
    let rs_output = rs_output.split('\n').filter(|&x| !x.is_empty());
    let python_output = std::process::Command::new("cairo-run")
        .arg("--layout=small")
        .arg(format!("--program={program:}"))
        .arg("--print_output")
        .output()
        .expect("failed to run python vm");
    let python_output = unsafe { std::str::from_utf8_unchecked(&python_output.stdout) }.to_string();
    let python_output = python_output
        .split('\n')
        .into_iter()
        .skip_while(|&x| x != "Program output:")
        .skip(1)
        .filter(|&x| !x.trim().is_empty())
        .into_iter();
    for (i, (rs, py)) in rs_output.zip(python_output).enumerate() {
        let py = py.to_string().trim().to_string();
        pretty_assertions::assert_eq!(*rs, py, "Output #{i:} is different");
    }
}

#[fixture]
pub fn sw_compat_config() -> (StarknetGeneralConfig, BlockInfo) {
    let mut conf = StarknetGeneralConfig::default();

    // update fee token to match sw test
    conf.starknet_os_config.fee_token_address =
        FieldElement::from_hex_be("482bc27fc5627bf974a72b65c43aa8a0464a70aab91ad8379b56a4f17a84c3")
            .unwrap();

    let mut block_info = BlockInfo::default();
    block_info.block_timestamp = 1000;

    (conf, block_info)
}

// StateDiff(address_to_class_hash={1320198688701432534719157742574249187606949535760401890964327160391813649815: 3091807693782130767501414083074324621934995166802976508502430836300051087875, 991941543224299354231458875645971891578962076399384993792970752200863471543: 2876089962371428491550960640645254719239874945228583157550348788822249547409}, nonces={<DataAvailabilityMode.L1: 0>: {1320198688701432534719157742574249187606949535760401890964327160391813649815: 2, 991941543224299354231458875645971891578962076399384993792970752200863471543: 1}}, storage_updates={<DataAvailabilityMode.L1: 0>: {1320198688701432534719157742574249187606949535760401890964327160391813649815: {322990191961554429053868449035526014412279677330895387449703561219527453810: 1464161352, 553060490499374521350519736808313349113904249869887409031913453630132670891: 1320198688701432534719157742574249187606949535760401890964327160391813649815, 27838543048034294391053713572600349634190921977214803311654412455831886488: 168811955464684315858783496655603761152, 482148859801725464274198147480840119334382080162606228723774290742111978842: 170141183460469231731687303715884105728, 877823913686921299048507465990220541161247202424540097559864758276037605753: 18, 1473120764136009396440970107973971969419251478021578277222806501183556393953: 6928249226643520745136808551794, 622991711977806760541268368343056323675924475443734630808231720566777350071: 1329227995784915872903807060280344576, 1267095271664963432194589802007389382906322551387806188627353037007263322258: 1}}}, declared_classes={}, block_info=BlockInfo(block_number=0, block_timestamp=1000, eth_l1_gas_price=100000000, strk_l1_gas_price=0, sequencer_address=443902168967810054148884074756742919510645257800272067493104417962415061304, starknet_version='0.12.3'))
#[rstest]
pub fn setup_snos_data(sw_compat_config: (StarknetGeneralConfig, BlockInfo), _compile_contracts: ()) {
    
    // let class_map = HashMap::from([
    //     (
    //         dummy_account_class_hash,
    //         load_contract_class_v0("build/dummy_account.json")
    //     ),
    //     (
    //         dummy_token_class_hash,
    //         load_contract_class_v0("build/dummy_token.json")
    //     ),
    // ]);

    println!("CONF: {:?}", sw_compat_config.1);
}


pub fn load_contract_class_v0(path: &str) -> ContractClassV0 {
    let raw_contract_class = fs::read_to_string(path::PathBuf::from(path)).unwrap();
    ContractClassV0::try_from_json_string(&raw_contract_class).unwrap()
}