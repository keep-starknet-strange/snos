use blockifier::block_context::BlockContext;
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

const TOKEN_FOR_TESTING_HASH_0_12_2: &str = "45000d731e6d5ad0023e448dd15cab6f997b04a39120daf56a8816d9f436376";
const DUMMY_ACCOUNT_HASH_0_12_2: &str = "7cea4d7710723fa9e33472b6ceb71587a0ce4997ef486638dd0156bdb6c2daa";
const DUMMY_TOKEN_HASH_0_12_2: &str = "16dc3038da22dde8ad61a786ab9930699cc496c8bccb90d77cc8abee89803f7";
const TESTING_HASH_0_12_2: &str = "7364bafc3d2c56bc84404a6d8be799f533e518b8808bce86395a9442e1e5160";

#[fixture]
pub fn setup_runner() -> (CairoRunner, VirtualMachine) {
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
pub fn setup_snos_data(sw_compat_config: (StarknetGeneralConfig, BlockInfo)) {
    let block_context = BlockContext::create_for_testing();
    println!("CONTEXT: {:?}", block_context);
    
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

// DEPLOY ACCOUNT: InternalDeployAccount(hash_value=22688876470218804543887986415455328819098091743988100398197353790124740200, version=1, max_fee=1267650600228229401496703205376, signature=[], nonce=0, sender_address=1470089414715992704702781317133162679047468004062084455026636858461958198968, contract_address_salt=0, class_hash=3531298130119845387864440863187980726515137569165069484670944625223023734186, constructor_calldata=[])
// DEPLOY TOKEN:  InternalInvokeFunction(hash_value=2852915394592604060963909836770256627436576776991723431020681987492769528640, version=1, max_fee=1267650600228229401496703205376, signature=[], nonce=1, sender_address=1470089414715992704702781317133162679047468004062084455026636858461958198968, entry_point_selector=617075754465154585683856897856256838130216341506379215893724690153393808813, entry_point_type=<EntryPointType.EXTERNAL: 0>, calldata=[1470089414715992704702781317133162679047468004062084455026636858461958198968, 232670485425082704932579856502088130646006032362877466777181098476241604910, 3, 2618767603815038378512366346550627731109766804643583016834052353912473402832, 1329227995784915872903807060280344576, 0])
// FUND ACCOUNT:  InternalDeployAccount(hash_value=96374521715508826444566467091393680183010464453336720810014746622481735761, version=1, max_fee=1267650600228229401496703205376, signature=[], nonce=0, sender_address=2618767603815038378512366346550627731109766804643583016834052353912473402832, contract_address_salt=0, class_hash=646245114977324210659279014519951538684823368221946044944492064370769527799, constructor_calldata=[])
pub fn load_contract_class_v0(path: &str) -> ContractClassV0 {
    let raw_contract_class = fs::read_to_string(path::PathBuf::from(path)).unwrap();
    ContractClassV0::try_from_json_string(&raw_contract_class).unwrap()
}
