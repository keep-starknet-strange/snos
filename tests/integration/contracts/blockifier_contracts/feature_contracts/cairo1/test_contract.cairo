#[starknet::contract]
mod TestContract {
    use box::BoxTrait;
    use dict::Felt252DictTrait;
    use ec::EcPointTrait;
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use starknet::get_execution_info;
    use starknet::StorageAddress;
    use array::ArrayTrait;
    use clone::Clone;
    use core::bytes_31::POW_2_128;
    use core::integer::bitwise;
    use traits::Into;
    use traits::TryInto;
    use starknet::{
        eth_address::U256IntoEthAddress, EthAddress, secp256_trait::{Signature, is_valid_signature},
        secp256r1::{Secp256r1Point, Secp256r1Impl}, eth_signature::verify_eth_signature,
        info::{BlockInfo, SyscallResultTrait}, info::v2::{ExecutionInfo, TxInfo, ResourceBounds,},
        syscalls
    };

    #[storage]
    struct Storage {
        my_storage_var: felt252,
        two_counters: LegacyMap<felt252, (felt252, felt252)>,
        ec_point: (felt252, felt252),
    }

    #[constructor]
    fn constructor(ref self: ContractState, arg1: felt252, arg2: felt252) -> felt252 {
        self.my_storage_var.write(arg1 + arg2);
        arg1
    }

    #[external(v0)]
    fn test_storage_read_write(
        self: @ContractState, address: StorageAddress, value: felt252
    ) -> felt252 {
        let address_domain = 0;
        syscalls::storage_write_syscall(address_domain, address, value).unwrap_syscall();
        syscalls::storage_read_syscall(address_domain, address).unwrap_syscall()
    }

    #[external(v0)]
    fn test_count_actual_storage_changes(self: @ContractState) {
        let storage_address = 15.try_into().unwrap();
        let address_domain = 0;
        syscalls::storage_write_syscall(address_domain, storage_address, 0).unwrap_syscall();
        syscalls::storage_write_syscall(address_domain, storage_address, 1).unwrap_syscall();
    }

    #[external(v0)]
    #[raw_output]
    fn test_call_contract(
        self: @ContractState,
        contract_address: ContractAddress,
        entry_point_selector: felt252,
        calldata: Array::<felt252>
    ) -> Span::<felt252> {
        syscalls::call_contract_syscall(contract_address, entry_point_selector, calldata.span())
            .unwrap_syscall()
            .snapshot
            .span()
    }

    #[external(v0)]
    fn test_emit_event(self: @ContractState, keys: Array::<felt252>, data: Array::<felt252>) {
        syscalls::emit_event_syscall(keys.span(), data.span()).unwrap_syscall();
    }

    #[external(v0)]
    fn test_get_block_hash(self: @ContractState, block_number: u64) -> felt252 {
        syscalls::get_block_hash_syscall(block_number).unwrap_syscall()
    }

    #[external(v0)]
    fn test_get_execution_info(
        self: @ContractState,
        expected_block_info: BlockInfo,
        expected_tx_info: TxInfo,
        // Expected call info.
        expected_caller_address: felt252,
        expected_contract_address: felt252,
        expected_entry_point_selector: felt252,
    ) {
        let execution_info = starknet::get_execution_info().unbox();
        let block_info = execution_info.block_info.unbox();
        assert(block_info == expected_block_info, 'BLOCK_INFO_MISMATCH');

        let tx_info = execution_info.tx_info.unbox();
        assert(tx_info == expected_tx_info, 'TX_INFO_MISMATCH');

        assert(execution_info.caller_address.into() == expected_caller_address, 'CALLER_MISMATCH');
        assert(
            execution_info.contract_address.into() == expected_contract_address, 'CONTRACT_MISMATCH'
        );
        assert(
            execution_info.entry_point_selector == expected_entry_point_selector,
            'SELECTOR_MISMATCH'
        );
    }

    #[external(v0)]
    #[raw_output]
    fn test_library_call(
        self: @ContractState,
        class_hash: ClassHash,
        function_selector: felt252,
        calldata: Array<felt252>
    ) -> Span::<felt252> {
        starknet::library_call_syscall(class_hash, function_selector, calldata.span())
            .unwrap_syscall()
            .snapshot
            .span()
    }

    #[external(v0)]
    #[raw_output]
    fn test_nested_library_call(
        self: @ContractState,
        class_hash: ClassHash,
        lib_selector: felt252,
        nested_selector: felt252,
        a: felt252,
        b: felt252
    ) -> Span::<felt252> {
        let mut nested_library_calldata: Array::<felt252> = Default::default();
        nested_library_calldata.append(class_hash.into());
        nested_library_calldata.append(nested_selector);
        nested_library_calldata.append(2);
        nested_library_calldata.append(a + 1);
        nested_library_calldata.append(b + 1);
        let res = starknet::library_call_syscall(
            class_hash, lib_selector, nested_library_calldata.span(),
        )
            .unwrap_syscall();

        let mut calldata: Array::<felt252> = Default::default();
        calldata.append(a);
        calldata.append(b);
        starknet::library_call_syscall(class_hash, nested_selector, calldata.span())
            .unwrap_syscall()
    }

    #[external(v0)]
    fn test_replace_class(self: @ContractState, class_hash: ClassHash) {
        syscalls::replace_class_syscall(class_hash).unwrap_syscall();
    }

    #[external(v0)]
    fn test_send_message_to_l1(
        self: @ContractState, to_address: felt252, payload: Array::<felt252>
    ) {
        starknet::send_message_to_l1_syscall(to_address, payload.span()).unwrap_syscall();
    }

    /// An external method that requires the `segment_arena` builtin.
    #[external(v0)]
    fn segment_arena_builtin(self: @ContractState) {
        let x = felt252_dict_new::<felt252>();
        x.squash();
    }

    #[l1_handler]
    fn l1_handle(self: @ContractState, from_address: felt252, arg: felt252) -> felt252 {
        arg
    }

    #[l1_handler]
    fn l1_handler_set_value(
        self: @ContractState, from_address: felt252, key: StorageAddress, value: felt252
    ) -> felt252 {
        let address_domain = 0;
        syscalls::storage_write_syscall(address_domain, key, value).unwrap_syscall();
        value
    }

    #[external(v0)]
    fn test_deploy(
        self: @ContractState,
        class_hash: ClassHash,
        contract_address_salt: felt252,
        calldata: Array::<felt252>,
        deploy_from_zero: bool,
    ) {
        syscalls::deploy_syscall(
            class_hash, contract_address_salt, calldata.span(), deploy_from_zero
        )
            .unwrap_syscall();
    }


    #[external(v0)]
    fn test_keccak(ref self: ContractState) {
        let mut input: Array::<u256> = Default::default();
        input.append(u256 { low: 1, high: 0 });

        let res = keccak::keccak_u256s_le_inputs(input.span());
        assert(res.low == 0x587f7cc3722e9654ea3963d5fe8c0748, 'Wrong hash value');
        assert(res.high == 0xa5963aa610cb75ba273817bce5f8c48f, 'Wrong hash value');

        let mut input: Array::<u64> = Default::default();
        input.append(1_u64);
        match syscalls::keccak_syscall(input.span()) {
            Result::Ok(_) => panic_with_felt252('Should fail'),
            Result::Err(revert_reason) => assert(
                *revert_reason.at(0) == 'Invalid input length', 'Wrong error msg'
            ),
        }
    }

    #[external(v0)]
    fn test_secp256k1(ref self: ContractState) {
        // Test a point not on the curve.
        assert(
            starknet::secp256k1::secp256k1_new_syscall(x: 0, y: 1).unwrap_syscall().is_none(),
            'Should be none'
        );

        let secp256k1_prime = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
        match starknet::secp256k1::secp256k1_new_syscall(x: secp256k1_prime, y: 1) {
            Result::Ok(_) => panic_with_felt252('Should fail'),
            Result::Err(revert_reason) => assert(
                *revert_reason.at(0) == 'Invalid argument', 'Wrong error msg'
            ),
        }

        // Test a point on the curve.
        let x = 0xF728B4FA42485E3A0A5D2F346BAA9455E3E70682C2094CAC629F6FBED82C07CD;
        let y = 0x8E182CA967F38E1BD6A49583F43F187608E031AB54FC0C4A8F0DC94FAD0D0611;
        let p0 = starknet::secp256k1::secp256k1_new_syscall(x, y).unwrap_syscall().unwrap();

        let (x_coord, y_coord) = starknet::secp256k1::secp256k1_get_xy_syscall(p0).unwrap_syscall();
        assert(x_coord == x && y_coord == y, 'Unexpected coordinates');

        let (msg_hash, signature, expected_public_key_x, expected_public_key_y, eth_address) =
            get_message_and_secp256k1_signature();
        verify_eth_signature(:msg_hash, :signature, :eth_address);
    }

    /// Returns a golden valid message hash and its signature, for testing.
    fn get_message_and_secp256k1_signature() -> (u256, Signature, u256, u256, EthAddress) {
        let msg_hash = 0xe888fbb4cf9ae6254f19ba12e6d9af54788f195a6f509ca3e934f78d7a71dd85;
        let r = 0x4c8e4fbc1fbb1dece52185e532812c4f7a5f81cf3ee10044320a0d03b62d3e9a;
        let s = 0x4ac5e5c0c0e8a4871583cc131f35fb49c2b7f60e6a8b84965830658f08f7410c;

        let (public_key_x, public_key_y) = (
            0xa9a02d48081294b9bb0d8740d70d3607feb20876964d432846d9b9100b91eefd,
            0x18b410b5523a1431024a6ab766c89fa5d062744c75e49efb9925bf8025a7c09e
        );

        let eth_address = 0x767410c1bb448978bd42b984d7de5970bcaf5c43_u256.into();

        (msg_hash, Signature { r, s, y_parity: true }, public_key_x, public_key_y, eth_address)
    }


    #[external(v0)]
    fn test_secp256r1(ref self: ContractState) {
        // Test a point not on the curve.
        assert(
            starknet::secp256r1::secp256r1_new_syscall(x: 0, y: 1).unwrap_syscall().is_none(),
            'Should be none'
        );

        let secp256r1_prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
        match starknet::secp256r1::secp256r1_new_syscall(x: secp256r1_prime, y: 1) {
            Result::Ok(_) => panic_with_felt252('Should fail'),
            Result::Err(revert_reason) => assert(
                *revert_reason.at(0) == 'Invalid argument', 'Wrong error msg'
            ),
        }

        // Test a point on the curve.
        let x = 0x502A43CE77C6F5C736A82F847FA95F8C2D483FE223B12B91047D83258A958B0F;
        let y = 0xDB0A2E6710C71BA80AFEB3ABDF69D306CE729C7704F4DDF2EAAF0B76209FE1B0;
        let p0 = starknet::secp256r1::secp256r1_new_syscall(x, y).unwrap_syscall().unwrap();

        let (x_coord, y_coord) = starknet::secp256r1::secp256r1_get_xy_syscall(p0).unwrap_syscall();
        assert(x_coord == x && y_coord == y, 'Unexpected coordinates');

        let (msg_hash, signature, expected_public_key_x, expected_public_key_y, eth_address) =
            get_message_and_secp256r1_signature();
        let public_key = Secp256r1Impl::secp256_ec_new_syscall(
            expected_public_key_x, expected_public_key_y
        )
            .unwrap_syscall()
            .unwrap();
        is_valid_signature::<Secp256r1Point>(msg_hash, signature.r, signature.s, public_key);
    }


    /// Returns a golden valid message hash and its signature, for testing.
    fn get_message_and_secp256r1_signature() -> (u256, Signature, u256, u256, EthAddress) {
        let msg_hash = 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;
        let r = 0xb292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a;
        let s = 0x177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2;

        let (public_key_x, public_key_y) = (
            0x04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5,
            0x0087d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d
        );
        let eth_address = 0x492882426e1cda979008bfaf874ff796eb3bb1c0_u256.into();

        (msg_hash, Signature { r, s, y_parity: true }, public_key_x, public_key_y, eth_address)
    }

    impl ResourceBoundsPartialEq of PartialEq<ResourceBounds> {
        #[inline(always)]
        fn eq(lhs: @ResourceBounds, rhs: @ResourceBounds) -> bool {
            (*lhs.resource == *rhs.resource)
                && (*lhs.max_amount == *rhs.max_amount)
                && (*lhs.max_price_per_unit == *rhs.max_price_per_unit)
        }
        #[inline(always)]
        fn ne(lhs: @ResourceBounds, rhs: @ResourceBounds) -> bool {
            !(*lhs == *rhs)
        }
    }

    impl TxInfoPartialEq of PartialEq<TxInfo> {
        #[inline(always)]
        fn eq(lhs: @TxInfo, rhs: @TxInfo) -> bool {
            (*lhs.version == *rhs.version)
                && (*lhs.account_contract_address == *rhs.account_contract_address)
                && (*lhs.max_fee == *rhs.max_fee)
                && (*lhs.signature == *rhs.signature)
                && (*lhs.transaction_hash == *rhs.transaction_hash)
                && (*lhs.chain_id == *rhs.chain_id)
                && (*lhs.nonce == *rhs.nonce)
                && (*lhs.resource_bounds == *rhs.resource_bounds)
                && (*lhs.tip == *rhs.tip)
                && (*lhs.paymaster_data == *rhs.paymaster_data)
                && (*lhs.nonce_data_availability_mode == *rhs.nonce_data_availability_mode)
                && (*lhs.fee_data_availability_mode == *rhs.fee_data_availability_mode)
                && (*lhs.account_deployment_data == *rhs.account_deployment_data)
        }
        #[inline(always)]
        fn ne(lhs: @TxInfo, rhs: @TxInfo) -> bool {
            !(*lhs == *rhs)
        }
    }

    impl BlockInfoPartialEq of PartialEq<BlockInfo> {
        #[inline(always)]
        fn eq(lhs: @BlockInfo, rhs: @BlockInfo) -> bool {
            (*lhs.block_number == *rhs.block_number)
                && (*lhs.block_timestamp == *rhs.block_timestamp)
                && (*lhs.sequencer_address == *rhs.sequencer_address)
        }
        #[inline(always)]
        fn ne(lhs: @BlockInfo, rhs: @BlockInfo) -> bool {
            !(*lhs == *rhs)
        }
    }

    #[external(v0)]
    fn assert_eq(ref self: ContractState, x: felt252, y: felt252) -> felt252 {
        assert(x == y, 'x != y');
        'success'
    }

    #[external(v0)]
    fn recursive_fail(ref self: ContractState, depth: felt252) {
        if depth == 0 {
            panic_with_felt252('recursive_fail');
        }
        recursive_fail(ref self, depth - 1)
    }

    #[external(v0)]
    fn recurse(ref self: ContractState, depth: felt252) {
        if depth == 0 {
            return;
        }
        recurse(ref self, depth - 1)
    }

    #[external(v0)]
    fn recursive_syscall(
        ref self: ContractState,
        contract_address: ContractAddress,
        function_selector: felt252,
        depth: felt252,
    ) {
        if depth == 0 {
            return;
        }
        let calldata: Array::<felt252> = array![
            contract_address.into(), function_selector, depth - 1
        ];
        syscalls::call_contract_syscall(contract_address, function_selector, calldata.span())
            .unwrap_syscall();
        return;
    }

    #[derive(Drop, Serde)]
    struct IndexAndValues {
        index: felt252,
        values: (u128, u128),
    }

    #[starknet::interface]
    trait MyContract<TContractState>{
        fn xor_counters(ref self: TContractState, index_and_x: IndexAndValues);
    }

    // Advances the 'two_counters' storage variable by 'diff'.
    #[external(v0)]
    fn advance_counter(ref self: ContractState, index: felt252, diff_0: felt252, diff_1: felt252) {
        let val = self.two_counters.read(index);
        let (val_0, val_1) = val;
        self.two_counters.write(index, (val_0 + diff_0, val_1 + diff_1));
    }

    #[external(v0)]
    fn xor_counters(ref self: ContractState, index_and_x: IndexAndValues) {
        let index = index_and_x.index;
       let (val_0, val_1) = index_and_x.values;
       let counters = self.two_counters.read(index);
       let (counter_0, counter_1) = counters;
       let counter_0: u128 = counter_0.try_into().unwrap();
       let counter_1: u128 = counter_1.try_into().unwrap();
       let res_0: felt252 = (counter_0^val_0).into();
       let res_1: felt252 = (counter_1^val_1).into();
       self.two_counters.write(index, (res_0, res_1));
    }

    #[external(v0)]
    fn call_xor_counters(ref self: ContractState, address: ContractAddress, index_and_x: IndexAndValues) {
       MyContractDispatcher{contract_address: address}.xor_counters(index_and_x);
    }

    #[external(v0)]
    fn test_ec_op(ref self: ContractState) {
        let p = EcPointTrait::new(
            0x654fd7e67a123dd13868093b3b7777f1ffef596c2e324f25ceaf9146698482c,
            0x4fad269cbf860980e38768fe9cb6b0b9ab03ee3fe84cfde2eccce597c874fd8
        ).unwrap();
        let q = EcPointTrait::new(
            0x3dbce56de34e1cfe252ead5a1f14fd261d520d343ff6b7652174e62976ef44d,
            0x4b5810004d9272776dec83ecc20c19353453b956e594188890b48467cb53c19
        ).unwrap();
        let m: felt252 = 0x6d232c016ef1b12aec4b7f88cc0b3ab662be3b7dd7adbce5209fcfdbd42a504;
        let res = q.mul(m) + p;
        let res_nz = res.try_into().unwrap();
        self.ec_point.write(res_nz.coordinates());
    }

    #[external(v0)]
    fn add_signature_to_counters(ref self: ContractState, index: felt252) {
        let signature = get_execution_info().unbox().tx_info.unbox().signature;
        let val = self.two_counters.read(index);
        let (val_0, val_1) = val;
        self.two_counters.write(index, (val_0 + *signature.at(0), val_1 + *signature.at(1)));
    }

    #[external(v0)]
    fn send_message(self: @ContractState, to_address: felt252) {
        let mut payload = ArrayTrait::<felt252>::new();
        payload.append(12);
        payload.append(34);
        starknet::send_message_to_l1_syscall(to_address, payload.span()).unwrap_syscall();
    }

    #[external(v0)]
    fn test_sha256_byte_array() {
        assert_eq!(
            sha256_as_u256("a"), 0xca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
        );
        assert_eq!(
            sha256_as_u256("aa"), 0x961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506
        );
        assert_eq!(
            sha256_as_u256("aaa"), 0x9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0
        );
        assert_eq!(
            sha256_as_u256("aaaa"), 0x61be55a8e2f6b4e172338bddf184d6dbee29c98853e0a0485ecee7f27b9af0b4
        );
        // test length 0
        assert_eq!(
            sha256_as_u256(""), 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        );
        // test length 1
        assert_eq!(
            sha256_as_u256("x"), 0x2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
        );
        // test length 7
        assert_eq!(
            sha256_as_u256("xffidcw"),
            0x692ca8f4448048d3eee81365d91f9220c4c446d123bf9dcd82a6e4d0dfd0940a
        );
        // test length 8
        assert_eq!(
            sha256_as_u256("szhgvskg"),
            0xbea98c851b81bb113b5b8fbb7add06a8aaae36555b63bbf3abe393b8b35260bd
        );
        // test length 9
        assert_eq!(
            sha256_as_u256("nokwxzwsl"),
            0x063dc8cf320d4dd4403c2e22b7255ab21898c97e4a131d26e1fc0589f7e9cbc4
        );
        // test length 15
        assert_eq!(
            sha256_as_u256("bhmvtgdkhgajqaf"),
            0xaffa8850bb7b05ac9e948fda305bfe39a15057a0269225ae8c2eeeb3c46e8fe8
        );
        // test length 16
        assert_eq!(
            sha256_as_u256("qxwwcxzjiibvkqky"),
            0xef1b40920adc9bd453103e171e79776be73f53288dd22baeb087f664e300d1e2
        );
        // test length 17
        assert_eq!(
            sha256_as_u256("ipjjkvuojtcinvvnu"),
            0x5419df507a08e45a805ae8dcdcfe544fbdfb955e71b65b048f46b4961aebf06c
        );
        // test length 23
        assert_eq!(
            sha256_as_u256("ygjbndjbjqfqwrywlpggahh"),
            0xb717c1690433f7e07809147d740c2061ce62ca12ac1e458bb2c9c7b4e720e1e2
        );
        // test length 24
        assert_eq!(
            sha256_as_u256("tqeruqfqlvrsxhjjzyfiuyni"),
            0xb4706bbfe2551f3838df517953f1f2e4cbd869c020fc2a6a78bd6dce26b2996d
        );
        // test length 25
        assert_eq!(
            sha256_as_u256("oppudxpkzsspqtmopvdhicyhc"),
            0xd81c9f032105f08d7411af404b9c40ba773e9fb5109ec43d742ab2b124b0985f
        );
        // test length 31
        assert_eq!(
            sha256_as_u256("iehpuxzsxzffqyhqxsnsybpygdscgrf"),
            0x0814d4d5d16c637c0c32b9cbe4831284027ea275f4363c7a0c2006eefcaf6a95
        );
        // test length 32
        assert_eq!(
            sha256_as_u256("dwdnlgtqkicjpyonhxtzqmxxqsjiwuov"),
            0x41e8c2ec97ab4c2ca0ea63a4d457d184f9daeeecfc67369fb485657227ee4055
        );
        // test length 33
        assert_eq!(
            sha256_as_u256("owhqocwxqapkjjryeveiuvyomnzgptexp"),
            0x7ca52baf871a67553eae8e1b7e319a4186f41a31bea6a8b13553986b5494304d
        );
        // test length 39
        assert_eq!(
            sha256_as_u256("jhgdvhubfsgmvqaiehclbhxtkerusriurmepeyz"),
            0x7ca8143c46fb792674f225441b7471b7f545571517478bce80e7e0c9cdbefff8
        );
        // test length 40
        assert_eq!(
            sha256_as_u256("pbzqxiqewdfzvelghpjclwwhkocssdmknssasdap"),
            0xdeff2a399ce47b6289bd6c051341403e195b4a68c299729414d13bcdef3eaee3
        );
        // test length 41
        assert_eq!(
            sha256_as_u256("twxzmlfepsjutlpmlpsetkfvixlttvegfdxeefcda"),
            0xebd7f16ac58ae7cc6fa5469c229b896f2a76440d394e0717ff1c49cc777dd81b
        );
        // test length 47
        assert_eq!(
            sha256_as_u256("ahdlyumrwxiwumrvkscepnxtptzsdkzhlfpuhypdoeqcqql"),
            0x31db2dea1937ece94652015558e98da557a1c6cf1841cd25e3e0748818a75f1c
        );
        // test length 48
        assert_eq!(
            sha256_as_u256("kmjeneddmhlcsyokduzjovbynzatmmqoekslfwiqbcoaudgd"),
            0x0b9cda0453fa1adbe558a18f7af8c72090891471ac3b09faa1ddf942d223c73b
        );
        // test length 49
        assert_eq!(
            sha256_as_u256("vyqcddnljnjajyilmafspxnwgxlgwulpkdgvpaweitfgjcgue"),
            0x1ea01ee2976b0361f8a24346c0f26911a98597a9ab2ebbd293fe7cfad72e6a7a
        );
        // test length 55
        assert_eq!(
            sha256_as_u256("wugdolcxgjgjugcibpydicnpjkeygkowbkqvsqhnydknzpiguhcwaxt"),
            0xb3fffae87e85a7d9085d04210e29a3dfc27469c61e60a957ad0c87db71c8cb79
        );
        // test length 56
        assert_eq!(
            sha256_as_u256("sdkxocmqvmljrezvkkfnylvjoklmpeyimvtnhtkheylolizwtqulbluf"),
            0x5c2b04d3b63a9fd04afe1137a00f1c642a962933e20ef1d4e4729fd1cadb01a6
        );
        // test length 57
        assert_eq!(
            sha256_as_u256("msrqhpytgzqnavnazvhswjwifxwvkiapcetishwuagxultoimyfzoself"),
            0x55bc8a6602d12fc6d5354ad9964e2d13ca9e3ede3e2e788c4c928d75b175a7ca
        );
        // test length 63
        assert_eq!(
            sha256_as_u256("xtoesagtsybcibtwsqxqltbdiygasnozjniwqnjakjogmcvdpujpprgcdmtuyvn"),
            0x7f70e2a9a8854f0634b57721b48fa5f95185b2ca1099d9e093088e416245da06
        );
        // test length 64
        assert_eq!(
            sha256_as_u256("fjxootkrqqljdfdvwwxjhndsqshphzaoehyyibqulmtihoutvofsekymjwczelit"),
            0x58c09482981dffd40109b7c14c82418ac1841395e9bbf106d53b0f228b37a464
        );
        // test length 65
        assert_eq!(
            sha256_as_u256("phtpnnjkxyinhxkwklyvxxrmhzaenpkauucubsubwcjucuyauxahxvylffqiqezbd"),
            0x9cba0ff0b0a2ec07208b46ef0a89a27bbbfe23fd24d8b9939a603c2f47bac1b0
        );
        // test length 71
        assert_eq!(
            sha256_as_u256("gjgdfsbmbbyhbuujhwlsvobhsfooaogvzxeixzpccpzogkkkkxuorhtaaemyojknipfdewb"),
            0x7d3bc3e84c1a82e4ea1e16a5150f73657a4d54f1ee127bd963f6ecf160c6d3bb
        );
        // test length 72
        assert_eq!(
            sha256_as_u256("kbziqjtltnzicqhvcgiqfbvamdhddiqzyqucuzbualvrajlcaslsvubilzfwvioysvdqypcp"),
            0xd1e18df0c2acc467e21cd7c7ea46c239bfdf3b75cc55addd255eee751daf5d54
        );
        // test length 73
        assert_eq!(
            sha256_as_u256("ugombvhpwrkpgvqdwjpopdbqvmldlupczklkdevzkhsjzfylgrkotaoltbnxtoqdhposxtuaz"),
            0xe64839141b5b17df5f84c7fb5561723f6050cf0bc52c81082a50f2de99e4a617
        );
    }

    /// computes the sha256 of the input and returns it as a u256.
    fn sha256_as_u256(input: ByteArray) -> u256 {
        let hash_result = compute_sha256_byte_array(@input);
        let mut value: u256 = 0;
        for word in hash_result.span() {
            value *= 0x100000000;
            value = value + (*word).into();
        };
        value
    }

}
