%builtins output pedersen range_check

from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.serialize import serialize_word
from starkware.starknet.core.os.block_context import BlockContext
from starkware.starknet.common.new_syscalls import BlockInfo
from starkware.starknet.core.os.state import StateUpdateOutput
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.starknet.core.os.output import (
    MessageToL1Header,
    MessageToL2Header,
    OsCarriedOutputs,
    os_carried_outputs_new,
)
from starkware.cairo.common.memcpy import memcpy
from starkware.starknet.core.os.builtins import get_builtin_params
from starkware.cairo.common.registers import get_label_location
from starkware.starknet.core.os.execution.execute_syscalls import execute_syscalls
from starkware.starknet.core.os.execution.deprecated_execute_syscalls import (
    execute_deprecated_syscalls,
)
from starkware.starknet.core.os.os_config.os_config import StarknetOsConfig
from starkware.starknet.core.os.contract_class.deprecated_compiled_class import DeprecatedCompiledClassFact
from starkware.starknet.core.os.contract_class.compiled_class import CompiledClassFact

func main{output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;

    // loading the input and initialised `initial_carried_outputs`.
    let (initial_carried_outputs: OsCarriedOutputs*) = alloc();
    %{
        from starkware.starknet.core.os.os_input import StarknetOsInput

        os_input = StarknetOsInput.load(data=program_input)

        ids.initial_carried_outputs.messages_to_l1 = segments.add_temp_segment()
        ids.initial_carried_outputs.messages_to_l2 = segments.add_temp_segment()
    %}

    // creating block_context, only `block_number` is actually used
    // so all other values are dummy
    let (builtin_params) = get_builtin_params();
    let (execute_syscalls_ptr) = get_label_location(label_value=execute_syscalls);
    let (execute_deprecated_syscalls_ptr) = get_label_location(
        label_value=execute_deprecated_syscalls
    );
    local compiled_class_facts: CompiledClassFact*;
    %{
        ids.compiled_class_facts = segments.add()
    %}

    local deprecated_compiled_class_facts: DeprecatedCompiledClassFact*;
    %{
        ids.deprecated_compiled_class_facts = segments.add()
    %}

    tempvar block_info = new BlockInfo(
        block_number=1,
        block_timestamp=0,
        sequencer_address=0,
    );
    tempvar block_context = new BlockContext(
        builtin_params=builtin_params,
        n_compiled_class_facts=0,
        compiled_class_facts=compiled_class_facts,
        n_deprecated_compiled_class_facts=0,
        deprecated_compiled_class_facts=deprecated_compiled_class_facts,
        block_info=block_info,
        starknet_os_config=StarknetOsConfig(
            chain_id=0,
            fee_token_address=0,
        ),
        execute_syscalls_ptr=execute_syscalls_ptr,
        execute_deprecated_syscalls_ptr=execute_deprecated_syscalls_ptr,
    );

    // creating messages to l1 and l2.
    tempvar state_update_output = new StateUpdateOutput(
        initial_root=125777881657840305468919655792243043894346744037226223335092204105986408733,
        final_root=2040334332115293258607805604894929469377060974617729443381753056905784954023,
    );

    assert [initial_carried_outputs.messages_to_l1] = MessageToL1Header(
        from_address=2006810680437147719782949677362224138923732654511812452693656965873469983890,
        to_address=85,
        payload_size=2,
    );
    let (payload_l1: felt*) = alloc();
    assert [payload_l1] = 12;
    assert [payload_l1 + 1] = 34;
    memcpy(
        dst=initial_carried_outputs.messages_to_l1 + MessageToL1Header.SIZE, src=payload_l1, len=2
    );

    assert [initial_carried_outputs.messages_to_l2] = MessageToL2Header(
        from_address=85,
        to_address=1005161437792794307757078281996005783125378987969285529172328835577592343232,
        nonce=0,
        selector=352040181584456735608515580760888541466059565068553383579463728554843487745,
        payload_size=1,
    );
    let (payload_l2: felt*) = alloc();
    assert [payload_l2] = 2;
    memcpy(
        dst=initial_carried_outputs.messages_to_l2 + MessageToL2Header.SIZE, src=payload_l2, len=1
    );
    let (final_carried_outputs) = os_carried_outputs_new(
        messages_to_l1=initial_carried_outputs.messages_to_l1 + MessageToL1Header.SIZE + 2,
        messages_to_l2=initial_carried_outputs.messages_to_l2 + MessageToL2Header.SIZE + 1,
    );

    // creating state changes
    local initial_state_updates_ptr: felt*;
    %{
        ids.initial_state_updates_ptr = segments.add_temp_segment()
    %}
    assert [initial_state_updates_ptr] = 5;
    assert [initial_state_updates_ptr + 1] = 2006810680437147719782949677362224138923732654511812452693656965873469983890;
    assert [initial_state_updates_ptr + 2] = 85;
    assert [initial_state_updates_ptr + 3] = 2;
    assert [initial_state_updates_ptr + 4] = 12;
    assert [initial_state_updates_ptr + 5] = 34;
    assert [initial_state_updates_ptr + 6] = 6;
    assert [initial_state_updates_ptr + 7] = 85;
    assert [initial_state_updates_ptr + 8] = 1005161437792794307757078281996005783125378987969285529172328835577592343232;
    assert [initial_state_updates_ptr + 9] = 0;
    assert [initial_state_updates_ptr + 10] = 352040181584456735608515580760888541466059565068553383579463728554843487745;
    assert [initial_state_updates_ptr + 11] = 1;
    assert [initial_state_updates_ptr + 12] = 2;
    assert [initial_state_updates_ptr + 13] = 5;
    assert [initial_state_updates_ptr + 14] = 1005161437792794307757078281996005783125378987969285529172328835577592343232;
    assert [initial_state_updates_ptr + 15] = 340282366920938463463374607431768211462;
    assert [initial_state_updates_ptr + 16] = 692694963414257194264020892248745848197431340753065024006875718260869872089;
    assert [initial_state_updates_ptr + 17] = 123;
    assert [initial_state_updates_ptr + 18] = 456;
    assert [initial_state_updates_ptr + 19] = 300;
    assert [initial_state_updates_ptr + 20] = 2215430303710902791540996484823030809971452078551498009603035870583464052788;
    assert [initial_state_updates_ptr + 21] = 311;
    assert [initial_state_updates_ptr + 22] = 1536727068981429685321;
    assert [initial_state_updates_ptr + 23] = 322;
    assert [initial_state_updates_ptr + 24] = 19;
    assert [initial_state_updates_ptr + 25] = 815679926571212018227195848707562322348558067406060931041239273854107494620;
    assert [initial_state_updates_ptr + 26] = 2;
    assert [initial_state_updates_ptr + 27] = 1316419243995606702889870694869183679645676506242823596326912212936248352465;
    assert [initial_state_updates_ptr + 28] = 3262122051170176624039908867798875903980511552421730070376672653403179864416;
    assert [initial_state_updates_ptr + 29] = 2006810680437147719782949677362224138923732654511812452693656965873469983890;
    assert [initial_state_updates_ptr + 30] = 340282366920938463463374607431768211461;
    assert [initial_state_updates_ptr + 31] = 2084524728099985327606460172540572310995923661656859675449923268913980850263;
    assert [initial_state_updates_ptr + 32] = 85;
    assert [initial_state_updates_ptr + 33] = 47;
    assert [initial_state_updates_ptr + 34] = 321;
    assert [initial_state_updates_ptr + 35] = 543;
    assert [initial_state_updates_ptr + 36] = 444;
    assert [initial_state_updates_ptr + 37] = 666;
    assert [initial_state_updates_ptr + 38] = 1715425246256821823855536409958992540846451989567087551676457027799652256186;
    assert [initial_state_updates_ptr + 39] = 100;
    assert [initial_state_updates_ptr + 40] = 1715425246256821823855536409958992540846451989567087551676457027799652256187;
    assert [initial_state_updates_ptr + 41] = 200;
    assert [initial_state_updates_ptr + 42] = 2221633069513894212967173919871301977519426338681819384231748898933664013766;
    assert [initial_state_updates_ptr + 43] = 340282366920938463463374607431768211460;
    assert [initial_state_updates_ptr + 44] = 3262122051170176624039908867798875903980511552421730070376672653403179864416;
    assert [initial_state_updates_ptr + 45] = 15;
    assert [initial_state_updates_ptr + 46] = 1;
    assert [initial_state_updates_ptr + 47] = 111;
    assert [initial_state_updates_ptr + 48] = 987;
    assert [initial_state_updates_ptr + 49] = 555;
    assert [initial_state_updates_ptr + 50] = 888;
    assert [initial_state_updates_ptr + 51] = 666;
    assert [initial_state_updates_ptr + 52] = 999;
    assert [initial_state_updates_ptr + 53] = 2618767603815038378512366346550627731109766804643583016834052353912473402832;
    assert [initial_state_updates_ptr + 54] = 442721857769029238784;
    assert [initial_state_updates_ptr + 55] = 3302098605493938887217934688678356071939708546668669666319008757914002811976;
    assert [initial_state_updates_ptr + 56] = 340282366920938463463374607431768211456;
    assert [initial_state_updates_ptr + 57] = 3262122051170176624039908867798875903980511552421730070376672653403179864416;
    assert [initial_state_updates_ptr + 58] = 0;

    let starknet_os_config_hash: felt = 310876289256536046287137994578069209749202099665831078341805439700916543594;

    os_output_serialize(
        block_context=block_context,
        state_update_output=state_update_output,
        initial_carried_outputs=initial_carried_outputs,
        final_carried_outputs=final_carried_outputs,
        state_updates_ptr_start=initial_state_updates_ptr,
        state_updates_ptr_end=initial_state_updates_ptr + 59,
        starknet_os_config_hash=starknet_os_config_hash,
    );

    return ();
}

func os_output_serialize{output_ptr: felt*}(
    block_context: BlockContext*,
    state_update_output: StateUpdateOutput*,
    initial_carried_outputs: OsCarriedOutputs*,
    final_carried_outputs: OsCarriedOutputs*,
    state_updates_ptr_start: felt*,
    state_updates_ptr_end: felt*,
    starknet_os_config_hash: felt,
) {
    // Serialize program output.

    // Serialize roots.
    serialize_word(state_update_output.initial_root);
    serialize_word(state_update_output.final_root);

    serialize_word(block_context.block_info.block_number);
    // Currently, the block hash is not enforced by the OS.
    serialize_word(nondet %{ os_input.block_hash %});
    serialize_word(starknet_os_config_hash);

    let messages_to_l1_segment_size = (
        final_carried_outputs.messages_to_l1 - initial_carried_outputs.messages_to_l1
    );
    serialize_word(messages_to_l1_segment_size);

    // Relocate 'messages_to_l1_segment' to the correct place in the output segment.
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l1, dest_ptr=output_ptr);
    let output_ptr = cast(final_carried_outputs.messages_to_l1, felt*);

    let messages_to_l2_segment_size = (
        final_carried_outputs.messages_to_l2 - initial_carried_outputs.messages_to_l2
    );
    serialize_word(messages_to_l2_segment_size);

    // Relocate 'messages_to_l2_segment' to the correct place in the output segment.
    relocate_segment(src_ptr=initial_carried_outputs.messages_to_l2, dest_ptr=output_ptr);
    let output_ptr = cast(final_carried_outputs.messages_to_l2, felt*);

    // Serialize data availability.
    let da_start = output_ptr;

    // Relocate 'state_updates_segment' to the correct place in the output segment.
    relocate_segment(src_ptr=state_updates_ptr_start, dest_ptr=output_ptr);
    let output_ptr = state_updates_ptr_end;

    %{
        from starkware.python.math_utils import div_ceil
        onchain_data_start = ids.da_start
        onchain_data_size = ids.output_ptr - onchain_data_start

        max_page_size = 3800
        n_pages = div_ceil(onchain_data_size, max_page_size)
        for i in range(n_pages):
            start_offset = i * max_page_size
            output_builtin.add_page(
                page_id=1 + i,
                page_start=onchain_data_start + start_offset,
                page_size=min(onchain_data_size - start_offset, max_page_size),
            )
        # Set the tree structure to a root with two children:
        # * A leaf which represents the main part
        # * An inner node for the onchain data part (which contains n_pages children).
        #
        # This is encoded using the following sequence:
        output_builtin.add_attribute('gps_fact_topology', [
            # Push 1 + n_pages pages (all of the pages).
            1 + n_pages,
            # Create a parent node for the last n_pages.
            n_pages,
            # Don't push additional pages.
            0,
            # Take the first page (the main part) and the node that was created (onchain data)
            # and use them to construct the root of the fact tree.
            2,
        ])
    %}

    return ();
}
