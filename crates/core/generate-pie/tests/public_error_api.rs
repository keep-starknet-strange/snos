use generate_pie::error::{BlockProcessingError, PieGenerationError, StateUpdateError};

#[test]
fn state_update_error_is_reexported_for_downstream_matching() {
    let error = StateUpdateError::PendingBlock;
    assert!(matches!(error, StateUpdateError::PendingBlock));
}

#[test]
fn pie_generation_error_exposes_typed_block_processing_source() {
    let error = PieGenerationError::BlockProcessing {
        block_number: 7,
        source: Box::new(BlockProcessingError::StateUpdate(StateUpdateError::PendingBlock)),
    };

    match error {
        PieGenerationError::BlockProcessing { block_number, source } => {
            assert_eq!(block_number, 7);
            assert!(matches!(*source, BlockProcessingError::StateUpdate(StateUpdateError::PendingBlock)));
        }
        _ => panic!("expected block processing error"),
    }
}
