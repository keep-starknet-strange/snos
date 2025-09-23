#!/bin/bash

# End-to-End Test Runner for SNOS
# This script provides convenient commands for running different types of e2e tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
RPC_URL="${SNOS_TEST_RPC_URL:-https://pathfinder-mainnet.d.karnot.xyz}"
NETWORK="${SNOS_TEST_NETWORK:-mainnet}"
TIMEOUT="${SNOS_TEST_TIMEOUT_SECS:-300}"
OUTPUT_DIR="${SNOS_TEST_OUTPUT_DIR:-/tmp}"

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

show_help() {
    echo "SNOS End-to-End Test Runner"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  quick          Run quick integration tests (no RPC required)"
    echo "  e2e            Run full e2e tests (requires RPC)"
    echo "  pie            Run only PIE generation tests"
    echo "  errors         Run only error handling tests"
    echo "  single         Run single block PIE test"
    echo "  multi          Run multi-block PIE test"
    echo "  all            Run all tests (quick + e2e)"
    echo "  check          Check test environment"
    echo ""
    echo "Options:"
    echo "  --rpc-url URL      RPC endpoint (default: $RPC_URL)"
    echo "  --network NET      Network: mainnet/sepolia (default: $NETWORK)"
    echo "  --timeout SECS     Test timeout in seconds (default: $TIMEOUT)"
    echo "  --output-dir DIR   Output directory (default: $OUTPUT_DIR)"
    echo "  --verbose          Show detailed output"
    echo "  --help             Show this help"
    echo ""
    echo "Environment variables:"
    echo "  SNOS_TEST_RPC_URL      Override default RPC URL"
    echo "  SNOS_TEST_NETWORK      Override default network"
    echo "  SNOS_TEST_TIMEOUT_SECS Override default timeout"
    echo "  SNOS_TEST_OUTPUT_DIR   Override default output directory"
    echo "  SNOS_SKIP_RPC_TESTS    Skip RPC-dependent tests"
    echo ""
    echo "Examples:"
    echo "  $0 quick                               # Fast tests only"
    echo "  $0 e2e --rpc-url http://localhost:9545 # Local pathfinder"
    echo "  $0 single --verbose                    # Single test with output"
    echo "  $0 check                               # Check environment"
}

check_environment() {
    print_header "Environment Check"

    echo "Configuration:"
    echo "  RPC URL: $RPC_URL"
    echo "  Network: $NETWORK"
    echo "  Timeout: ${TIMEOUT}s"
    echo "  Output Dir: $OUTPUT_DIR"
    echo ""

    # Check if output directory is writable
    if [ ! -d "$OUTPUT_DIR" ]; then
        print_warning "Output directory doesn't exist, attempting to create: $OUTPUT_DIR"
        mkdir -p "$OUTPUT_DIR" || {
            print_error "Cannot create output directory: $OUTPUT_DIR"
            return 1
        }
    fi

    if [ ! -w "$OUTPUT_DIR" ]; then
        print_error "Output directory is not writable: $OUTPUT_DIR"
        return 1
    fi

    print_success "Output directory is accessible: $OUTPUT_DIR"

    # Check RPC connectivity (basic check)
    if command -v curl >/dev/null 2>&1; then
        echo "Testing RPC connectivity..."
        if curl -s --max-time 10 "$RPC_URL" >/dev/null 2>&1; then
            print_success "RPC endpoint is reachable: $RPC_URL"
        else
            print_warning "RPC endpoint may not be reachable: $RPC_URL"
            echo "This might be expected if authentication or specific headers are required"
        fi
    else
        print_warning "curl not available, skipping connectivity check"
    fi

    # Check cargo
    if ! command -v cargo >/dev/null 2>&1; then
        print_error "cargo not found in PATH"
        return 1
    fi

    print_success "cargo is available"

    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ] || [ ! -d "tests" ]; then
        print_error "Please run this script from the SNOS project root directory"
        return 1
    fi

    print_success "In correct project directory"
    print_success "Environment check passed!"
    return 0
}

run_quick_tests() {
    print_header "Quick Integration Tests"
    echo "Running fast tests that don't require external RPC..."

    export SNOS_TEST_RPC_URL="$RPC_URL"
    export SNOS_TEST_NETWORK="$NETWORK"
    export SNOS_TEST_TIMEOUT_SECS="$TIMEOUT"
    export SNOS_TEST_OUTPUT_DIR="$OUTPUT_DIR"

    if [ "$VERBOSE" = "true" ]; then
        cargo test -p e2e-tests --test basic_integration -- --nocapture
    else
        cargo test -p e2e-tests --test basic_integration
    fi

    print_success "Quick tests completed!"
}

run_e2e_tests() {
    print_header "Full E2E Tests"
    echo "Running complete e2e tests (this may take 30-60 minutes)..."

    export SNOS_TEST_RPC_URL="$RPC_URL"
    export SNOS_TEST_NETWORK="$NETWORK"
    export SNOS_TEST_TIMEOUT_SECS="$TIMEOUT"
    export SNOS_TEST_OUTPUT_DIR="$OUTPUT_DIR"

    if [ "$VERBOSE" = "true" ]; then
        cargo test -p e2e-tests --test integration -- --ignored --nocapture
    else
        cargo test -p e2e-tests --test integration -- --ignored
    fi

    print_success "E2E tests completed!"
}

run_pie_tests() {
    print_header "PIE Generation Tests"
    echo "Running PIE generation e2e tests..."

    export SNOS_TEST_RPC_URL="$RPC_URL"
    export SNOS_TEST_NETWORK="$NETWORK"
    export SNOS_TEST_TIMEOUT_SECS="$TIMEOUT"
    export SNOS_TEST_OUTPUT_DIR="$OUTPUT_DIR"

    if [ "$VERBOSE" = "true" ]; then
        cargo test --test integration pie_generation -- --ignored --nocapture
    else
        cargo test --test integration pie_generation -- --ignored
    fi

    print_success "PIE generation tests completed!"
}

run_error_tests() {
    print_header "Error Handling Tests"
    echo "Running error handling e2e tests..."

    export SNOS_TEST_RPC_URL="$RPC_URL"
    export SNOS_TEST_NETWORK="$NETWORK"
    export SNOS_TEST_TIMEOUT_SECS="$TIMEOUT"
    export SNOS_TEST_OUTPUT_DIR="$OUTPUT_DIR"

    if [ "$VERBOSE" = "true" ]; then
        cargo test --test integration error_handling -- --ignored --nocapture
    else
        cargo test --test integration error_handling -- --ignored
    fi

    print_success "Error handling tests completed!"
}

run_single_test() {
    print_header "Single Block PIE Test"
    echo "Running single block PIE generation test..."

    export SNOS_TEST_RPC_URL="$RPC_URL"
    export SNOS_TEST_NETWORK="$NETWORK"
    export SNOS_TEST_TIMEOUT_SECS="$TIMEOUT"
    export SNOS_TEST_OUTPUT_DIR="$OUTPUT_DIR"

    if [ "$VERBOSE" = "true" ]; then
        cargo test --test integration test_single_block_pie_generation -- --ignored --nocapture
    else
        cargo test --test integration test_single_block_pie_generation -- --ignored
    fi

    print_success "Single block test completed!"
}

run_multi_test() {
    print_header "Multi-Block PIE Test"
    echo "Running multi-block PIE generation test..."

    export SNOS_TEST_RPC_URL="$RPC_URL"
    export SNOS_TEST_NETWORK="$NETWORK"
    export SNOS_TEST_TIMEOUT_SECS="$TIMEOUT"
    export SNOS_TEST_OUTPUT_DIR="$OUTPUT_DIR"

    if [ "$VERBOSE" = "true" ]; then
        cargo test --test integration test_multi_block_pie_generation -- --ignored --nocapture
    else
        cargo test --test integration test_multi_block_pie_generation -- --ignored
    fi

    print_success "Multi-block test completed!"
}

# Parse arguments
COMMAND=""
VERBOSE="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        quick|e2e|pie|errors|single|multi|all|check)
            COMMAND="$1"
            shift
            ;;
        --rpc-url)
            RPC_URL="$2"
            shift 2
            ;;
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE="true"
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Show help if no command provided
if [ -z "$COMMAND" ]; then
    show_help
    exit 1
fi

# Execute command
case $COMMAND in
    quick)
        run_quick_tests
        ;;
    e2e)
        run_e2e_tests
        ;;
    pie)
        run_pie_tests
        ;;
    errors)
        run_error_tests
        ;;
    single)
        run_single_test
        ;;
    multi)
        run_multi_test
        ;;
    all)
        run_quick_tests
        echo ""
        run_e2e_tests
        ;;
    check)
        check_environment
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac