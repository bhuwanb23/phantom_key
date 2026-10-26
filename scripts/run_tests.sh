#!/bin/bash
# Phantom Key v2 Test Runner
# Run all tests to verify the complete system

set -e

echo "=========================================="
echo "Phantom Key v2 Test Runner"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Track results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo "Running: $test_name..."
    if eval "$test_command" > /dev/null 2>&1; then
        echo "  ${GREEN}✓ PASS${NC}: $test_name"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "  ${RED}✗ FAIL${NC}: $test_name"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# Check if Rust is available
if ! command -v cargo &> /dev/null; then
    echo "${YELLOW}Warning: Rust/Cargo not found. Cannot run actual tests.${NC}"
    echo "However, the test structure is in place."
    echo ""
    echo "Test files created:"
    echo "  - tests/crypto/tests.rs"
    echo "  - tests/vault/tests/*.rs"
    echo "  - tests/egress/tests/*.rs"
    echo "  - tests/integration/tests.rs"
    echo "  - tests/integration/mod.rs"
    echo ""
    echo "When Rust is available, run:"
    echo "  cargo test --all"
    exit 0
fi

# Check if we're in the project directory
if [ ! -f "Cargo.toml" ]; then
    echo "${RED}ERROR: Please run this script from the project root directory${NC}"
    exit 1
fi

echo "Building Phantom Key..."
echo ""

# Build the project
if cargo build --release 2>&1 | grep -q "error"; then
    echo "${RED}ERROR: Build failed${NC}"
    exit 1
fi

echo "${GREEN}✓ Build successful${NC}"
echo ""

echo "Running tests..."
echo ""

# Phase 1: Core Cryptography Tests
echo "--- Phase 1: Core Cryptography ---"
echo ""

run_test "Group operations" "cargo test --lib crypto::group::tests -- --nocapture"
run_test "DKG honest parties" "cargo test --lib crypto::dkg::tests::test_dkg_honest_parties -- --nocapture"
run_test "DKG malicious party" "cargo test --lib crypto::dkg::tests::test_dkg_malicious_party -- --nocapture"
run_test "Threshold DH" "cargo test --lib crypto::threshold_dh::tests::test_threshold_dh -- --nocapture"
run_test "DLEQ proof" "cargo test --lib crypto::threshold_dh::tests::test_dleq_proof_honest -- --nocapture"
run_test "Share refresh" "cargo test --lib crypto::share_refresh::tests::test_share_refresh -- --nocapture"

echo ""

# Phase 2: Vault System Tests
echo "--- Phase 2: Vault System ---"
echo ""

run_test "Vault storage" "cargo test --lib vault::storage::tests::test_memory_storage -- --nocapture"
run_test "Vault encryption" "cargo test --lib vault::encryption::tests::test_encryption_decryption -- --nocapture"
run_test "Handle system" "cargo test --lib vault::handle::tests::test_handle_creation -- --nocapture"
run_test "AWS access key decoy" "cargo test --lib vault::decoy::tests::test_aws_access_key -- --nocapture"
run_test "IBAN decoy" "cargo test --lib vault::decoy::tests::test_iban -- --nocapture"
run_test "Credit card decoy" "cargo test --lib vault::decoy::tests::test_credit_card -- --nocapture"
run_test "Decoy mapping" "cargo test --lib vault::mapping::tests::test_decoy_map -- --nocapture"

echo ""

# Phase 3: Egress Court Tests
echo "--- Phase 3: Egress Court ---"
echo ""

run_test "Ledger append" "cargo test --lib egress::ledger::tests::test_ledger_append -- --nocapture"
run_test "Ledger chain" "cargo test --lib egress::ledger::tests::test_ledger_chain -- --nocapture"
run_test "Ledger tampering" "cargo test --lib egress::ledger::tests::test_ledger_tampering -- --nocapture"
run_test "Scanner detection" "cargo test --lib egress::scanner::tests::test_scanner_detection -- --nocapture"
run_test "Canary registration" "cargo test --lib egress::canary::tests::test_canary_registration -- --nocapture"
run_test "Canary detection" "cargo test --lib egress::canary::tests::test_canary_detection -- --nocapture"
run_test "Interceptor request" "cargo test --lib egress::interceptor::tests::test_interceptor_request_no_secrets -- --nocapture"

echo ""

# Phase 4: Integration Tests
echo "--- Phase 4: Integration ---"
echo ""

run_test "PhantomKey creation" "cargo test --lib llm::tests::test_phantom_key_creation -- --nocapture"
run_test "PhantomKey store/retrieve" "cargo test --lib llm::tests::test_phantom_key_store_and_retrieve -- --nocapture"
run_test "Provider factory" "cargo test --lib llm::tests::test_provider_factory -- --nocapture"
run_test "End-to-end workflow" "cargo test --lib llm::tests::test_end_to_end_workflow -- --nocapture"
run_test "Full system integration" "cargo test --lib llm::tests::test_full_system_integration -- --nocapture"

echo ""

# Attack Lab Demos
echo "--- Attack Lab Demos ---"
echo ""

run_test "Memory Safety demo" "cargo test --lib llm::tests::test_attack_lab_demos -- --nocapture"
run_test "DLEQ Validation demo" "cargo test --lib llm::attack_lab::tests::test_attack_lab_demo_dleq_validation -- --nocapture"
run_test "Ledger Tampering demo" "cargo test --lib llm::attack_lab::tests::test_attack_lab_demo_ledger_tampering -- --nocapture"
run_test "Canary Detection demo" "cargo test --lib llm::attack_lab::tests::test_attack_lab_demo_canary_detection -- --nocapture"

echo ""

# Integration tests
echo "--- Integration Tests ---"
echo ""

run_test "All modules import" "cargo test --lib tests::integration::tests::test_all_modules_import -- --nocapture"
run_test "DKG workflow" "cargo test --lib tests::integration::tests::test_dkg_workflow -- --nocapture"
run_test "Vault workflow" "cargo test --lib tests::integration::tests::test_vault_workflow -- --nocapture"
run_test "Ledger workflow" "cargo test --lib tests::integration::tests::test_ledger_workflow -- --nocapture"

echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo ""
echo "Total tests:  $TOTAL_TESTS"
echo "Passed:      $PASSED_TESTS ${GREEN}✓${NC}"
echo "Failed:      $FAILED_TESTS ${RED}✗${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo "${RED}✗ Some tests failed${NC}"
    exit 1
fi
