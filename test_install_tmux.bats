#!/usr/bin/env bats

# Test suite for install_tmux() function with pre/post condition validation
# Requires: bats-core, bats-assert, bats-support

load '/usr/lib/bats-support/load'
load '/usr/lib/bats-assert/load'

# Source the main script to get access to functions
source "${BATS_TEST_DIRNAME}/bootler.sh"

# Test setup and cleanup
setup() {
    # Create temporary test environment
    export TEST_DIR="$(mktemp -d)"
    export ORIGINAL_TARGET_USER="${TARGET_USER:-}"
    export ORIGINAL_TARGET_HOME="${TARGET_HOME:-}"
    export ORIGINAL_TMUX_INSTALL_TPM="${TMUX_INSTALL_TPM:-}"
    
    # Set up test user and home directory
    export TARGET_USER="testuser"
    export TARGET_HOME="${TEST_DIR}/home/testuser"
    mkdir -p "${TARGET_HOME}"
    
    # Mock functions to avoid system dependencies
    apt_install() { echo "apt_install called with: $*" >> "${TEST_DIR}/mock_calls"; }
    run_as() { 
        echo "run_as called with: $*" >> "${TEST_DIR}/mock_calls"
        # Simulate command execution in test environment
        case "$*" in
            "mkdir -p '${TARGET_HOME}/.tmux/plugins'")
                mkdir -p "${TARGET_HOME}/.tmux/plugins"
                ;;
            "git clone --depth 1 https://github.com/tmux-plugins/tpm '${TARGET_HOME}/.tmux/plugins/tpm'")
                mkdir -p "${TARGET_HOME}/.tmux/plugins/tpm"
                touch "${TARGET_HOME}/.tmux/plugins/tpm/tpm"
                chmod +x "${TARGET_HOME}/.tmux/plugins/tpm/tpm"
                ;;
        esac
    }
    command() {
        if [[ "$1" == "-v" && "$2" == "tmux" ]]; then
            # Simulate tmux availability based on test scenario
            if [[ "${TMUX_AVAILABLE:-1}" == "1" ]]; then
                return 0
            else
                return 1
            fi
        fi
        # Default to original command behavior for other cases
        /usr/bin/command "$@"
    }
    
    export -f apt_install run_as command
}

teardown() {
    # Cleanup test environment
    rm -rf "${TEST_DIR}"
    export TARGET_USER="${ORIGINAL_TARGET_USER}"
    export TARGET_HOME="${ORIGINAL_TARGET_HOME}"
    export TMUX_INSTALL_TPM="${ORIGINAL_TMUX_INSTALL_TPM}"
}

# Pre-condition validation tests

@test "install_tmux: fails when TARGET_USER is not set" {
    unset TARGET_USER
    
    run install_tmux
    
    assert_failure
    assert_output --partial "TARGET_USER"
}

@test "install_tmux: fails when TARGET_HOME cannot be determined" {
    export TARGET_USER=""
    export TARGET_HOME=""
    
    run install_tmux
    
    assert_failure
}

@test "install_tmux: validates TMUX_INSTALL_TPM variable type" {
    export TMUX_INSTALL_TPM="invalid"
    
    # Should handle non-numeric values gracefully
    run install_tmux
    
    # Should not fail catastrophically, but may skip TPM installation
    assert_success
}

# Core functionality tests

@test "install_tmux: installs tmux when not available" {
    export TMUX_AVAILABLE=0
    export TMUX_INSTALL_TPM=1
    
    run install_tmux
    
    assert_success
    assert_output --partial "TMUX not found; installing via apt"
    assert_line --partial "apt_install called with: tmux"
}

@test "install_tmux: skips tmux installation when already available" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    
    run install_tmux
    
    assert_success
    refute_output --partial "TMUX not found"
    refute_line --partial "apt_install called with: tmux"
}

@test "install_tmux: installs TPM when TMUX_INSTALL_TPM=1" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    
    run install_tmux
    
    assert_success
    assert_output --partial "Installing TMUX Plugin Manager (TPM)..."
    assert_line --partial "run_as called with: mkdir -p '${TARGET_HOME}/.tmux/plugins'"
    assert_line --partial "run_as called with: git clone --depth 1 https://github.com/tmux-plugins/tpm"
}

@test "install_tmux: skips TPM installation when TMUX_INSTALL_TPM=0" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=0
    
    run install_tmux
    
    assert_success
    refute_output --partial "Installing TMUX Plugin Manager"
    refute_line --partial "git clone"
}

@test "install_tmux: skips TPM installation when already exists" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    
    # Pre-create TPM installation
    mkdir -p "${TARGET_HOME}/.tmux/plugins/tpm"
    touch "${TARGET_HOME}/.tmux/plugins/tpm/tpm"
    chmod +x "${TARGET_HOME}/.tmux/plugins/tpm/tpm"
    
    run install_tmux
    
    assert_success
    assert_output --partial "TPM already installed; skipping"
    refute_line --partial "git clone"
}

# Post-condition validation tests

@test "install_tmux: creates TPM plugin directory with correct structure" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    
    run install_tmux
    
    assert_success
    assert [ -d "${TARGET_HOME}/.tmux/plugins" ]
    assert [ -d "${TARGET_HOME}/.tmux/plugins/tpm" ]
    assert [ -x "${TARGET_HOME}/.tmux/plugins/tpm/tpm" ]
}

@test "install_tmux: succeeds and reports completion" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    
    run install_tmux
    
    assert_success
    assert_output --partial "TMUX setup completed"
    assert_output --partial "configuration will be provided by dotfiles"
}

@test "install_tmux: handles git clone failures gracefully" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    
    # Override run_as to simulate git clone failure
    run_as() {
        echo "run_as called with: $*" >> "${TEST_DIR}/mock_calls"
        case "$*" in
            "mkdir -p '${TARGET_HOME}/.tmux/plugins'")
                mkdir -p "${TARGET_HOME}/.tmux/plugins"
                ;;
            "git clone --depth 1"*)
                return 1  # Simulate git clone failure
                ;;
        esac
    }
    export -f run_as
    
    run install_tmux
    
    # Should complete successfully despite clone failure (due to || true)
    assert_success
    assert_output --partial "Installing TMUX Plugin Manager"
}

# Edge cases and error handling

@test "install_tmux: handles non-existent target home directory" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    export TARGET_HOME="${TEST_DIR}/nonexistent/user"
    
    run install_tmux
    
    # Should attempt to create directories via run_as
    assert_success
    assert_line --partial "mkdir -p"
}

@test "install_tmux: validates plugin path construction" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=1
    
    run install_tmux
    
    assert_success
    # Verify the plugin path uses TARGET_HOME correctly
    local expected_path="${TARGET_HOME}/.tmux/plugins"
    assert_line --partial "${expected_path}"
}

@test "install_tmux: environment variable defaults work correctly" {
    export TMUX_AVAILABLE=1
    unset TMUX_INSTALL_TPM
    
    run install_tmux
    
    # Should default to installing TPM (TMUX_INSTALL_TPM defaults to 1)
    assert_success
    assert_output --partial "Installing TMUX Plugin Manager"
}

# Integration test with multiple conditions

@test "install_tmux: complete workflow - tmux missing, TPM enabled" {
    export TMUX_AVAILABLE=0
    export TMUX_INSTALL_TPM=1
    
    run install_tmux
    
    assert_success
    
    # Verify complete workflow
    assert_line --partial "apt_install called with: tmux"
    assert_line --partial "Installing TMUX Plugin Manager"
    assert_line --partial "mkdir -p '${TARGET_HOME}/.tmux/plugins'"
    assert_line --partial "git clone --depth 1"
    assert_output --partial "TMUX setup completed"
    
    # Verify post-conditions
    assert [ -d "${TARGET_HOME}/.tmux/plugins/tpm" ]
    assert [ -x "${TARGET_HOME}/.tmux/plugins/tpm/tpm" ]
}

@test "install_tmux: minimal workflow - tmux present, TPM disabled" {
    export TMUX_AVAILABLE=1
    export TMUX_INSTALL_TPM=0
    
    run install_tmux
    
    assert_success
    
    # Verify minimal workflow
    refute_line --partial "apt_install called with: tmux"
    refute_output --partial "Installing TMUX Plugin Manager"
    assert_output --partial "TMUX setup completed"
    
    # Verify no TPM installation occurred
    assert [ ! -d "${TARGET_HOME}/.tmux/plugins/tpm" ]
}