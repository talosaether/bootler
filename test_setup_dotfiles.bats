#!/usr/bin/env bats

# Test suite for setup_dotfiles() function with pre/post condition validation
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
    export ORIGINAL_DOTFILES_REPO="${DOTFILES_REPO:-}"
    export ORIGINAL_DOTFILES_METHOD="${DOTFILES_METHOD:-}"
    export ORIGINAL_DOTFILES_PACKAGES="${DOTFILES_PACKAGES:-}"
    export ORIGINAL_DOTFILES_REF="${DOTFILES_REF:-}"
    export ORIGINAL_DOTFILES_STOW_FLAGS="${DOTFILES_STOW_FLAGS:-}"
    
    # Set up test user and home directory
    export TARGET_USER="testuser"
    export TARGET_HOME="${TEST_DIR}/home/testuser"
    mkdir -p "${TARGET_HOME}"
    
    # Default test dotfiles repo
    export TEST_DOTFILES_REPO="https://github.com/test/dotfiles.git"
    
    # Mock functions to avoid system dependencies
    apt_install() { 
        echo "apt_install called with: $*" >> "${TEST_DIR}/mock_calls"
        # Simulate stow installation success
        if [[ "$*" == "stow" ]]; then
            export STOW_INSTALLED=1
        fi
    }
    
    run_as() { 
        echo "run_as called with: $*" >> "${TEST_DIR}/mock_calls"
        # Simulate various commands
        case "$*" in
            "cd '${TARGET_HOME}/.dotfiles' && for pkg in"*)
                # Simulate stow package application
                echo "stow packages applied" >> "${TEST_DIR}/stow_output"
                ;;
            "cp -rf '${TARGET_HOME}/.dotfiles/.' '${TARGET_HOME}/'"*)
                # Simulate copy method
                echo "dotfiles copied" >> "${TEST_DIR}/copy_output"
                ;;
        esac
    }
    
    chown() {
        echo "chown called with: $*" >> "${TEST_DIR}/mock_calls"
        # Simulate chown success
        return 0
    }
    
    command() {
        if [[ "$1" == "-v" && "$2" == "stow" ]]; then
            # Simulate stow availability based on test scenario
            if [[ "${STOW_AVAILABLE:-0}" == "1" || "${STOW_INSTALLED:-0}" == "1" ]]; then
                return 0
            else
                return 1
            fi
        fi
        # Default to original command behavior for other cases
        /usr/bin/command "$@"
    }
    
    clone_update_repo() {
        local url="$1" dest="$2" ref="${3:-}"
        echo "clone_update_repo called with url=$url dest=$dest ref=$ref" >> "${TEST_DIR}/mock_calls"
        
        # Simulate repo cloning/updating
        if [[ "${CLONE_SHOULD_FAIL:-0}" == "1" ]]; then
            return 1
        fi
        
        mkdir -p "$dest/.git"
        mkdir -p "$dest"
        
        # Create mock dotfiles structure based on test packages
        if [[ -n "${DOTFILES_PACKAGES:-}" ]]; then
            for pkg in ${DOTFILES_PACKAGES}; do
                mkdir -p "$dest/$pkg"
                echo "# $pkg config" > "$dest/$pkg/.${pkg}rc"
            done
        fi
        
        # Create some default files
        echo "# Test dotfile" > "$dest/.testrc"
        mkdir -p "$dest/nvim"
        echo "# Neovim config" > "$dest/nvim/init.vim"
        
        return 0
    }
    
    export -f apt_install run_as chown command clone_update_repo
}

teardown() {
    # Cleanup test environment
    rm -rf "${TEST_DIR}"
    export TARGET_USER="${ORIGINAL_TARGET_USER}"
    export TARGET_HOME="${ORIGINAL_TARGET_HOME}"
    export DOTFILES_REPO="${ORIGINAL_DOTFILES_REPO}"
    export DOTFILES_METHOD="${ORIGINAL_DOTFILES_METHOD}"
    export DOTFILES_PACKAGES="${ORIGINAL_DOTFILES_PACKAGES}"
    export DOTFILES_REF="${ORIGINAL_DOTFILES_REF}"
    export DOTFILES_STOW_FLAGS="${ORIGINAL_DOTFILES_STOW_FLAGS}"
}

# Pre-condition validation tests

@test "setup_dotfiles: skips when DOTFILES_REPO is not set" {
    unset DOTFILES_REPO
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "No dotfiles repository specified; skipping dotfiles setup"
    refute_line --partial "clone_update_repo"
}

@test "setup_dotfiles: skips when DOTFILES_REPO is empty" {
    export DOTFILES_REPO=""
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "No dotfiles repository specified; skipping dotfiles setup"
    refute_line --partial "clone_update_repo"
}

@test "setup_dotfiles: fails when TARGET_HOME is not set" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    unset TARGET_HOME
    
    run setup_dotfiles
    
    assert_failure
}

@test "setup_dotfiles: fails when TARGET_USER is not set" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    unset TARGET_USER
    
    run setup_dotfiles
    
    assert_failure
}

# Core functionality tests - Repository cloning

@test "setup_dotfiles: clones dotfiles repository to correct location" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    
    run setup_dotfiles
    
    assert_success
    assert_line --partial "clone_update_repo called with url=${TEST_DOTFILES_REPO} dest=${TARGET_HOME}/.dotfiles ref="
    assert_line --partial "chown called with: -R ${TARGET_USER}:${TARGET_USER} ${TARGET_HOME}/.dotfiles"
}

@test "setup_dotfiles: clones with specific git reference" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_REF="develop"
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "Setting up dotfiles from ${TEST_DOTFILES_REPO} (ref develop)"
    assert_line --partial "clone_update_repo called with url=${TEST_DOTFILES_REPO} dest=${TARGET_HOME}/.dotfiles ref=develop"
}

@test "setup_dotfiles: handles clone failures gracefully" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export CLONE_SHOULD_FAIL=1
    
    run setup_dotfiles
    
    assert_failure
    assert_line --partial "clone_update_repo called with"
}

# Method selection and stow installation tests

@test "setup_dotfiles: defaults to stow method" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    unset DOTFILES_METHOD
    
    run setup_dotfiles
    
    assert_success
    # Should attempt to use stow method (but no packages specified, so warning)
    assert_output --partial "No dotfiles packages specified for stow method"
}

@test "setup_dotfiles: installs stow when not available" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES="nvim tmux"
    export STOW_AVAILABLE=0
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "stow not found; installing stow"
    assert_line --partial "apt_install called with: stow"
}

@test "setup_dotfiles: falls back to copy method when stow installation fails" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export STOW_AVAILABLE=0
    export STOW_INSTALLED=0  # Simulate stow install failure
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "stow installation failed; falling back to copy method"
    assert_output --partial "Using copy method for dotfiles"
}

# Stow method tests

@test "setup_dotfiles: applies stow packages when specified" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES="nvim tmux zsh"
    export STOW_AVAILABLE=1
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "Using stow method for dotfiles packages: nvim tmux zsh"
    assert_line --partial "run_as called with: cd '${TARGET_HOME}/.dotfiles' && for pkg in nvim tmux zsh"
    assert [ -f "${TEST_DIR}/stow_output" ]
}

@test "setup_dotfiles: passes custom stow flags" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES="nvim"
    export DOTFILES_STOW_FLAGS="--verbose --no-folding"
    export STOW_AVAILABLE=1
    
    run setup_dotfiles
    
    assert_success
    assert_line --partial "stow --restow --verbose --no-folding"
}

@test "setup_dotfiles: warns when no stow packages specified" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    unset DOTFILES_PACKAGES
    export STOW_AVAILABLE=1
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "No dotfiles packages specified for stow method; skipping dotfiles application"
}

# Copy method tests

@test "setup_dotfiles: uses copy method when specified" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="copy"
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "Using copy method for dotfiles"
    assert_line --partial "run_as called with: cp -rf '${TARGET_HOME}/.dotfiles/.' '${TARGET_HOME}/'"
    assert [ -f "${TEST_DIR}/copy_output" ]
}

@test "setup_dotfiles: copy method handles errors gracefully" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="copy"
    
    # Override run_as to simulate copy failure
    run_as() {
        echo "run_as called with: $*" >> "${TEST_DIR}/mock_calls"
        if [[ "$*" == *"cp -rf"* ]]; then
            return 1  # Simulate copy failure
        fi
    }
    export -f run_as
    
    run setup_dotfiles
    
    # Should still succeed due to || true
    assert_success
    assert_output --partial "Using copy method for dotfiles"
}

# Post-condition validation tests

@test "setup_dotfiles: creates dotfiles directory structure" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES="nvim"
    export STOW_AVAILABLE=1
    
    run setup_dotfiles
    
    assert_success
    assert [ -d "${TARGET_HOME}/.dotfiles" ]
    assert [ -d "${TARGET_HOME}/.dotfiles/.git" ]
    assert [ -d "${TARGET_HOME}/.dotfiles/nvim" ]
}

@test "setup_dotfiles: sets correct ownership on dotfiles directory" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    
    run setup_dotfiles
    
    assert_success
    assert_line --partial "chown called with: -R ${TARGET_USER}:${TARGET_USER} ${TARGET_HOME}/.dotfiles"
}

@test "setup_dotfiles: reports successful completion" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "Dotfiles setup completed"
}

# Integration tests with multiple scenarios

@test "setup_dotfiles: complete workflow - stow method with packages" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES="nvim tmux git"
    export DOTFILES_REF="main"
    export DOTFILES_STOW_FLAGS="--verbose"
    export STOW_AVAILABLE=1
    
    run setup_dotfiles
    
    assert_success
    
    # Verify complete workflow
    assert_output --partial "Setting up dotfiles from ${TEST_DOTFILES_REPO} (ref main)"
    assert_line --partial "clone_update_repo called with url=${TEST_DOTFILES_REPO} dest=${TARGET_HOME}/.dotfiles ref=main"
    assert_line --partial "chown called with: -R ${TARGET_USER}:${TARGET_USER} ${TARGET_HOME}/.dotfiles"
    assert_output --partial "Using stow method for dotfiles packages: nvim tmux git"
    assert_line --partial "stow --restow --verbose"
    assert_output --partial "Dotfiles setup completed"
    
    # Verify post-conditions
    assert [ -d "${TARGET_HOME}/.dotfiles" ]
    assert [ -f "${TEST_DIR}/stow_output" ]
}

@test "setup_dotfiles: complete workflow - copy method fallback" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES="nvim"
    export STOW_AVAILABLE=0
    export STOW_INSTALLED=0  # Stow install fails
    
    run setup_dotfiles
    
    assert_success
    
    # Verify fallback workflow
    assert_output --partial "stow not found; installing stow"
    assert_line --partial "apt_install called with: stow"
    assert_output --partial "stow installation failed; falling back to copy method"
    assert_output --partial "Using copy method for dotfiles"
    assert_line --partial "cp -rf"
    assert_output --partial "Dotfiles setup completed"
    
    # Verify post-conditions
    assert [ -d "${TARGET_HOME}/.dotfiles" ]
    assert [ -f "${TEST_DIR}/copy_output" ]
}

# Edge cases and error handling

@test "setup_dotfiles: handles invalid method gracefully" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="invalid_method"
    
    run setup_dotfiles
    
    assert_success
    # Should fall back to default stow behavior
    assert_output --partial "No dotfiles packages specified for stow method"
    assert_output --partial "Dotfiles setup completed"
}

@test "setup_dotfiles: handles empty packages with stow method" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES=""
    export STOW_AVAILABLE=1
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "No dotfiles packages specified for stow method"
    refute_line --partial "stow --restow"
}

@test "setup_dotfiles: validates dotfiles directory path construction" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    
    run setup_dotfiles
    
    assert_success
    # Verify the dotfiles path uses TARGET_HOME correctly
    local expected_path="${TARGET_HOME}/.dotfiles"
    assert_line --partial "${expected_path}"
}

@test "setup_dotfiles: processes multiple packages correctly" {
    export DOTFILES_REPO="${TEST_DOTFILES_REPO}"
    export DOTFILES_METHOD="stow"
    export DOTFILES_PACKAGES="nvim tmux zsh git bash"
    export STOW_AVAILABLE=1
    
    run setup_dotfiles
    
    assert_success
    assert_output --partial "Using stow method for dotfiles packages: nvim tmux zsh git bash"
    
    # Verify all packages are mentioned in the command
    assert_line --partial "for pkg in nvim tmux zsh git bash"
}