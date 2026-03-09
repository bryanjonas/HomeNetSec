#!/usr/bin/env bash
#
# HomeNetSec: Continuous Pipeline Entry Point
#
# This script is the primary entry point for external schedulers (cron, systemd, etc.)
# It orchestrates the continuous pipeline: Ingest → Analysis → Dashboard
#
# Usage:
#   ./scripts/run_ingest_and_analysis.sh
#
# Environment Variables:
#   HOMENETSEC_WORKDIR  - Required: Output directory path
#   SKIP_INGEST         - Optional: Set to 1 to skip ingest phase
#   SKIP_ANALYSIS       - Optional: Set to 1 to skip analysis phase
#   SKIP_DASHBOARD      - Optional: Set to 1 to skip dashboard generation
#
# Exit Codes:
#   0 - Success (all phases completed)
#   1 - Ingest failed
#   2 - Analysis failed
#   3 - Dashboard generation failed
#   4 - Configuration error
#

set -Eeu -o pipefail

# Determine script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source .env if it exists
if [[ -f "$ROOT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    source "$ROOT_DIR/.env"
fi

# Configuration
WORKDIR="${HOMENETSEC_WORKDIR:-}"
SKIP_INGEST="${SKIP_INGEST:-0}"
SKIP_ANALYSIS="${SKIP_ANALYSIS:-0}"
SKIP_DASHBOARD="${SKIP_DASHBOARD:-0}"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*" >&2
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

log_section() {
    echo "" >&2
    echo "========================================" >&2
    echo "$*" >&2
    echo "========================================" >&2
}

# Validate configuration
validate_config() {
    if [[ -z "$WORKDIR" ]]; then
        log_error "HOMENETSEC_WORKDIR is not set"
        log_error "Please set it in .env or pass as environment variable"
        return 4
    fi

    if [[ ! -d "$WORKDIR" ]]; then
        log_error "HOMENETSEC_WORKDIR does not exist: $WORKDIR"
        return 4
    fi

    log_info "Configuration validated"
    log_info "WORKDIR: $WORKDIR"
    return 0
}

# Update pipeline status JSON
update_pipeline_status() {
    local status="$1"
    local message="$2"
    if ! python3 "$SCRIPT_DIR/generate_pipeline_status.py" \
        --workdir "$WORKDIR" \
        --overall-status "$status" \
        --overall-message "$message" >/dev/null; then
        log_error "Unable to update pipeline status file: $WORKDIR/state/pipeline_status.json"
        return 0
    fi
}

ensure_state_databases() {
    local init_script="$SCRIPT_DIR/init_databases.py"

    if [[ ! -f "$init_script" ]]; then
        log_error "Database initialization script not found: $init_script"
        return 4
    fi

    if ! python3 "$init_script" --workdir "$WORKDIR" >/dev/null; then
        log_error "Failed to initialize state databases"
        return 4
    fi
}

# Phase 1: Ingest
run_ingest() {
    log_section "Phase 1: PCAP Ingest & Processing"

    if [[ "$SKIP_INGEST" == "1" ]]; then
        log_info "Skipping ingest phase (SKIP_INGEST=1)"
        return 0
    fi

    local ingest_script="$SCRIPT_DIR/continuous_ingest.sh"

    if [[ ! -x "$ingest_script" ]]; then
        log_error "Ingest script not found or not executable: $ingest_script"
        return 1
    fi

    log_info "Running ingest pipeline..."

    if ! "$ingest_script" --once; then
        log_error "Ingest pipeline failed"
        return 1
    fi

    log_info "✓ Ingest phase completed successfully"
    return 0
}

# Phase 2: Analysis
run_analysis() {
    log_section "Phase 2: Security Analysis"

    if [[ "$SKIP_ANALYSIS" == "1" ]]; then
        log_info "Skipping analysis phase (SKIP_ANALYSIS=1)"
        return 0
    fi

    local analysis_script="$SCRIPT_DIR/continuous_analysis.sh"

    if [[ ! -x "$analysis_script" ]]; then
        log_error "Analysis script not found or not executable: $analysis_script"
        return 2
    fi

    log_info "Running analysis pipeline..."

    if ! "$analysis_script" --process-queue; then
        log_error "Analysis pipeline failed"
        return 2
    fi

    log_info "✓ Analysis phase completed successfully"
    return 0
}

# Phase 3: Dashboard
run_dashboard() {
    log_section "Phase 3: Dashboard Generation"

    if [[ "$SKIP_DASHBOARD" == "1" ]]; then
        log_info "Skipping dashboard phase (SKIP_DASHBOARD=1)"
        return 0
    fi

    local dashboard_script="$SCRIPT_DIR/generate_dashboard.sh"

    if [[ ! -x "$dashboard_script" ]]; then
        log_error "Dashboard script not found or not executable: $dashboard_script"
        return 3
    fi

    log_info "Generating dashboard..."

    if ! "$dashboard_script"; then
        log_error "Dashboard generation failed"
        return 3
    fi

    log_info "✓ Dashboard phase completed successfully"
    return 0
}

# Main execution
main() {
    local start_time
    start_time=$(date +%s)

    log_section "HomeNetSec Pipeline Execution Started"
    log_info "Start time: $(date)"

    # Validate configuration
    if validate_config; then
        :
    else
        return $?
    fi

    if ensure_state_databases; then
        :
    else
        return $?
    fi

    # Update status: running
    update_pipeline_status "running" "Pipeline execution in progress"

    # Execute phases
    local exit_code=0

    if run_ingest; then
        :
    else
        exit_code=$?
        update_pipeline_status "failed" "Ingest phase failed"
        log_error "Pipeline failed at ingest phase"
        return $exit_code
    fi

    if run_analysis; then
        :
    else
        exit_code=$?
        update_pipeline_status "failed" "Analysis phase failed"
        log_error "Pipeline failed at analysis phase"
        return $exit_code
    fi

    if run_dashboard; then
        :
    else
        exit_code=$?
        update_pipeline_status "failed" "Dashboard generation failed"
        log_error "Pipeline failed at dashboard phase"
        return $exit_code
    fi

    # Calculate runtime
    local end_time
    end_time=$(date +%s)
    local runtime=$((end_time - start_time))

    # Update status: success
    update_pipeline_status "success" "All phases completed successfully (${runtime}s)"

    log_section "Pipeline Execution Completed Successfully"
    log_info "End time: $(date)"
    log_info "Total runtime: ${runtime} seconds"

    return 0
}

# Run main function
main "$@"
exit_code=$?

# Ensure we exit with the correct code
exit $exit_code
