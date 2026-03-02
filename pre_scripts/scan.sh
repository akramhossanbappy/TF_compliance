#!/usr/bin/env bash
# =============================================================================
# Terraform Security Scanner
# Tools: tfsec + checkov
# Outputs: JSON results + HTML report
# =============================================================================

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPORT_DIR="${PROJECT_ROOT}/pre_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Default target directory (override with first arg)
TF_DIR="${1:-${PROJECT_ROOT}/terraform}"

# Colors
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[INFO]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${RESET} $*"; }
err()  { echo -e "${RED}[FAIL]${RESET} $*"; }

check_tool() {
  if ! command -v "$1" &>/dev/null; then
    err "Required tool '$1' not found. Install it first:"
    case "$1" in
      tfsec)   echo "  brew install tfsec  OR  https://github.com/aquasecurity/tfsec#installation" ;;
      checkov) echo "  pip install checkov" ;;
      jq)      echo "  brew install jq  OR  apt-get install jq" ;;
    esac
    exit 1
  fi
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
log "Terraform Security Scanner starting..."
log "Target directory: ${TF_DIR}"

[[ -d "${TF_DIR}" ]] || { err "Directory not found: ${TF_DIR}"; exit 1; }

check_tool tfsec
check_tool checkov
check_tool jq

mkdir -p "${REPORT_DIR}"

TFSEC_JSON="${REPORT_DIR}/tfsec_${TIMESTAMP}.json"
CHECKOV_JSON="${REPORT_DIR}/checkov_${TIMESTAMP}.json"
MERGED_JSON="${REPORT_DIR}/merged_${TIMESTAMP}.json"
HTML_REPORT="${REPORT_DIR}/pre_report_${TIMESTAMP}.html"

# ── Run tfsec ─────────────────────────────────────────────────────────────────
log "Running tfsec..."
if tfsec "${TF_DIR}" \
    --format json \
    --out "${TFSEC_JSON}" \
    --no-color \
    --include-passed 2>/dev/null; then
  ok "tfsec completed"
else
  warn "tfsec exited with findings (expected). Continuing..."
fi

# ── Run checkov ───────────────────────────────────────────────────────────────
log "Running checkov..."
if checkov \
    --directory "${TF_DIR}" \
    --output json \
    --output-file-path "${REPORT_DIR}" \
    --quiet 2>/dev/null; then
  ok "checkov completed"
else
  warn "checkov exited with findings (expected). Continuing..."
fi

# checkov writes results.json into the directory, rename it
CHECKOV_RAW="${REPORT_DIR}/results_json.json"
[[ -f "${REPORT_DIR}/results.json" ]] && mv "${REPORT_DIR}/results.json" "${CHECKOV_RAW}"
[[ ! -f "${CHECKOV_RAW}" ]] && echo '{"results":{"failed_checks":[],"passed_checks":[]}}' > "${CHECKOV_RAW}"
cp "${CHECKOV_RAW}" "${CHECKOV_JSON}"

# ── Merge & normalize results ──────────────────────────────────────────────────
log "Merging results..."

python3 "${SCRIPT_DIR}/merge_results.py" \
  --tfsec "${TFSEC_JSON}" \
  --checkov "${CHECKOV_JSON}" \
  --output "${MERGED_JSON}"

ok "Merged JSON: ${MERGED_JSON}"

# ── Generate HTML report ──────────────────────────────────────────────────────
log "Generating HTML report..."
python3 "${SCRIPT_DIR}/generate_report.py" \
  --input "${MERGED_JSON}" \
  --output "${HTML_REPORT}"

ok "HTML report: ${HTML_REPORT}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo -e "${BOLD}  Scan Complete${RESET}"
echo -e "${BOLD}═══════════════════════════════════════${RESET}"

TOTAL=$(jq '.summary.total' "${MERGED_JSON}")
CRITICAL=$(jq '.summary.critical' "${MERGED_JSON}")
HIGH=$(jq '.summary.high' "${MERGED_JSON}")
MEDIUM=$(jq '.summary.medium' "${MERGED_JSON}")
LOW=$(jq '.summary.low' "${MERGED_JSON}")

echo -e "  Total findings : ${BOLD}${TOTAL}${RESET}"
echo -e "  ${RED}CRITICAL${RESET}       : ${CRITICAL}"
echo -e "  ${RED}HIGH${RESET}           : ${HIGH}"
echo -e "  ${YELLOW}MEDIUM${RESET}         : ${MEDIUM}"
echo -e "  ${GREEN}LOW${RESET}            : ${LOW}"
echo ""
echo -e "  Report → ${CYAN}${HTML_REPORT}${RESET}"
echo ""

[[ "${CRITICAL}" -gt 0 ]] && exit 2
[[ "${HIGH}" -gt 0 ]]     && exit 1
exit 0
