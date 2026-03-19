#!/usr/bin/env bash
set -euo pipefail

ASSESSMENT="container/e2e-output/assessment.md"
REFERENCE="samples/assessments"
RESULTS="container/e2e-output/validation-results.txt"

mkdir -p container/e2e-output

echo "=== E2E Assessment Validation ===" | tee "$RESULTS"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$RESULTS"
echo "" | tee -a "$RESULTS"

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1" result="$2"
    if [ "$result" = "PASS" ]; then
        echo "[PASS] $label" | tee -a "$RESULTS"
        PASS=$((PASS + 1))
    elif [ "$result" = "WARN" ]; then
        echo "[WARN] $label" | tee -a "$RESULTS"
        WARN=$((WARN + 1))
    else
        echo "[FAIL] $label" | tee -a "$RESULTS"
        FAIL=$((FAIL + 1))
    fi
}

# 1. File exists and is non-empty
if [ -f "$ASSESSMENT" ] && [ -s "$ASSESSMENT" ]; then
    check "Assessment file exists and is non-empty" "PASS"
    LINES=$(wc -l < "$ASSESSMENT")
    echo "       Lines: $LINES" | tee -a "$RESULTS"
else
    check "Assessment file exists and is non-empty" "FAIL"
    echo "FATAL: No assessment file found at $ASSESSMENT" | tee -a "$RESULTS"
    exit 1
fi

# 2. Required sections
SECTIONS=("Executive Summary" "Infrastructure Snapshot" "Critical Findings" "High-Priority Findings" "Configuration Error Remediation" "Best Practices" "Remediation Roadmap" "Looking Ahead")
for section in "${SECTIONS[@]}"; do
    if grep -qi "$section" "$ASSESSMENT"; then
        check "Section present: $section" "PASS"
    else
        check "Section present: $section" "FAIL"
    fi
done

# 3. Key diagnostic terms
TERMS=("demo" "istiod" "EnvoyFilter" "version" "sidecar")
for term in "${TERMS[@]}"; do
    if grep -qi "$term" "$ASSESSMENT"; then
        check "Key term found: $term" "PASS"
    else
        check "Key term found: $term" "WARN"
    fi
done

# 4. Security: explicit customer name must NOT appear
# Resource names (vs-example-resource) are expected; full company names are not
if grep -qi "example customer\|example customer name" "$ASSESSMENT"; then
    check "Security: customer name redacted" "FAIL"
else
    check "Security: customer name redacted" "PASS"
fi

# 5. Compare with reference (if available)
REF_FILE=$(find "$REFERENCE" -name "*.md" -type f 2>/dev/null | head -1)
if [ -n "$REF_FILE" ]; then
    echo "" | tee -a "$RESULTS"
    echo "--- Reference Comparison ---" | tee -a "$RESULTS"
    REF_LINES=$(wc -l < "$REF_FILE")
    echo "Reference lines: $REF_LINES, Generated lines: $LINES" | tee -a "$RESULTS"

    # Check if reference sections are covered
    REF_SECTIONS=$(grep -c '^#' "$REF_FILE" || true)
    GEN_SECTIONS=$(grep -c '^#' "$ASSESSMENT" || true)
    echo "Reference heading count: $REF_SECTIONS, Generated heading count: $GEN_SECTIONS" | tee -a "$RESULTS"
else
    echo "" | tee -a "$RESULTS"
    echo "No reference assessment found for comparison" | tee -a "$RESULTS"
fi

# Summary
echo "" | tee -a "$RESULTS"
echo "=== Summary ===" | tee -a "$RESULTS"
echo "PASS: $PASS  WARN: $WARN  FAIL: $FAIL" | tee -a "$RESULTS"

if [ "$FAIL" -gt 0 ]; then
    echo "STATUS: FAILED" | tee -a "$RESULTS"
    exit 1
else
    echo "STATUS: PASSED" | tee -a "$RESULTS"
fi
