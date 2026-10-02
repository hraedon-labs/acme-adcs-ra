# Shared step helpers for the POSIX-shell client scenarios (sourced).
#   step    <name> <command...>            PASS when the command exits 0
#   refused <name> <regex> <command...>    PASS when the command exits non-zero
#                                          AND its output matches <regex> (so a
#                                          refusal for the wrong reason is a FAIL)
#   skip    <name> <why>                   the client cannot drive this endpoint
CLIENT="${CLIENT:-unknown}"
_out=""
cleanup_step_tmp() {
    [ -z "$_out" ] || rm -f "$_out"
}
trap cleanup_step_tmp EXIT

step() {
    _out="$(mktemp)"
    name="$1"; shift
    echo "=== STEP $name: $*"
    "$@" >"$_out" 2>&1; rc=$?
    cat "$_out"
    if [ $rc -eq 0 ]; then echo "RESULT $CLIENT $name PASS"; else echo "RESULT $CLIENT $name FAIL (exit $rc)"; fi
    rm -f "$_out"
    _out=""
}
refused() {
    _out="$(mktemp)"
    name="$1"; pattern="$2"; shift 2
    echo "=== STEP $name (expect refusal matching /$pattern/): $*"
    "$@" >"$_out" 2>&1; rc=$?
    cat "$_out"
    if [ $rc -ne 0 ] && grep -Eq "$pattern" "$_out"; then
        echo "RESULT $CLIENT $name PASS"
    else
        echo "RESULT $CLIENT $name FAIL (exit $rc; refusal reason not matched)"
    fi
    rm -f "$_out"
    _out=""
}
skip() { echo "RESULT $CLIENT $1 SKIP ($2)"; }
