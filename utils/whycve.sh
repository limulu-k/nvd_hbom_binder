# shellcheck shell=bash
# 특정 vendor/product/version 에 대해 하나의 CVE 판정 근거(assertion 단위)를 출력한다.
#   source utils/whycve.sh
#   whycve imagemagick imagemagick 7.0.10-58 CVE-2026-56379
#   DB=workspace/other.sqlite whycve openssl openssl 1.1.1k CVE-2021-3711
# 저장소 루트에서 실행할 것 (scripts/ 를 PYTHONPATH 로 사용).
whycve() {
  local DB=${DB:-workspace/nvd_applicability_v5.sqlite}
  local POLICY=${POLICY:-strict}
  PYTHONPATH=scripts python3 scripts/query_nvd_cves.py --db "$DB" \
    --vendor "$1" --product "$2" --version "$3" \
    --prediction-policy "$POLICY" --all-states --trace --format json \
  | python3 -c '
import json,sqlite3,sys
cve,db=sys.argv[1].upper(),sys.argv[2]
d=json.load(sys.stdin)
hit=[r for r in d["results"] if r["cve_id"]==cve]
if not hit: sys.exit("%s: not a candidate (candidates=%s)"%(cve,d["candidate_count"]))
r=hit[0]
con=sqlite3.connect("file:"+db+"?mode=ro",uri=True)
rng=dict(con.execute("SELECT a.assertion_id, COALESCE(e.raw_expression,?) FROM applicability_assertion a LEFT JOIN version_expression e ON e.expression_id=a.expression_id WHERE a.cve_id=?",("-",cve)))
print("== %s  state=%s  positive=%s  reasons=%s"%(cve,r["state"],r["positive"],r["reason_codes"]))
print("   %s"%r["description"][:150])
for a in sorted(r.get("assertions",[]),key=lambda x:(x["version_result"]!="true",x["assertion_id"])):
    print(" %s [%s] %-15s%-11sver=%-6s(%-22s) scope=%-6scfg=%-8sprof=%s"%(
        "->" if a["version_result"]=="true" else "  ",a["assertion_id"],a["source_family"],
        a["polarity"],a["version_result"],a["version_reason"],a["scope_result"],
        a["configuration_result"],a["version_profile"]))
    print("      %s"%rng.get(a["assertion_id"],"-")[:150])
' "$4" "$DB"
}
