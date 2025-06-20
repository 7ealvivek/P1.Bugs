#!/bin/bash

# A personalized Nuclei automation script by Vivek.
# Features: Performance profiles, colored banner, prioritized scanning, Slack alerts,
# terminal output, conditional logs, and a final scan summary report.

# --- Configuration ---
# WARNING: Your Slack Webhook URL is a secret. Do not share this script publicly.
SLACK_WEBHOOK="https://hooks.slack.com/services/T03JPK11LNM/B090R2S4ED9/2Flx5qwAfioGVLjZQE0MBxv"
DEFAULT_SEVERITY="high,critical,medium"

# --- Color Definitions ---
C_CYAN='\033[36m'; C_GREEN='\033[32m'; C_YELLOW='\033[33m'; C_RESET='\033[0m'

# --- Banner Function ---
display_banner() {
    cat << 'EOF'
░▒▓███████▓▒░     ░▒▓█▓▒░          ░▒▓███████▓▒░  ░▒▓█▓▒░░▒▓█▓▒░  ░▒▓██████▓▒░   ░▒▓███████▓▒░
░▒▓█▓▒░░▒▓█▓▒░ ░▒▓████▓▒░          ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░    ░▒▓█▓▒░          ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░        ░▒▓█▓▒░
░▒▓███████▓▒░     ░▒▓█▓▒░          ░▒▓███████▓▒░  ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒▒▓███▓▒░  ░▒▓██████▓▒░
░▒▓█▓▒░           ░▒▓█▓▒░          ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░        ░▒▓█▓▒░
░▒▓█▓▒░           ░▒▓█▓▒░ ░▒▓██▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░        ░▒▓█▓▒░
░▒▓█▓▒░           ░▒▓█▓▒░ ░▒▓██▓▒░ ░▒▓███████▓▒░   ░▒▓██████▓▒░   ░▒▓██████▓▒░  ░▒▓███████▓▒░

EOF
    local details="${C_CYAN}by Vivek Kashyap${C_RESET} | ${C_GREEN}Bugcrowd:${C_RESET} bugcrowd.com/realvivek | ${C_GREEN}X:${C_RESET} @starkcharry | ${C_GREEN}GitHub:${C_RESET} @7ealvivek"
    local width=${COLUMNS:-$(tput cols 2>/dev/null || echo 100)}
    local details_len=$(echo -e "$details" | sed 's/\x1b\[[0-9;]*m//g' | wc -c)
    local padding_len=$((width - details_len))
    printf "%${padding_len}s" "" && echo -e "$details\n"
}

usage() {
    echo "Usage: $0 -f <target_file> [-s <severity>] [-p <profile>]"
    echo "  -f <file>     : Required. File with target URLs."
    echo "  -s <severity> : Optional. Comma-separated severities. Default: $DEFAULT_SEVERITY"
    echo "  -p <profile>  : Optional. Performance profile. Options: 'safe' (default), 'aggressive'."
    exit 1
}

# --- Initial Setup ---
display_banner
for cmd in nuclei jq curl; do
    if ! command -v "$cmd" &> /dev/null; then
        echo -e "${C_YELLOW}[!] ERROR: Required command '$cmd' is not installed.${C_RESET}" >&2; exit 1;
    fi
done

# --- Argument Parsing ---
SEVERITY="$DEFAULT_SEVERITY"
TARGET_FILE=""
PROFILE="safe"
while getopts ":f:s:p:" opt; do
    case $opt in
        f) TARGET_FILE="$OPTARG" ;;
        s) SEVERITY="$OPTARG" ;;
        p) PROFILE="$OPTARG" ;;
        *) usage ;;
    esac
done

# --- Input Validation ---
if [[ -z "$TARGET_FILE" || ! -f "$TARGET_FILE" ]]; then
    echo -e "${C_YELLOW}[!] ERROR: Target file not provided or does not exist.${C_RESET}" >&2; usage;
fi

# --- Set Performance Flags Based on Profile ---
echo "[*] Using performance profile: ${C_GREEN}${PROFILE}${C_RESET}"
case "$PROFILE" in
    safe) PERF_FLAGS="-timeout 15 -c 25 -bs 25 -rl 280" ;;
    aggressive) PERF_FLAGS="-timeout 18 -c 50 -bs 100 -rl 340" ;;
    *) echo -e "${C_YELLOW}[!] Invalid profile '$PROFILE'. Use 'safe' or 'aggressive'.${C_RESET}" >&2; usage ;;
esac

# --- Build Nuclei Arguments ---
JSON_OUTPUT="${TARGET_FILE%.txt}.json"; VULN_OUTPUT_FILE="${TARGET_FILE%.txt}_vulns.txt"
PROXY_CMD=""; if command -v proxychains &> /dev/null; then if proxychains -q curl --max-time 10 https://ifconfig.me &> /dev/null; then PROXY_CMD="proxychains"; fi; fi
PRIORITY_TEMPLATE_PATHS=(~/nuclei-templates/technologies/ ~/nuclei-templates/cves/ ~/nuclei-templates/vulnerabilities/ ~/nuclei-templates/security-misconfiguration/)
OTHER_TEMPLATE_PATHS=(~/nuclei-templates/brute-force/ ~/nuclei-templates/basic-detections/ ~/nuclei-templates/dns/ ~/nuclei-templates/files/ ~/nuclei-templates/panels/ ~/nuclei-templates/subdomain-takeover/ ~/nuclei-templates/tokens/)
ALL_TEMPLATE_PATHS=("${PRIORITY_TEMPLATE_PATHS[@]}" "${OTHER_TEMPLATE_PATHS[@]}")
EXCLUDE_TAGS=(network headers dns ssl pop3); EXCLUDE_IDS=(weak-cipher-suites self-signed-ssl revoked-ssl-certificate unauthenticated-varnish-cache-purge untrusted-root-certificate expired-ssl mismatched-ssl-certificate missing-x-frame-options mismatched-ssl CVE-2000-0114 CVE-2017-5487 aws-object-listing CVE-2021-24917 exposed-sharepoint-list git-mailmap)
nuclei_args=(); nuclei_args+=(-etags "$(IFS=,; echo "${EXCLUDE_TAGS[*]}")"); nuclei_args+=(-eid "$(IFS=,; echo "${EXCLUDE_IDS[*]}")")
for path in "${ALL_TEMPLATE_PATHS[@]}"; do nuclei_args+=(-t "$path"); done

# --- Run Scan and Process Results ---
echo -e "${C_YELLOW}[*] Starting Nuclei scan for '$TARGET_FILE' with severity: $SEVERITY${C_RESET}"
VULN_FOUND_FLAG=0; count_critical=0; count_high=0; count_medium=0; count_low=0; count_info=0

# THIS IS THE CORRECTED PART: Using Process Substitution '< <(...)' instead of a pipe '|'
# This ensures the loop runs in the current shell and variable changes are not lost.
while read -r line; do
    if ! jq -e . >/dev/null 2>&1 <<< "$line"; then continue; fi
    VULN_FOUND_FLAG=1
    severity=$(jq -r '.info.severity' <<< "$line"); case "$severity" in "critical") ((count_critical++));; "high") ((count_high++));; "medium") ((count_medium++));; "low") ((count_low++));; "info") ((count_info++));; esac
    formatted_message=$(jq -r '"🚨 <!channel> *Vivek New P1 Discovered*\n\n*Severity:* `\(.info.severity)`\n*Host:* `\(.host)`\n*Affected URL:* `\(.["matched-at"])`\n*Template:* `\(.template)`"' <<< "$line")
    
    if [[ -n "$formatted_message" ]]; then
        # Action 1: Print to terminal
        echo -e "\n${formatted_message}\n"
        
        # Action 2: Send to Slack
        payload=$(jq -n --arg text "$formatted_message" '{text: $text, "mrkdwn": true}')
        curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK" >/dev/null

        # Action 3: Write to vulnerability file
        if [[ ! -f "$VULN_OUTPUT_FILE" ]]; then
            echo "[*] First vulnerability found. Creating summary file: $VULN_OUTPUT_FILE"
            echo -e "${formatted_message}\n" > "$VULN_OUTPUT_FILE"
        else
            echo -e "${formatted_message}\n" >> "$VULN_OUTPUT_FILE"
        fi
    fi
done < <($PROXY_CMD nuclei -l "$TARGET_FILE" -o "$JSON_OUTPUT" -jsonl -silent -severity "$SEVERITY" $PERF_FLAGS "${nuclei_args[@]}")


# --- Final Status Report and Slack Summary Notification ---
# This part will now have the CORRECT values for all the counters.
echo -e "${C_GREEN}[*] Scan complete.${C_RESET}"
summary_text="✅ *Scan Completed for Target File:* \`$(basename "$TARGET_FILE")\`\n\n*Summary of Findings:*\n"
if [ "$VULN_FOUND_FLAG" -eq 0 ]; then
    summary_text+="No vulnerabilities were found matching the criteria."
else
    [ "$count_critical" -gt 0 ] && summary_text+="- *Critical:* \`$count_critical\`\n"
    [ "$count_high" -gt 0 ]     && summary_text+="- *High:* \`$count_high\`\n"
    [ "$count_medium" -gt 0 ]   && summary_text+="- *Medium:* \`$count_medium\`\n"
    [ "$count_low" -gt 0 ]      && summary_text+="- *Low:* \`$count_low\`\n"
    [ "$count_info" -gt 0 ]     && summary_text+="- *Info:* \`$count_info\`\n"
    summary_text+="\nDetailed results saved to \`$(basename "$JSON_OUTPUT")\`"
    [ -f "$VULN_OUTPUT_FILE" ] && summary_text+=" and a summary in \`$(basename "$VULN_OUTPUT_FILE")\`"
fi

# Print summary to terminal
echo -e "\n--- Scan Summary ---\n$(echo -e "$summary_text" | sed -e 's/\*/-/g' -e 's/`//g')"

# Send summary to Slack
echo "[*] Sending final summary report to Slack..."
summary_payload=$(jq -n --arg text "$summary_text" '{text: $text, "mrkdwn": true}')
curl -s -X POST -H 'Content-type: application/json' --data "$summary_payload" "$SLACK_WEBHOOK" >/dev/null

echo -e "${C_GREEN}[+] All operations finished.${C_RESET}"
