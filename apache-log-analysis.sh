#!/bin/bash

log_file_path="${2}"

banner()
{
        echo ".................................."
        echo "      Apache Logs Analyzer        "
        echo ".................................."
	echo ""
	echo ">>Use: ./apache-log-analysis.sh [Option] [Log_File_Path]"
	echo ">>Ex: ./apache-log-analysis.sh 1 access.log"
	echo ""
	echo ">>Detection Options:"
	echo "1) Potential XSS (Cross-Site Scripting) Attacks: 1"
	echo "2) SQL Injection Attacks: 2"
	echo "3) Directory Traversal (Path Traversal): 3"
	echo "4) Suspicious User-agents: 4"
}

banner2()
{
	echo ""
	echo "................"
        echo ":    By Tai    :"
	echo "................"
}

# If the argument is empty, show the banner and out.
if [ -z "${1}" ]; then
	banner
	banner2
	exit
fi

# Case structure for the options.
case "${1}" in
    "1")
	# XSS attacks detection using URL Encoding (%3C)
        echo "Detecting potential XSS attacks ${log_file_path}..."
	grep -iE "<script|%3Cscript" "${log_file_path}"
        ;;
    "2")
        # SQL injection detection with URL Encoding (%22/%27) and SQL keywords to prevent false positives.
	echo "Detecting SQL Injection ${log_file_path}..."
	grep -iE "%22|%27" "${log_file_path}" | grep -iE "union|select|insert|drop|truncate"
	;;
    "3")
	# Directory Traversal also known as Path Traversal.
	echo "Detecting Directory Traversal ${log_file_path}..."
	grep -iE "\.\./|\.\.%2f|%2e%2e%2f|%2e%2e/" "${log_file_path}"
	;;
    "4")
	# Detects possible scanner attacks using default tools (Suspicious User-Agents).
	echo "Detecting Scanners Attacks ${log_file_path}..."
	grep -iE "nikto|nmap|sqlmap|acunetix|curl|masscan|python" "${log_file_path}"
	;;
    *)
	# Catch-all: Anything else that's not on the list.
	echo "Invalid option. Please choose between options 1 to 10."
	banner
	banner2
	exit
	;;
esac
