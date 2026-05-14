#!/bin/bash

log_file_path="${2}"

banner()
{
        echo ".................................."
        echo "         Análise de Logs          "
        echo ".................................."
	echo ""
	echo ">>Use: ./apache-log-analysis.sh [Option] [Log_File_Path]"
	echo ">>Ex: ./apache-log-analysis.sh 1 access.log"
	echo ""
	echo ">>Options:"
	echo "1)Detect potential XSS (Cross-Site Scripting) attacks: 1"
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
        echo "Detecting potential XSS attacks" "${log_file_path}" "..."
	grep -iE "<script|%3Cscript" "${log_file_path}"
esac
