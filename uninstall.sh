#!/bin/bash

####################################
## pimeshlogger uninstall script ###
####################################

## File paths
log_dir="/var/log/pimeshlogger"
python_file="/usr/local/src/pimeshlogger.py"
wrapper_file="/usr/local/bin/pimeshlogger"
daemon_file_path="/etc/systemd/system/pimeshlogger.service"

## Check if root
if [[ $EUID -ne 0 ]]; then
	echo "This script must be ran as root"
	exit 1
fi

## Stop service
systemctl stop pimeshlogger
systemctl disable pimeshlogger

## Kill process
pkill "pimeshlogger"

## Remove files
rm -f $daemon_file_path
rm -f $wrapper_file
rm -f $python_file
rm -rf $log_dir

