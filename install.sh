#!/bin/bash

#######################################
## pimeshlogger installation script ###
#######################################

## File paths
log_dir="/var/log/pimeshlogger"
script_working_dir="/usr/local/src"
script_path="$script_working_dir/pimeshlogger.py"
config_file_path="/usr/local/etc/pimeshlogger.json"
daemon_file_path="/etc/systemd/system/pimeshlogger.service"
program_log_path="$log_dir/pimeshlogger.log"
message_log_path="$og_dir/mesh-messages.log"
wrapper_path="/usr/local/bin/pimeshlogger"

## Check if root
if [[ $EUID -ne 0 ]]; then
	echo "This script must be ran as root"
	exit 1
fi

## Create log directory
if [[ ! -d $log_dir ]]; then
	mkdir $log_dir
fi
touch $program_log_path
touch $message_log_path

## Create daemon file
echo "[Unit]" > $daemon_file_path
echo "Description=PiMeshLogger Meshtastic Logger Service" >> $daemon_file_path
echo "After=network.target" >> $daemon_file_path
echo "" >> $daemon_file_path
echo "[Service]" >> $daemon_file_path
echo "Type=simple" >> $daemon_file_path
echo "ExecStart=/bin/python3 $script_path" >> $daemon_file_path
echo "WorkingDirectory=$script_working_dir" >> $daemon_file_path
# echo "StandardOutput=null" >> $daemon_file_path
# echo "StandardError=null" >> $daemon_file_path
echo "Restart=always" >> $daemon_file_path
echo "User=$USER" >> $daemon_file_path
echo "Environment=PYTHONUNBUFFERED=1" >> $daemon_file_path
echo "" >> $daemon_file_path
echo "[Install]" >> $daemon_file_path
echo "WantedBy=multi-user.target" >> $daemon_file_path

## Compile wrapper
gcc -o $wrapper_path pimeshlogger.c
## Set ownership and permissions
chown root:root $wrapper_path
chmod 4755 $wrapper_path

## Copy and move files
cp pimeshlogger.py $script_path
cp pimeshlogger.json $config_file_path

## Reload daemon
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable pimeshlogger.service
systemctl start pimeshlogger.service

## Show finished
systemctl status pimeshlogger

