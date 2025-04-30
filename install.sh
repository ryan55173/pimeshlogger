#!/bin/bash

#######################################
## pimeshlogger installation script ###
#######################################

## File paths
script_working_dir="/usr/local/src"
script_path="$script_working_dir/pimeshlogger.py"
wrapper_path="/usr/local/bin/pymeshlogger"
log_dir="/var/log/pimeshlogger"
daemon_file_path="/etc/systemd/system/pimeshlogger.service"
program_log_path="$log_dir/pimeshlogger.log"
message_log_path="$og_dir/mesh-messages.log"

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

## Create wrapper
echo "// C wrapper for pimeshlogger" > "pimeshlogger.c"
echo "#include <stdio.h>" >> "pimeshlogger.c"
echo "#include <stdlib.h>" >> "pimeshlogger.c"
echo "#include <unistd.h>" >> "pimeshlogger.c"
echo "" >> "pimeshlogger.c"
echo "int main(int argc, char *argv[]) {" >> "pimeshlogger.c"
echo "    const char *python_path = \"/bin/python3\";" >> "pimeshlogger.c"
echo "    const char *script_path = \"$script_path\";" >> "pimeshlogger.c"
echo "" >> "pimeshlogger.c"
echo "    char *cmd[argc + 3];" >> "pimeshlogger.c"
echo "    cmd[0] = (char *)python_path;" >> "pimeshlogger.c"
echo "    cmd[1] = (char *)script_path;" >> "pimeshlogger.c"
echo "    for (int i = 1; i < argc; i++) {" >> "pimeshlogger.c"
echo "        cmd[i + 1] = argv[i];" >> "pimeshlogger.c"
echo "    }" >> "pimeshlogger.c"
echo "    cmd[argc + 1] = NULL;" >> "pimeshlogger.c"
echo "" >> "pimeshlogger.c"
echo "    execvp(python_path, cmd);" >> "pimeshlogger.c"
echo "    perror(\"execvp failed\");" >> "pimeshlogger.c"
echo "    return 1;" >> "pimeshlogger.c"
echo "}" >> "pimeshlogger.c"
echo "" >> "pimeshlogger.c"

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

## Reload daemon
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable pimeshlogger.service
systemctl start pimeshlogger.service

