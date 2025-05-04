#!/bin/python3
import os
# import sys
# import glob
import json
import time
# import fcntl
import psutil
import logging
import argparse
# import datetime
import meshtastic
import subprocess
from enum import Enum
from pubsub import pub
import meshtastic.tcp_interface
from logging.handlers import RotatingFileHandler


## enum for portnum in the packet object, list of special port numbers for meshtastic
class MeshPortNum(Enum):
    UNKNOWN_APP = 0
	# A simple UTF-8 text message, which even the little micros in the mesh
	# can understand and show on their screen eventually in some circumstances
	# even signal might send messages in this form (see below)
	# ENCODING: UTF-8 Plaintext (?)
    TEXT_MESSAGE_APP = 1
	# Reserved for built-in GPIO/example app.
	# See remote_hardware.proto/HardwareMessage for details on the message sent/received to this port number
	# ENCODING: Protobuf
    REMOTE_HARDWARE_APP = 2
	# The built-in position messaging app.
	# Payload is a Position message.
	# ENCODING: Protobuf
    POSITION_APP = 3
	# The built-in user info app.
	# Payload is a User message.
	# ENCODING: Protobuf
    NODEINFO_APP = 4
	# Protocol control packets for mesh protocol use.
	# Payload is a Routing message.
	# ENCODING: Protobuf
    ROUTING_APP = 5
	# Admin control packets.
	# Payload is a AdminMessage message.
	# ENCODING: Protobuf
    ADMIN_APP = 6
	# Compressed TEXT_MESSAGE payloads.
	# ENCODING: UTF-8 Plaintext (?) with Unishox2 Compression
	# NOTE: The Device Firmware converts a TEXT_MESSAGE_APP to TEXT_MESSAGE_COMPRESSED_APP if the compressed
	# payload is shorter. There's no need for app developers to do this themselves. Also the firmware will decompress
	# any incoming TEXT_MESSAGE_COMPRESSED_APP payload and convert to TEXT_MESSAGE_APP.
    TEXT_MESSAGE_COMPRESSED_APP = 7
	# Waypoint payloads.
	# Payload is a Waypoint message.
	# ENCODING: Protobuf
    WAYPOINT_APP = 8
	# Audio Payloads.
	# Encapsulated codec2 packets. On 2.4 GHZ Bandwidths only for now
	# ENCODING: codec2 audio frames
	# NOTE: audio frames contain a 3 byte header (0xc0 0xde 0xc2) and a one byte marker for the decompressed bitrate.
	# This marker comes from the 'moduleConfig.audio.bitrate' enum minus one.
    AUDIO_APP = 9
	# Same as Text Message but originating from Detection Sensor Module.
	# NOTE: This portnum traffic is not sent to the public MQTT starting at firmware version 2.2.9
    DETECTION_SENSOR_APP = 10
	# Provides a 'ping' service that replies to any packet it receives.
	# Also serves as a small example module.
	# ENCODING: ASCII Plaintext
    REPLY_APP = 32
	# Used for the python IP tunnel feature
	# ENCODING: IP Packet. Handled by the python API, firmware ignores this one and pases on.
    IP_TUNNEL_APP = 33
	# Paxcounter lib included in the firmware
	# ENCODING: protobuf
    PAXCOUNTER_APP = 34
	# Provides a hardware serial interface to send and receive from the Meshtastic network.
	# Connect to the RX/TX pins of a device with 38400 8N1. Packets received from the Meshtastic
	# network is forwarded to the RX pin while sending a packet to TX will go out to the Mesh network.
	# Maximum packet size of 240 bytes.
	# Module is disabled by default can be turned on by setting SERIAL_MODULE_ENABLED = 1 in SerialPlugh.cpp.
	# ENCODING: binary undefined
    SERIAL_APP = 64
	# STORE_FORWARD_APP (Work in Progress)
	# Maintained by Jm Casler (MC Hamster) : jm@casler.org
	# ENCODING: Protobuf
    STORE_FORWARD_APP = 65
	# Optional port for messages for the range test module.
	# ENCODING: ASCII Plaintext
	# NOTE: This portnum traffic is not sent to the public MQTT starting at firmware version 2.2.9
    RANGE_TEST_APP = 66
	# Provides a format to send and receive telemetry data from the Meshtastic network.
	# Maintained by Charles Crossan (crossan007) : crossan007@gmail.com
	# ENCODING: Protobuf
    TELEMETRY_APP = 67
	# Experimental tools for estimating node position without a GPS
	# Maintained by Github user a-f-G-U-C (a Meshtastic contributor)
	# Project files at https://github.com/a-f-G-U-C/Meshtastic-ZPS
	# ENCODING: arrays of int64 fields
    ZPS_APP = 68
	# Used to let multiple instances of Linux native applications communicate
	# as if they did using their LoRa chip.
	# Maintained by GitHub user GUVWAF.
	# Project files at https://github.com/GUVWAF/Meshtasticator
	# ENCODING: Protobuf (?)
    SIMULATOR_APP = 69
	# Provides a traceroute functionality to show the route a packet towards
	# a certain destination would take on the mesh. Contains a RouteDiscovery message as payload.
	# ENCODING: Protobuf
    TRACEROUTE_APP = 70
	# Aggregates edge info for the network by sending out a list of each node's neighbors
	# ENCODING: Protobuf
    NEIGHBORINFO_APP = 71
	# ATAK Plugin
	# Portnum for payloads from the official Meshtastic ATAK plugin
    ATAK_PLUGIN = 72
	# Provides unencrypted information about a node for consumption by a map via MQTT
    MAP_REPORT_APP = 73
	# PowerStress based monitoring support (for automated power consumption testing)
    POWERSTRESS_APP = 74
	# Private applications should use portnums >= 256.
	# To simplify initial development and testing you can use "PRIVATE_APP"
	# in your code without needing to rebuild protobuf files (via [regen-protos.sh](https://github.com/meshtastic/firmware/blob/master/bin/regen-protos.sh))
    PRIVATE_APP = 256
	# ATAK Forwarder Module https://github.com/paulmandal/atak-forwarder
	# ENCODING: libcotshrink
    ATAK_FORWARDER = 257
	# Currently we limit port nums to no higher than this value
    MAX = 511


## Create config
def get_pimeshlogger_config():
    ## Create default config if it does not exist
    default_config = {
        "channel": 0,
        "respond": True,
    }
    if not os.path.exists(config_path):    
        json_file = open(config_path, 'w')
        json.dump(default_config, json_file, indent=4)
        json_file.close()
        return default_config
    ## Read config file
    else:
        json_file = open(config_path, 'r')
        cfg = json.load(json_file)
        json_file.close()
        return cfg

## To see if meshtasticd.service is running
def is_meshtasticd_running():
    try:
        result = subprocess.run(['pgrep', '-f', 'meshtastic'], stdout=subprocess.DEVNULL)
        running = (result.returncode == 0)
        if running:
            p_logger.debug('Meshtastic daemon is running')
        else:
            p_logger.warning('Meshtastic daemon is NOT running')
        return result.returncode == 0
    except Exception as e:
        p_logger.error(f'Error checking process: {e}')
        return False

## See if this proces is running anywhere
def is_this_running():
    running = False
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            if proc.info['pid'] == current_pid:
                continue
            cmdline = ' '.join(proc.info.get('cmdline', []))
            if 'pimeshlogger' in cmdline:
                pid_str = str(proc.info['pid'])
                p_logger.warning(f'Clone process found - PID: {pid_str}')
                running = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return running

## Kill other instances of same process
def kill_clones():
    clones_killed = False
    current_pid = os.getpid()
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            if proc.info['pid'] == current_pid:
                continue
            cmdline = ' '.join(proc.info.get('cmdline', []))
            if 'pimeshlogger' in cmdline:
                p_logger.warning('Clone process found - ' + str(proc.info['pid']) + '\r\n\tKilling...')
                proc.kill()
                clones_killed = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return clones_killed

## Added as a callback for receiving a meshtastic packet
def on_receive(packet, interface):
    # Decode packet
    received_packet = str(packet)
    received_packet = received_packet.replace('\r', '')
    received_packet = received_packet.replace('\n', '')
    received_packet = received_packet.replace('\t', '')
    received_packet = received_packet.replace(' ', '')
    # Log formatted packet
    print(received_packet)
    mml = open(mesh_message_log, 'a')
    mml.write('\n' + received_packet)
    mml.close()

## Added as a callback for receiving a meshtastic packet
def on_receive_respond(packet, interface):
    # Decode packet
    received_packet = str(packet)
    received_packet = received_packet.replace('\r', '')
    received_packet = received_packet.replace('\n', '')
    received_packet = received_packet.replace('\t', '')
    received_packet = received_packet.replace(' ', '')
    # Log formatted packet
    print(received_packet)
    mml = open(mesh_message_log, 'a')
    mml.write('\n' + received_packet)
    mml.close()
    # Output info back
    if 'TEXT_MESSAGE' in packet['decoded']['portnum']:
        rxRssi = packet['rxRssi']
        from_node_id = packet['from']
        node = interface.nodes.get(from_node_id)
        if not node:
            node = from_node_id
        text_out = f'Message received from - {str(node)}\nRSSI: {str(rxRssi)}'
        interface.sendText(str(text_out), channelIndex=0)


######################
### Initialization ###
######################

## File initialization
if os.geteuid() == 0:    
    log_dir = '/var/log/pimeshlogger'
    config_path = '/usr/local/etc/pimeshlogger.json'
else:
    log_dir = os.path.expanduser('~') + os.path.sep + 'pimeshlogger'
    config_path = os.path.expanduser('~') + os.path.sep + 'pimeshlogger/pimeshlogger.json'
program_log = log_dir + '/pimeshlogger.log'
mesh_message_log = log_dir + '/mesh-messages.log'
if not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)

## Program logger initialization
p_logger = logging.getLogger('pimesh_logger')
p_logger.setLevel(logging.DEBUG)
p_formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(message)s', '%Y%m%d-%H:%M:%S')
p_file_handler = RotatingFileHandler(program_log, maxBytes=8_000_000, backupCount=2)
p_file_handler.setLevel(logging.DEBUG)
p_file_handler.setFormatter(p_formatter)
p_console_handler = logging.StreamHandler()
p_console_handler.setLevel(logging.DEBUG)
p_console_handler.setFormatter(p_formatter)
p_logger.addHandler(p_file_handler)
p_logger.addHandler(p_console_handler)

## Argument parser initialization
parser = argparse.ArgumentParser(prog='pimeshlogger')
parser.add_argument('-c', '--channel', type=int, help='Select channel to respond on')
parser.add_argument('-r', '--respond', action='store_true', help='Turn on/off responses')
parser.add_argument('--clear', type=str, help='Clearing logs ->  --clear: [option] -> Options:[all,logs,messages]')


############
### Main ###
############

def main_loop(config):
    if config['response'] in ['none', 'null', 'default']:
        pub.subscribe(on_receive, 'meshtastic.receive')
    else:
        pub.subscribe(on_receive_respond, 'meshtastic.receive')
    interface = meshtastic.tcp_interface.TCPInterface(hostname='127.0.0.1')
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        p_logger.debug('Exiting main_loop...')
    interface.close()
    p_logger.debug('Closed meshtastic interface')

if __name__ == '__main__':
    ## Get args and kill clones (other threads)
    args = parser.parse_args()
    config = get_pimeshlogger_config()
    kill_clones()

    ## args - Channel
    if args.channel != None:
        config['channel'] = args.channel
        p_logger.debug(f'Set channel to {str(args.channel)}')
    ## args - Respond true/false
    if args.respond:
        ## Toggle
        if config.respond:
            config.respond = False
            p_logger.debug('Respond toggled to false')
        else:
            config.respond = True
            p_logger.debug('Respond toggled to true')
    ## args - Clear files
    if args.clear != None:
        clear_lower = args.clear.lower()
        if clear_lower in ['*', 'all', 'log', 'logs', 'program_log', 'program_logs']:
            for file in os.listdir(log_dir):
                if 'pimeshlogger' in file:
                    os.remove(file)
        if clear_lower in ['*', 'all', 'message', 'messages', 'text', 'texts']:
            os.remove(log_dir + 'mesh-messages.log')

    ## Write new config and run
    json.dump(config, config_path, indent=4)
    
    if config.respond:
        # TODO: Build response message
        pass
    else:
        pass
    main_loop(config)

