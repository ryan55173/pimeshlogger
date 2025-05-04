# pimeshlogger

A python script or daemon for logging messages from a Meshtastic node

## Usage

<pre>
- -h, --help        ->    Show help
- -c, --channel     ->    Set channel for responses (int)
- -r, --respond     ->    Turn responses on/off
</pre>

## Requirements

- Python 3.7+
- Linux machine with the Meshtastic Python API running the *meshtasticd* daemon
#### pip installs (system interpreter)
- Meshtastic Python API (meshtastic)
- psutil, argparse

```
python3 -m pip install meshtastic psutil argparse
```

