# bigswitch-tools

### Prerequisites

Requires python3 >= 3.4.0

Check version: `python3 -V`

Requires pip or some way to install python modules:

Uses these additional python modules:

- pygments
- tabulate
- argparse


Clone this to your machine and install modules

```
git clone https://github.com/sboutang/bigswitch-tools.git

pip3 install pygments --user
pip3 install tabulate --user
pip3 install argparse --user

export BSNUSER=<username>
export BSNPASS=<password>
# or add these to your shell rc file
```

bsn-ig-error.py: gather interface-group error stats for a supplied interface-group

bsn-ig-info.py: gather switch/port status and vlan membership for a supplied interface-group

bsn-vlan-info.py: gather tenant, segment, and interface-group membership for a supplied vlan ID

bsnapi.py: handles the login and allows you to do a one off API call to see the output


