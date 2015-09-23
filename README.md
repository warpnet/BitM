# Beagle in the Middle

This is an improved version of the original Warpnet BitM script for transparent
NAC (802.1X) evasion at https://github.com/Warpnet/BitM.

It can be used on a beaglebone/raspberry pi/... or on any laptop with two ethernet interfaces.

## Dependencies

### Hardware
* Laptop or arm board with kali, debian, ubuntu, archlinux ...
* Two network interfaces - you can also use USB interfaces

### Software
* Libs and tools: libpcap, bridge-utils, ebtables, iptables, arptables, macchanger
* Python2 with argparse, pcapy
* Improved impacket from https://github.com/c0d3z3r0/impacket


* Install libs, tools and python2 using the packet manager (e.g. apt-get for debian/ubuntu)
* Python packages: `pip install argparse pcapy`
* Impacket

  ~~~
  git clone https://github.com/c0d3z3r0/impacket.git
  cd impacket
  python ./setup.py install
  ~~~

## Usage

### Basic Setup

#### ARM board
* Connect two USB interfaces to your device (you need two because the builtin ethernet maybe won't support promiscuous)
* Make sure autosniff.py runs as root on startup with ssh as a hidden service e.g. adding it to `/etc/rc.local`
* Put the device between the victim's and the switch's ethernet cables
* Reboot the ARM board

#### Laptop
* Connect two USB interfaces to your laptop or use one/two internal interface(s)
* Put the laptop between the victim's and the switch's ethernet cables
* Run autosniff.py as root and supply the two interface names

### Hidden Services

You can provide hidden services using the `-t` (tcp) and `-u` (udp) parameters
with the local port - the one your service runs on - and the remote port on which
you want to connect to your service from the outside using the victims ip as
destination ip.

Example:
* Start the SSH daemon on port 22
* Run autosniff.py -t 2222:22
* From outside run `ssh -p2222 root@<victims IP>`

### Reverse Shell

BitM supports a reverse connect shell. Use the `-h` parameter to set a host
and port the shell should connect to. If you want to prevent unauthorized access
you can set a password using `-p`. To set the sleep time between connects use
the `-s` parameter. The default is 30 seconds.

On your remote machine use netcat, ncat, socat or something else to listen
on the specified port. When the reverse shell connects to you you will get
a basic shell to e.g. set up an ssh tunnel or something else to get a full
featured bash shell.

## Caveats

* IPv6 (switch -6) has not been tested
* nmap uses raw sockets so NAT will NOT work for host discovery.
  For your own safety we block all outgoing ARP traffic with ebtables.
  You will need to provide the --send-ip parameter to get any results.
* netcat for connections from the attack machine doesn't work - use ncat (nmap) or socat