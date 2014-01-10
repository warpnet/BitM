Installation and Usage
============

1. perform default install of archlinux for ARM on a beaglebone [here](http://archlinuxarm.org/platforms/armv7/ti/beaglebone)
2. install dependencies with yaourt/pacman (or manually with the pkg files from AUR)
3. change necessary config files (pointers in the stealth block below)
4. make sure autosniff.py starts on startup

5. connect two usb ethernet dongles and reboot the device (you need two because the builtin ethernet won't support promiscuous mode)

6. perform physical ethernet cable beagle in the middle and wait for dhcp on the wireless AP

7. It's probably good if you bind a SSH server to the wlan0 interface (make sure it doesn't burn the device to the switch).


Deps
=====

python2
pycrypto
python2-pcapy
impacket
libpcap
bridge-utils
ebtables
iptables
arptables
hostapd

Stealth
========

```
[root@alarm ~]# cat /etc/sysctl.d/40-ipv6.conf 
# Disable IPv6

net.ipv6.conf.all.disable_ipv6 = 1
#net.ipv6.conf.interface0.disable_ipv6 = 1
#net.ipv6.conf.interfaceN.disable_ipv6 = 1
```

  rm /etc/netctl/eth0




hostapd.conf

```
interface=wlan0
driver=nl80211
ssid=Nothingtoseehere
hw_mode=g
channel=11
wpa=2
wpa_passphrase=hackallthethings
wpa_key_mgmt=WPA-PSK
wpa_ptk_rekey=600
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

License
=======

Just give me some credits if you build on this and keep it open source :)
