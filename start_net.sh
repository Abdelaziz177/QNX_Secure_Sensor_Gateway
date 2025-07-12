#!/bin/sh

if_up -p -r 20 vtnet0
ifconfig vtnet0 up
sysctl -w net.inet.icmp.bmcastecho=1 > /dev/null
sysctl -w qnx.sec.droproot=33:33 > /dev/null
# io-usb-otg -d hcd-uhci -d hcd-ehci -d hcd-xhci  ///Hardware specific only if running on PI
#Load USB Ethernet Driver
# devnp-usb  ///Hardware specific only if running on PI
#Start TCP/IP Stack
# io-pkt-v6-hc -d e1000 -ptcpip ///no need for this driver to start TCP/IP Stack as interface vtnet0 is loaded in the previous lines and it contains io-pkt driver(network stack (networking resource manager))
#Assign an IP Address
ifconfig vtnet0 192.168.56.101 netmask 255.255.255.0 up

exit 0
