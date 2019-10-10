#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, ShortField, IntField
from scapy.all import bind_layers

class ECMP(Packet):
    name = "ECMP"
    fields_desc = [ 
                    ShortField("enable", 0),
                    ShortField("prot_id", 0)
                ]
bind_layers(Ether, ECMP, type=0x0888)
bind_layers(ECMP, IP, prot_id=0x0800)


class STATS(Packet):
    name = "STATS"
    fields_desc = [ 
                    IntField("port2", 0),
                    IntField("port3", 0),
                    ShortField("enable",0),
                    ShortField("prot_id", 0)
                ]
bind_layers(Ether, STATS, type=0x0999)
bind_layers(STATS, IP, prot_id=0x0800)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination> "<message>" for communicatin'
        print 'pass 1 argument: <destination> for packet statistics'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    if len(sys.argv)==3:
        for i in range(1000)
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt / ECMP(enable=1) /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
            pkt.show2()
            sendp(pkt, iface=iface, verbose=False)
    if len(sys.argv)==2:
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / STATS(enable=1) /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / 'stats'
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
    


if __name__ == '__main__':
    main()
