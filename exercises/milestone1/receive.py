#!/usr/bin/env python
import sys
import struct
import os
import collections

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from send import ECMP, STATS

flowMap = collections.defaultdict(list)
outOfOrderMap = collections.defaultdict(int)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if (STATS in pkt) or (ECMP in pkt) or (TCP in pkt and pkt[TCP].dport == 1234):
        print "got a packet"
        if ECMP in pkt:
            cur_pkt_num = pkt[ECMP].pkt_num
            flow = flowMap[pkt[TCP].sport]
            if(cur_pkt_num < flow[-1]):
                outOfOrderMap[pkt[TCP].sport] += 1 
            flowMap[pkt[TCP].sport].append(pkt[ECMP].pkt_num)
        pkt.show2()
        for key in outOfOrderMap.keys():
            print "flow %s has %s packet in wrong order" % (key, outOfOrderMap[key])
        sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
