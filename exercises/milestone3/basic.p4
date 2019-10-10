/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_FLOWLET = 0x888;
const bit<16> TYPE_STATS = 0x999;
const bit<32> HASH_COUNT = 100;
const bit<48> TIME_INTERVAL = 1000;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header flowlet_t {
    bit<16> enable;
    bit<16> prot_id;
    bit<32> pkt_num;
}

header stats_t {
    bit<32> port2; 
    bit<32> port3;
    bit<16> enable; 
    bit<16> prot_id;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    bit<14> route;
}

struct headers {
    ethernet_t  ethernet;
    flowlet_t  flowlet;
    stats_t stats;
    ipv4_t  ipv4;
    tcp_t   tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_FLOWLET: parse_flowlet;
            TYPE_STATS: parse_stats;
            default: accept;
        }
    }

    state parse_flowlet {
        packet.extract(hdr.flowlet);
        transition select(hdr.flowlet.prot_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_stats{
        packet.extract(hdr.stats);
        transition select(hdr.stats.prot_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(1) packet_counter; 
    register<bit<16>>(100) reg_flow_ports;
    register<bit<48>>(100) reg_flow_times;

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table route_exact {
        key = {
            meta.route: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action load_balance() {
        // flowlet load balance
        bit<32> pkt_cnt;
        packet_counter.read(pkt_cnt, (bit<32>)0);
        pkt_cnt = pkt_cnt+1;
        packet_counter.write((bit<32>)0, pkt_cnt);
        hdr.flowlet.pkt_num = pkt_cnt;

        bit<14> hashVal ; 

        hash(hashVal, HashAlgorithm.crc16, (bit<16>)0,
	        {   hdr.ipv4.srcAddr,
	            hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort     }, HASH_COUNT);
        bit<16> port ;
        bit<48> time ;
        reg_flow_times.read(time, (bit<32>)hashVal);
        reg_flow_ports.read(port, (bit<32>)hashVal);
        if(standard_metadata.ingress_global_timestamp - time > TIME_INTERVAL){
            // time interval of two packet within the same flow is larger than 1000, the packet should use another port
            if(port==(bit<16>)2){
                port = (bit<16>)3;
                meta.route = 1 ;
            }else{
                port = (bit<16>)2;
                meta.route = 0 ;
            }
            reg_flow_ports.write((bit<32>)hashVal, port);
        }
        reg_flow_times.write((bit<32>)hashVal, standard_metadata.ingress_global_timestamp);
    }
    
    apply {
        if (hdr.flowlet.isValid()) {
            // process flowlet load balance
            if(hdr.flowlet.enable==1){
                bit<32> pkt_cnt;
                packet_counter.read(pkt_cnt, (bit<32>)0);
                pkt_cnt = pkt_cnt+1;
                packet_counter.write((bit<32>)0, pkt_cnt);
                hdr.flowlet.pkt_num = pkt_cnt;

                bit<14> hashVal ; 

                hash(hashVal, HashAlgorithm.crc16, (bit<16>)0,
	                {   hdr.ipv4.srcAddr,
	                    hdr.ipv4.dstAddr,
                        hdr.ipv4.protocol,
                        hdr.tcp.srcPort,
                        hdr.tcp.dstPort     }, HASH_COUNT);
                bit<16> port ;
                bit<48> time ;
                reg_flow_times.read(time, (bit<32>)hashVal);
                reg_flow_ports.read(port, (bit<32>)hashVal);
                if(standard_metadata.ingress_global_timestamp - time > TIME_INTERVAL){
                    // time interval of two packet within the same flow is larger than 1000, the packet should use another port
                    if(port==(bit<16>)2){
                        port = (bit<16>)3;
                        meta.route = 1 ;
                    }else{
                        port = (bit<16>)2;
                        meta.route = 0 ;
                    }
                    reg_flow_ports.write((bit<32>)hashVal, port);
                }
                reg_flow_times.write((bit<32>)hashVal, standard_metadata.ingress_global_timestamp);

                route_exact.apply();
                hdr.flowlet.enable=0;
            }else{
                ipv4_lpm.apply();
            }
        }else if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    register<bit<32>>(4) byte_cnt_reg;
    
    apply{
        if(!hdr.stats.isValid()){
            // if this packet is not query packet, we count the bytes forwarded
            bit<32> byte_cnt;
            byte_cnt_reg.read(byte_cnt, (bit<32>)standard_metadata.egress_port);
            byte_cnt = byte_cnt + standard_metadata.packet_length;
            byte_cnt_reg.write((bit<32>)standard_metadata.egress_port, byte_cnt);
        }else if(hdr.stats.enable==1){
            // this packet is a query packet and statistics is enabled, we read the count of bytes previously forwarded
            byte_cnt_reg.read(hdr.stats.port2, (bit<32>)2);
            byte_cnt_reg.read(hdr.stats.port3, (bit<32>)3);
            hdr.stats.enable = 0;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.flowlet);
        packet.emit(hdr.stats);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
