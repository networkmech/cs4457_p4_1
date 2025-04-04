/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;

const bit<8> TYPE_ICMP = 0x01;

#define MAC_TABLE_SIZE  1024
#define L2_TYPE         2
#define L3_TYPE         3


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header arp_rarp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
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

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

struct metadata {
    bit<32> network_device_type;
    bit<8> src_ip_is_local;
    bit<8> dst_ip_is_local;
}

struct headers {
    ethernet_t      ethernet;
    arp_rarp_t       arp;
    ipv4_t          ipv4;
    icmp_t          icmp;
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
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    // ##### YOUR CODE HERE 1 - START #####

    // HINT: 
    // You need to make some updates to the parse_ipv4 parser state,
    // and also add another parser state.
    // 
    // Think about different packet types that 
    // would arrive at the routers. You have to parse them
    // correctly.
    //
    // In general, for this whole homework,
    // the MRI tutorial example will be a good reference to check.
    // This is because the MRI example also deals with custom headers.
    // Check at: p4tutorials/exercises/mri/solution/mri.p4
    // Reading through the MRI example online should help too:
    // https://github.com/networkmech/p4tutorials/tree/master/exercises/mri
  
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    // HINT: 
    // Normally, we should look up the IP protocol type (e.g., ICMP),
    // which is saved in the ESP trailer header's nextHdr field. Only after knowing that,
    // the parser can parse the transport layer fields correctly (e.g., ICMP header). 
    //
    // But for the sake of this homework, it is fine to check the
    // value in hdr.innerIPHdr.protocol.

    // ##### YOUR CODE HERE 1 - END #####
    
    state parse_icmp {
        packet.extract(hdr.icmp);
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

    register<bit<9>>(MAC_TABLE_SIZE) mac_table;
    register<bit<48>>(1024) arp_cache;

    action drop() {
        standard_metadata.egress_spec = 0;
    }

    action device_mark(bit<32> device_type) {
        meta.network_device_type = device_type;
    }

    action mark_src_local() {
        meta.src_ip_is_local = 1;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<8> dst_ip_is_local) {
        /*
            Action function for forwarding IPv4 packets.

            This function is responsible for forwarding IPv4 packets to the specified
            destination MAC address and egress port.

            Parameters:
            - dstAddr: Destination MAC address of the packet.
            - port: Egress port where the packet should be forwarded.

            TODO: Implement the logic for forwarding the IPv4 packet based on the
            destination MAC address and egress port.
        */

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        meta.dst_ip_is_local = dst_ip_is_local;
    }

    action set_dmac(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = dstAddr;
    }

    table src_ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            mark_src_local;
            drop;
        }
        size = 1024;
        default_action = drop();
    }


    table dst_ipv4_lpm {
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


    table arp_cache_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_dmac;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    table l2_or_l3_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            device_mark;
            NoAction;
        }
        size = 10;
        default_action = NoAction();
    }

    apply {
 
        bit<9> output_port = 0;
        bit<32> lookup_key;
        bit<32> save_key;

        l2_or_l3_table.apply();

        // if L2 router
        if (meta.network_device_type == L2_TYPE && hdr.ethernet.isValid()) {
            hash(lookup_key, HashAlgorithm.crc32, (bit<32>)0, {hdr.ethernet.dstAddr}, (bit<32>)MAC_TABLE_SIZE);
            hash(save_key, HashAlgorithm.crc32, (bit<32>)0, {hdr.ethernet.srcAddr}, (bit<32>)MAC_TABLE_SIZE);
    
            // save to mac table.
            mac_table.write(save_key, standard_metadata.ingress_port);

            // if broadcast, broadcast.
            if (hdr.ethernet.dstAddr == 0xffffffffffff) {
                standard_metadata.mcast_grp = 1;
            }
            else {
                // lookup register
                mac_table.read(output_port, lookup_key);
    
                // if found, set egress port based on retrieved info.
                if (output_port > 0) {
                    standard_metadata.egress_spec = output_port;
                }
                // if not found in mac_table, flood
                else {
                    standard_metadata.mcast_grp = 1;
                }
            }
        }

        // else if, L3 router
        else if (meta.network_device_type == L3_TYPE && hdr.ethernet.isValid() && hdr.ipv4.isValid()) {

            src_ipv4_lpm.apply();

//            if (meta.src_ip_is_local == 1) {
////                bit<32> save_ip_key;
//                //hash(save_ip_key, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.srcAddr}, (bit<32>)1024);
//                //arp_cache.write(save_ip_key, hdr.ethernet.srcAddr);
//                arp_cache.write(hdr.ipv4.srcAddr, hdr.ethernet.srcAddr);
//            }
//
////            hash(save_ip_key, HashAlgorithm.crc32, (bit<32>)0, {hdr.ethernet.srcAddr}, (bit<32>)1024);
////            arp_cache.write(save_ip_key, hdr.ethernet.srcAddr);

            dst_ipv4_lpm.apply();

            // if destination IP is for local subnet, lookup ARP cache
            if (meta.dst_ip_is_local == 1) {        
                bit<48> MacDstAddr;
                arp_cache_table.apply();
                //hash(lookup_ip_key, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.dstAddr}, (bit<32>)1024);
                //arp_cache.read(MacDstAddr, (bit<32>)hdr.ipv4.dstAddr);
                //arp_cache.read(MacDstAddr, lookup_ip_key);
                //hdr.ethernet.dstAddr = MacDstAddr;
            }
        }

        // else, drop packet.
        else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
    packet.emit(hdr.arp);
    packet.emit(hdr.ipv4);
    packet.emit(hdr.icmp);
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
