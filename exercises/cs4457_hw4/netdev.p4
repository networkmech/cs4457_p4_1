/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;

const bit<8> TYPE_ICMP = 0x01;
const bit<8> TYPE_TCP = 0x06;

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
    bit<32> network_device_type;
    bit<8> dst_ip_is_local;
}

struct headers {
    ethernet_t      ethernet;
    arp_rarp_t      arp;
    ipv4_t          ipv4;
    icmp_t          icmp;
    tcp_t           tcp;
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
    // You need to add parser states for ARP, IPv4, TCP, and ICMP.
    //
    // Think about different packet types that 
    // could arrive at swtiches and routers. You have to parse them
    // correctly.
    //
    // HINT: TCP or ICMP comes after the IP header.
  
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }
    
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    // ##### YOUR CODE HERE 1 - END #####
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

    /* The MAC table for L2 switches */
    register<bit<9>>(MAC_TABLE_SIZE) mac_table;

    /* Action function to mark a packet for dropping */
    action drop() {
        standard_metadata.egress_spec = 0;
    }

    /* Action function to mark a network device.  
     *
     * Parameters:
     * - device_type: L2 (device_type = 2) or L3 (device_type = 3) 
     */
    action device_mark(bit<32> device_type) {
        meta.network_device_type = device_type;
    }

    /*
        Action function for forwarding IPv4 packets.

        This function is responsible for forwarding IPv4 packets to the specified
        destination MAC address and egress port.

        Parameters:
        - dstAddr: Destination MAC address of the packet.
        - port: Egress port where the packet should be forwarded.
    */
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<8> dst_ip_is_local) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // If 0, this packet's destination is for some other L3 network.
        // If 1, this packet's destination is the local network this L3 router is responsible for.
        meta.dst_ip_is_local = dst_ip_is_local;
    }

    /* 
     * Rewrite destination MAC to dstAddr 
     *
     * Parameters:
     * - dstAddr: Destination MAC you want.
     */
    action set_dmac(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = dstAddr;
    }

    /* IPv4 forwarding table based on destination IP address 
     *
     * You don't have to populate the entries. 
     * You have to apply this table somewhere.
     *
     */
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

    /* ARP cache table for L3 routers 
     *
     * You don't have to populate the entries. 
     * You have to apply this table somewhere.
     *
     */
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

    /* Table to indicate whether this network device is a L2 switch or L3 router 
     *
     * You don't have to populate the entries. 
     * You don't have to use this. It's already applied for you.
     *
     */ 
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
 
        // Output interface number you want to send this packet out.
        bit<9> output_port = 0;

        // Hash key index for finding a MAC table entry
        bit<32> lookup_key;

        // Hash key index for saving a MAC table entry
        bit<32> save_key;

        // Apply the table to know if the packet entered
        // a L2 switch or L3 router
        l2_or_l3_table.apply();

        /* This router, which the packet entered, is an L2 switch */ 
        if (meta.network_device_type == L2_TYPE && hdr.ethernet.isValid()) {

            // Hash source MAC address and save to save_key 
            hash(save_key, HashAlgorithm.crc32, (bit<32>)0, {hdr.ethernet.srcAddr}, (bit<32>)MAC_TABLE_SIZE);

            // Hash destination MAC address and save to lookup_key
            hash(lookup_key, HashAlgorithm.crc32, (bit<32>)0, {hdr.ethernet.dstAddr}, (bit<32>)MAC_TABLE_SIZE);

            /* ##### YOUR CODE HERE 2 - START #####
             * 
             * HINT: Think about what an L2 switch should do when it gets a packet. 
             *
             * A packet might be an ARP or ping (ICMP) packet.
             * 
             * Setting "standard_metadata.mcast_grp = 1" will make a packet broadcast.
             *
             */
    
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

            /* ##### YOUR CODE HERE 2 - END ##### */
        }

        /* This router, which the packet entered, is an L3 router */ 
        else if (meta.network_device_type == L3_TYPE && hdr.ethernet.isValid() && hdr.ipv4.isValid()) {

            /* ##### YOUR CODE HERE 3 - START ##### 
             *
             * HINT: Think about what an L3 router should do when it gets a packet. 
             *
             */

            dst_ipv4_lpm.apply();

            // if destination IP is for local subnet, lookup ARP cache
            if (meta.dst_ip_is_local == 1) {        
                arp_cache_table.apply();
            }

            /* ##### YOUR CODE HERE 3 - END ##### */
        }

        /* This router, which the packet entered, is not known.*/ 
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
    apply {}
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
