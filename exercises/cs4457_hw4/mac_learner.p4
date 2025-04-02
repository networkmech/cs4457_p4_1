/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

const bit<8> TYPE_ESP = 0x32;
const bit<8> TYPE_ICMP = 0x01;

#define MAX_FLOWS   1024


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

header esp_t {
    bit<32> spi;
    bit<32> sequenceNumber;
}

header innerip_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<8>  protocol;
}

header esptrail_t {
    bit<8>  pad;
    bit<8>  pad_length;
    bit<8>  nextHdr;
}

header icmp_esptrail_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
    bit<8>  pad;
    bit<8>  pad_length;
    bit<8>  nextHdr;
}


struct metadata {
    bit<32> outer_srcIP;
    bit<32> outer_dstIP;
    bit<8> is_going_to_internet;
    bit<8> is_middle_rtr;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    esp_t           espFrontHdr;
    innerip_t       innerIPHdr;
    esptrail_t     espTrailHdr;
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

    state parse_icmp_then_esp_trailer {
        packet.extract(hdr.icmp);
        packet.extract(hdr.espTrailHdr);
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


    action drop() {
        standard_metadata.egress_spec = 0;
    }

    action mark_and_forward(bit<8> mark_middle, bit<9> output_port) {
        meta.is_middle_rtr = mark_middle;
        standard_metadata.egress_spec = output_port;
    }

    action forward(bit<9> output_port, bit<8> is_going_to_internet) {
        standard_metadata.egress_spec = output_port;
        meta.is_going_to_internet = is_going_to_internet;
    }

    action set_meta_outer_srcIP(bit<32> outer_srcIP) {
        meta.outer_srcIP = outer_srcIP ;
    }

    action set_meta_outer_dstIP(bit<32> outer_dstIP) {
        meta.outer_dstIP = outer_dstIP ;
    }

    table srcIP_conversion_table {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            set_meta_outer_srcIP;
            NoAction;
        }
        size = MAX_FLOWS;
        default_action = NoAction;
    }

    table dstIP_conversion_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_meta_outer_dstIP;
            NoAction;
        }
        size = MAX_FLOWS;
        default_action = NoAction;
    }

    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            forward;
            NoAction;
        }
        size = MAX_FLOWS;
        default_action = forward(3,1);
    }

    table middle_rtr_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            mark_and_forward;
            NoAction;
        }
        size = MAX_FLOWS;
        default_action = NoAction;
    }

    apply {

        // if header ethernet and IPv4 exist and are valid,
        if (hdr.ethernet.isValid() && hdr.ipv4.isValid()) {




            if (hdr.ethernet.dstAddr == "ff:ff:ff:ff:ff:ff") {
                // broadcast
                standard_metadata.mcast_grp = 1;
            }

            else {
                // lookup register
                //
            }
                if {
                //look up register
                // forward
            }

            else {
                drop();
            }
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
    packet.emit(hdr.ipv4);

    // ESP headers will be attached 
    // automatically when set to valid
    packet.emit(hdr.espFrontHdr);
    packet.emit(hdr.innerIPHdr);
    packet.emit(hdr.icmp);
    packet.emit(hdr.espTrailHdr);
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
