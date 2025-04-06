// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define KEY_SIZE 32
#define NUM_REGISTERS 1024
#define CPU_PORT 255
const bit<16> TYPE_IPV4 = 0x800;


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
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

@controller_header("packet_in")
header packet_in_header_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  protocol;
    bit<8>  result;

    
}



struct metadata {
    bit<32> pkt_count;
    bit<32> byte_count;
    bit<32> avg_pkt_size;
    bit<32> duration;
    bit<32> avg_iat;
    bit<32> cur_iat_sum;
    bit<32> last_timestamp;
    bit<32> src_addr;
    bit<32> dst_addr;
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> pkt_index;
    bit<8>  result;
}






struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    packet_in_header_t packet_in ;
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

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
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

    
    
    // Sample register definition
    register<bit<32>>(NUM_REGISTERS) pkt_count_reg;
    // TODO: Populate the other registers here
    register<bit<32>>(NUM_REGISTERS) byte_count_reg;
    register<bit<32>>(NUM_REGISTERS) avg_pkt_length_reg;
    register<bit<32>>(NUM_REGISTERS) duration_reg;
    register<bit<32>>(NUM_REGISTERS) sum_iat_reg;
    register<bit<32>>(NUM_REGISTERS) last_time_reg;
    register<bit<32>>(NUM_REGISTERS) avg_iat_reg;
    register<bit<32>>(NUM_REGISTERS) first_time_reg;
    
    

    action write_result(bit<8> result) {
        meta.result = result;
    }
  
         
    action send_digest() {
    
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.srcAddr=hdr.ipv4.srcAddr;
        hdr.packet_in.dstAddr=hdr.ipv4.dstAddr;
        hdr.packet_in.srcPort=hdr.tcp.srcPort;
        hdr.packet_in.dstPort=hdr.tcp.dstPort;
        hdr.packet_in.protocol=hdr.ipv4.protocol;
        hdr.packet_in.result=meta.result;
        
       
    } 
    
    

    table classifier {
        key = {
            meta.pkt_count: exact;
            meta.byte_count: exact;
            meta.avg_pkt_size: exact;
            meta.duration: exact;
            meta.avg_iat: exact;
            hdr.tcp.flags: exact;
        }
        actions = {
            write_result;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    

    apply {
        

        // TODO: Implement the rest of the register operations here
        hash(meta.pkt_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                                          hdr.ipv4.dstAddr,
                                                          hdr.tcp.srcPort,
                                                          hdr.tcp.dstPort,
                                                          hdr.ipv4.protocol},
                                                          (bit<32>)NUM_REGISTERS);
                                                        
        bit<32> cur_pkt_count;
        bit<32> cur_byte_count;
        bit<32> last_time;
        bit<32> cur_iat_sum;
        bit<32> first_time;
        bit<8> shift_amount = 0;
        
                                                          
                                                  
        // Read values from all registers
        pkt_count_reg.read(cur_pkt_count, meta.pkt_index);
        byte_count_reg.read(cur_byte_count,meta.pkt_index);
        last_time_reg.read(last_time,meta.pkt_index);
        sum_iat_reg.read(cur_iat_sum,meta.pkt_index);
        first_time_reg.read(first_time, meta.pkt_index);
        
        //Updating register values of specific flow packet belongs
        cur_pkt_count=cur_pkt_count+1;
        meta.pkt_count=cur_pkt_count;
        meta.byte_count=cur_byte_count+(bit<32>)standard_metadata.packet_length;
        if (meta.pkt_count >= 16) {
           shift_amount = 4;  
        } else if (meta.pkt_count >= 8) {
           shift_amount = 3;  
        } else if (meta.pkt_count >= 4) {
           shift_amount = 2;  
        } else if (meta.pkt_count >= 2) {
           shift_amount = 1;  
        }
  
        
        if (meta.pkt_count != 0) {
           meta.avg_pkt_size = (shift_amount > 0) ?(meta.byte_count >> shift_amount) : meta.byte_count;
           
        } else {
           meta.avg_pkt_size= 0;
        }
        

       
        if (meta.pkt_count <= 1) {
            first_time_reg.write(meta.pkt_index, (bit<32>)standard_metadata.ingress_global_timestamp);
            meta.duration = 0;
            meta.cur_iat_sum=0;
            meta.avg_iat=0;
        } else {
            meta.duration = (bit<32>) standard_metadata.ingress_global_timestamp - first_time;
            bit<32> current_time = (bit<32>)standard_metadata.ingress_global_timestamp;
            bit<32> iat = current_time - last_time;
            cur_iat_sum = cur_iat_sum + iat;
            meta.cur_iat_sum = cur_iat_sum; 
            //meta.avg_iat= meta.cur_iat_sum* (bit<32>)(1/(cur_pkt_count-1));
            meta.avg_iat= (shift_amount > 0) ?(meta.cur_iat_sum >> shift_amount) : meta.cur_iat_sum ;
        }
        
    
         // Write back
        duration_reg.write(meta.pkt_index, meta.duration);
        sum_iat_reg.write(meta.pkt_index, meta.cur_iat_sum);
        avg_iat_reg.write(meta.pkt_index,meta.avg_iat);
        pkt_count_reg.write(meta.pkt_index, meta.pkt_count);
        byte_count_reg.write(meta.pkt_index, meta.byte_count);
        avg_pkt_length_reg.write(meta.pkt_index,meta.avg_pkt_size);
        
        // Update last timestamp
        last_time_reg.write(meta.pkt_index, (bit<32>)standard_metadata.ingress_global_timestamp);
        meta.last_timestamp = (bit<32>)standard_metadata.ingress_global_timestamp;
        
        // Apply the classifier
        classifier.apply();
        
        
        //Apply Digest Trigger
        if(hdr.tcp.isValid()){
          if((hdr.tcp.flags & 0x01) != 0){
             send_digest();
          }
        }
          
      
        
    }
}

/********************************
*****************************************
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

