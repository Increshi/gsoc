#!/usr/bin/env python3


import json
import argparse
import logging
import ipaddress
import p4runtime_sh.shell as p4sh
from p4.v1 import p4runtime_pb2 as p4rt

CFG_DIR = 'cfg'


BRIDGE_ID = 1


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Protocol mapping
PROTOCOLS = {6: "TCP", 17: "UDP"}


def ProcessInPacket():
    try:
        while True:
            rep = p4sh.client.get_stream_packet("packet", timeout=1)
            if rep is not None:
               
                metadata = rep.packet.metadata
                # Extract 5-tuple and result (adjust indices per your P4 program)
                src_ip = int.from_bytes(metadata[0].value, 'big')
                dst_ip = int.from_bytes(metadata[1].value, 'big')
                src_port = int.from_bytes(metadata[2].value, 'big')
                dst_port = int.from_bytes(metadata[3].value, 'big')
                protocol = int.from_bytes(metadata[4].value, 'big')
                result = int.from_bytes(metadata[5].value, 'big')  # Classification result

                # Print formatted output
                #logger.info("\n=== Flow Classification ===")
                #logger.info(f" <-5-Tuple: {ipaddress.IPv4Address(src_ip)}:{src_port} → " 
                #        f"{ipaddress.IPv4Address(dst_ip)}:{dst_port} {PROTOCOLS.get(protocol, 'UNKNOWN')}")
                #logger.info(f"<--- Classification Result: {result}--->")
                
                logger.info("\n=== Flow Classification ===")
                logger.info(f"5-Tuple: {ipaddress.IPv4Address(src_ip)}:{src_port} → " 
                              f"{ipaddress.IPv4Address(dst_ip)}:{dst_port}")
                logger.info(f"Protocol number: {protocol} ({hex(protocol)})")
                logger.info(f"Classification Result: {result}")
                

    except KeyboardInterrupt:
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Message Receiver Script')
    parser.add_argument('--grpc-port', help='GRPC Port', required=True,
                        type=str, action="store", default='50001')
    
    args = parser.parse_args()

    # Create a switch name postfixed with the grpc port number
    switch_name = 'decision_tree-{0}'.format(args.grpc_port)


    # Setup the P4Runtime connection with the bridge
    p4sh.setup(
        device_id=BRIDGE_ID, grpc_addr='127.0.0.1:{0}'.format(args.grpc_port), election_id=(0, 2),
        config=p4sh.FwdPipeConfig(
            '{0}/{1}-p4info.txt'.format(CFG_DIR, switch_name),  # Path to P4Info file
            '{0}/{1}.json'.format(CFG_DIR, switch_name)  # Path to config file
        )
    )


    print("Receiver connected to switch on port: {0}".format(args.grpc_port))
    print("Press CTRL+C to stop ...")

    try:
        ProcessInPacket()
    except KeyboardInterrupt:
        print("\n[!] Receiver Controller shutting down.")
        p4sh.teardown()

   
