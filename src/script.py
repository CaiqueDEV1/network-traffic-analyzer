import pyshark
from collections import Counter
import argparse


THRESHOLD = 10
WHITELIST_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443}
connection_count = Counter()


def analyzer_packet(pkt):
    try:
        if hasattr(pkt, 'ip'):
            protocol = pkt.transport_layer
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            
            src_port = pkt[protocol].srcport
            dst_port = pkt[protocol].dstport
            
            connection_count[(src_ip, dst_port)] += 1

            print(f"[{protocol}] Source IP:{src_ip} and port:{src_port} ---> Destination IP:{dst_ip} and port:{dst_port}")
    except AttributeError:
        pass
    
def main():
    parser = argparse.ArgumentParser(description="PCAPNG file processor")
    parser.add_argument("Archive", help="path for archive .pcapng")
    args = parser.parse_args()
    
    print(f"Processing archive: {args.Archive}")

    capture = pyshark.FileCapture(args.Archive)
    capture.apply_on_packets(analyzer_packet, timeout=120)

    for (src_ip, dst_port), count in connection_count.items():
        if int(dst_port) < 1024 and count > THRESHOLD and int(dst_port) not in WHITELIST_PORTS:
            print(f"[ALERT] IP {src_ip} sent {count} packets to port {dst_port}")
            
if __name__ == "__main__":
    main()