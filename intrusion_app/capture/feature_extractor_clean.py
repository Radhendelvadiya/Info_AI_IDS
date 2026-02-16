from scapy.layers.inet import TCP, UDP

def extract_features(packet):
    return {
        "packet_size": len(packet),
        "protocol": 1 if packet.haslayer(TCP) else 2 if packet.haslayer(UDP) else 0,
        "src_port": packet.sport if hasattr(packet, "sport") else 0,
        "dst_port": packet.dport if hasattr(packet, "dport") else 0
    }
