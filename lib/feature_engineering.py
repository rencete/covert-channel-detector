import scapy.all as scapy


def extract_feature(pkt: scapy.Packet):
    features = {
        # General Packet Features
        "pkt_wirelen": 0,
        "pkt_cntlyrs": 0,
        # IP Layer (Layer 3) Features
        "has_ip_layer": 0,
        "ip_ver": 0,
        "ip_ihl": 0,
        "ip_serv": 0,
        "ip_len": 0,
        "ip_id": 0,
        "ip_flags1": 0,
        "ip_flags2": 0,
        "ip_frago": 0,
        "ip_ttl": 0,
        "ip_proto": 0,
        # TCP Layer (Layer 4) Features
        "has_tcp_layer": 0,
        "tcp_seqnum": 0,
        "tcp_acknum": 0,
        "tcp_headlen": 0,
        "tcp_urgflag": 0,
        "tcp_ackflag": 0,
        "tcp_pshflag": 0,
        "tcp_rstflag": 0,
        "tcp_synflag": 0,
        "tcp_finflag": 0,
        "tcp_winsize": 0,
        "tcp_urgpntr": 0,
        # ICMP Layer Features
        "has_icmp_layer": 0,
        "icmp_type": 0,
        "icmp_code": 0,
    }

    # Populate Layer 1 features
    features["pkt_wirelen"] = len(pkt)
    features["pkt_cntlyrs"] = len(pkt.layers())

    # Populate IP Layer (Layer 3) features
    if pkt.haslayer(scapy.IP):
        ip_layer: scapy.IP = pkt.getlayer(scapy.IP)
        features["has_ip_layer"] = 1
        features["ip_ver"] = ip_layer.version
        features["ip_ihl"] = ip_layer.ihl
        features["ip_serv"] = ip_layer.tos
        features["ip_len"] = ip_layer.len
        features["ip_id"] = ip_layer.id
        features["ip_flags1"] = 1 if ip_layer.flags.DF else 0
        features["ip_flags2"] = 1 if ip_layer.flags.MF else 0
        features["ip_frago"] = ip_layer.frag
        features["ip_ttl"] = ip_layer.ttl
        features["ip_proto"] = ip_layer.proto

    # Populate TCP Layer (Layer 4)
    if pkt.haslayer(scapy.TCP):
        tcp_layer: scapy.TCP = pkt.getlayer(scapy.TCP)
        features["has_tcp_layer"] = 1
        features["tcp_seqnum"] = tcp_layer.seq
        features["tcp_acknum"] = tcp_layer.ack
        features["tcp_headlen"] = tcp_layer.dataofs
        features["tcp_urgflag"] = 1 if tcp_layer.flags.U else 0
        features["tcp_ackflag"] = 1 if tcp_layer.flags.A else 0
        features["tcp_pshflag"] = 1 if tcp_layer.flags.P else 0
        features["tcp_rstflag"] = 1 if tcp_layer.flags.R else 0
        features["tcp_synflag"] = 1 if tcp_layer.flags.S else 0
        features["tcp_finflag"] = 1 if tcp_layer.flags.F else 0
        features["tcp_winsize"] = tcp_layer.window
        features["tcp_urgpntr"] = tcp_layer.urgptr

    # Populate ICMP Layer Features
    if pkt.haslayer(scapy.ICMP):
        icmp_layer: scapy.ICMP = pkt.getlayer(scapy.ICMP)
        features["has_icmp_layer"] = 1
        features["icmp_type"] = icmp_layer.type
        features["icmp_code"] = icmp_layer.code

    return features