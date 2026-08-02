from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
import sys

def extract_flows(pcap_file, label):
    print(f"Ucitavam {pcap_file}...")
    packets = rdpcap(pcap_file)
    flows = defaultdict(list)
    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = 6 if TCP in pkt else 17
            sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
            dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            flow_key = (src, dst, sport, dport, proto)
            flows[flow_key].append({'time': float(pkt.time), 'size': len(pkt)})
    records = []
    for flow_key, pkts in flows.items():
        if len(pkts) < 2:
            continue
        src, dst, sport, dport, proto = flow_key
        times = [p['time'] for p in pkts]
        sizes = [p['size'] for p in pkts]
        iats = [times[i+1]-times[i] for i in range(len(times)-1)]
        record = {
            'src_ip': src, 'dst_ip': dst, 'src_port': sport,
            'dst_port': dport, 'protocol': proto,
            'flow_start': times[0], 'flow_end': times[-1],
            'flow_duration': times[-1]-times[0],
            'tot_pkts': len(pkts),
            'pkt_len_mean': np.mean(sizes), 'pkt_len_std': np.std(sizes),
            'pkt_len_min': np.min(sizes), 'pkt_len_max': np.max(sizes),
            'pkt_len_var': np.var(sizes),
            'flow_iat_mean': np.mean(iats) if iats else 0,
            'flow_iat_std': np.std(iats) if iats else 0,
            'flow_iat_min': np.min(iats) if iats else 0,
            'flow_iat_max': np.max(iats) if iats else 0,
            'label': label
        }
        records.append(record)
    return records

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Upotreba: python3 extract_flows.py <pcap> <label> <output>")
        sys.exit(1)
    records = extract_flows(sys.argv[1], sys.argv[2])
    df = pd.DataFrame(records)
    df.to_csv(sys.argv[3], index=False)
    print(f"Sacuvano {len(records)} tokova u {sys.argv[3]}")
