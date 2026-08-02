import pandas as pd
import numpy as np

NETWORK_FEATURES = ['flow_duration', 'tot_pkts', 'pkt_len_mean', 'pkt_len_std',
                     'pkt_len_min', 'pkt_len_max', 'pkt_len_var', 'flow_iat_mean',
                     'flow_iat_std', 'flow_iat_min', 'flow_iat_max']

def align(network_csv, http_csv, label):
    net = pd.read_csv(network_csv)
    http = pd.read_csv(http_csv)
    http = http[http['label'] == label].copy()

    rows = []
    matched = 0
    unmatched = 0

    for _, hrow in http.iterrows():
        ip = hrow['src_ip']
        w_start = hrow['window_start_epoch']
        w_end = hrow['window_end_epoch']

        # network tokovi koji se preklapaju sa HTTP prozorom, iste IP adrese
        overlapping = net[
            (net['src_ip'] == ip) &
            (net['flow_start'] <= w_end) &
            (net['flow_end'] >= w_start)
        ]

        if len(overlapping) == 0:
            unmatched += 1
            continue

        matched += 1
        net_agg = overlapping[NETWORK_FEATURES].mean()

        row = net_agg.to_dict()
        for col in ['total_requests', 'ratio_404', 'ratio_200', 'ratio_302',
                    'ratio_500', 'unique_url_ratio', 'unique_agent_ratio',
                    'size_mean', 'size_std', 'reqtime_mean', 'reqtime_std']:
            row[col] = hrow[col]
        row['label'] = label
        rows.append(row)

    print(f"  {label}: {matched} uparenih, {unmatched} HTTP sesija bez odgovarajuceg toka")
    return rows

def main():
    malicious_rows = align('/home/sanja/all_malicious_flows.csv',
                            '/home/sanja/http_features_dataset.csv', 'malicious')
    benign_rows = align('/home/sanja/benign_traffic2_flows.csv',
                         '/home/sanja/http_features_dataset.csv', 'benign')

    all_rows = malicious_rows + benign_rows
    df = pd.DataFrame(all_rows)
    df.to_csv('/home/sanja/hybrid_dataset.csv', index=False)

    print(f"\nUkupno u hibridnom skupu: {len(df)}")
    print(df['label'].value_counts())

if __name__ == "__main__":
    main()
