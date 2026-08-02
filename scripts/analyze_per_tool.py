import re
import glob
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

RANDOM_STATE = 42
NET_FEATURES = ['flow_duration', 'tot_pkts', 'pkt_len_mean', 'pkt_len_std',
                'pkt_len_min', 'pkt_len_max', 'pkt_len_var', 'flow_iat_mean',
                'flow_iat_std', 'flow_iat_min', 'flow_iat_max']
HTTP_FEATURES = ['total_requests', 'ratio_404', 'ratio_200', 'ratio_302',
                  'ratio_500', 'unique_url_ratio', 'unique_agent_ratio',
                  'size_mean', 'size_std']

TOOL_APP_RE_NET = re.compile(r'^(nikto|zap|wapiti)_(webgoat|dvwa|mutillidae|gruyere)_flows\.csv$')
TOOL_APP_RE_HTTP = re.compile(r'^(nikto|zap|wapiti)_(webgoat|dvwa|mutillidae|gruyere)_http_flows\.csv$')

def load_tagged(pattern, regex):
    rows = []
    for f in glob.glob(pattern):
        m = regex.match(f.split('/')[-1])
        if not m:
            continue
        df = pd.read_csv(f)
        df['tool'] = m.group(1)
        df['app'] = m.group(2)
        rows.append(df)
    return pd.concat(rows, ignore_index=True)

def build_dataset_A():
    mal = load_tagged('/home/sanja/*_flows.csv', TOOL_APP_RE_NET)
    mal = mal[mal['tool'].isin(['nikto', 'zap', 'wapiti'])].copy()
    ben = pd.read_csv('/home/sanja/benign_mapped.csv')
    ben['tool'] = 'benign'
    ben['app'] = 'benign'
    df = pd.concat([mal[NET_FEATURES + ['label', 'tool', 'app']],
                     ben[NET_FEATURES + ['label', 'tool', 'app']]], ignore_index=True)
    return df, NET_FEATURES

def build_dataset_B():
    mal = load_tagged('/home/sanja/*_http_flows.csv', TOOL_APP_RE_HTTP)
    mal = mal[mal['tool'].isin(['nikto', 'zap', 'wapiti'])].copy()
    ben_files = glob.glob('/home/sanja/benign_*_http_flows.csv')
    ben_rows = []
    for f in ben_files:
        app = f.split('/')[-1].replace('benign_', '').replace('_http_flows.csv', '')
        d = pd.read_csv(f)
        d['tool'] = 'benign'
        d['app'] = app
        ben_rows.append(d)
    ben = pd.concat(ben_rows, ignore_index=True)
    df = pd.concat([mal[HTTP_FEATURES + ['label', 'tool', 'app']],
                     ben[HTTP_FEATURES + ['label', 'tool', 'app']]], ignore_index=True)
    return df, HTTP_FEATURES

def build_dataset_C():
    net_mal = load_tagged('/home/sanja/*_flows.csv', TOOL_APP_RE_NET)
    net_mal = net_mal[net_mal['tool'].isin(['nikto', 'zap', 'wapiti'])].copy()
    net_ben = pd.read_csv('/home/sanja/benign_traffic2_flows.csv')

    http_mal = load_tagged('/home/sanja/*_http_flows.csv', TOOL_APP_RE_HTTP)
    http_mal = http_mal[http_mal['tool'].isin(['nikto', 'zap', 'wapiti'])].copy()
    ben_files = glob.glob('/home/sanja/benign_*_http_flows.csv')
    http_ben_rows = []
    for f in ben_files:
        app = f.split('/')[-1].replace('benign_', '').replace('_http_flows.csv', '')
        d = pd.read_csv(f)
        d['tool'] = 'benign'
        d['app'] = app
        http_ben_rows.append(d)
    http_ben = pd.concat(http_ben_rows, ignore_index=True)

    def align(net_df, http_df):
        rows = []
        for _, hrow in http_df.iterrows():
            ip = hrow['src_ip']
            overlap = net_df[
                (net_df['src_ip'] == ip) &
                (net_df['flow_start'] <= hrow['window_end_epoch']) &
                (net_df['flow_end'] >= hrow['window_start_epoch'])
            ]
            if len(overlap) == 0:
                continue
            row = overlap[NET_FEATURES].mean().to_dict()
            for c in HTTP_FEATURES:
                row[c] = hrow[c]
            row['label'] = hrow['label']
            row['tool'] = hrow['tool']
            row['app'] = hrow['app']
            rows.append(row)
        return pd.DataFrame(rows)

    mal_hybrid = align(net_mal, http_mal)
    ben_hybrid = align(net_ben, http_ben)
    df = pd.concat([mal_hybrid, ben_hybrid], ignore_index=True)
    return df, NET_FEATURES + HTTP_FEATURES

def analyze(name, df, feature_cols):
    print(f"\n=== {name} ===")
    X = df[feature_cols]
    y = df['label']
    meta = df[['tool', 'app']]

    X_train, X_test, y_train, y_test, meta_train, meta_test = train_test_split(
        X, y, meta, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    rf = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)

    test_df = meta_test.copy()
    test_df['y_true'] = y_test.values
    test_df['y_pred'] = y_pred
    test_df['correct'] = test_df['y_true'] == test_df['y_pred']

    mal_test = test_df[test_df['y_true'] == 'malicious']
    grouped = mal_test.groupby(['tool', 'app']).agg(
        N=('correct', 'size'),
        recall=('correct', 'mean')
    ).reset_index()

    print(grouped.to_string(index=False))
    return name, grouped

def main():
    results = []
    for name, builder in [('A_network_only', build_dataset_A),
                            ('B_http_only', build_dataset_B),
                            ('C_hybrid', build_dataset_C)]:
        df, feats = builder()
        model_name, grouped = analyze(name, df, feats)
        grouped.insert(0, 'model', model_name)
        results.append(grouped)

    final = pd.concat(results, ignore_index=True)
    final.to_csv('/home/sanja/per_tool_recall.csv', index=False)
    print("\nSacuvano u /home/sanja/per_tool_recall.csv")

if __name__ == "__main__":
    main()
