import re
import glob
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC

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

def build_dataset_B():
    mal = load_tagged('/home/sanja/*_http_flows.csv', TOOL_APP_RE_HTTP)
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

def analyze_all_algos(name, df, feature_cols):
    print(f"\n=== {name} ===")
    df = df.dropna(subset=feature_cols).reset_index(drop=True)

    X = df[feature_cols]
    y = df['label']
    meta = df[['tool', 'app']]

    X_train, X_test, y_train, y_test, meta_train, meta_test = train_test_split(
        X, y, meta, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    algos = {
        'RF': RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE),
        'KNN': KNeighborsClassifier(n_neighbors=5),
        'SVM': SVC(kernel='rbf', C=1, random_state=RANDOM_STATE)
    }

    all_results = []
    for algo_name, model in algos.items():
        if algo_name in ('KNN', 'SVM'):
            scaler = StandardScaler()
            X_train_use = scaler.fit_transform(X_train)
            X_test_use = scaler.transform(X_test)
        else:
            X_train_use, X_test_use = X_train, X_test

        model.fit(X_train_use, y_train)
        y_pred = model.predict(X_test_use)

        test_df = meta_test.copy()
        test_df['y_true'] = y_test.values
        test_df['y_pred'] = y_pred
        test_df['correct'] = test_df['y_true'] == test_df['y_pred']

        mal_test = test_df[test_df['y_true'] == 'malicious']
        grouped = mal_test.groupby(['tool', 'app']).agg(
            N=('correct', 'size'),
            recall=('correct', 'mean')
        ).reset_index()
        grouped.insert(0, 'algoritam', algo_name)
        all_results.append(grouped)

    result = pd.concat(all_results, ignore_index=True)
    print(result.to_string(index=False))
    return result

def main():
    df, feats = build_dataset_B()
    result = analyze_all_algos('B_http_only', df, feats)
    result.to_csv('/home/sanja/per_tool_recall_all_algos.csv', index=False)
    print("\nSacuvano u /home/sanja/per_tool_recall_all_algos.csv")

if __name__ == "__main__":
    main()
