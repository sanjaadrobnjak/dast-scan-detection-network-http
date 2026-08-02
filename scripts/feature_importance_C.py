import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

RANDOM_STATE = 42

df = pd.read_csv('/home/sanja/hybrid_dataset.csv')
X = df.drop(columns=['label'])
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
)

rf = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
rf.fit(X_train, y_train)

importances = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)
print(importances.to_string())

NET_FEATURES = ['flow_duration', 'tot_pkts', 'pkt_len_mean', 'pkt_len_std',
                'pkt_len_min', 'pkt_len_max', 'pkt_len_var', 'flow_iat_mean',
                'flow_iat_std', 'flow_iat_min', 'flow_iat_max']
net_sum = importances[importances.index.isin(NET_FEATURES)].sum()
http_sum = importances[~importances.index.isin(NET_FEATURES)].sum()
print(f"\nUkupno mrezne karakteristike: {net_sum:.3f}")
print(f"Ukupno HTTP karakteristike: {http_sum:.3f}")

importances.to_csv('/home/sanja/feature_importance_C.csv', header=['importance'])
