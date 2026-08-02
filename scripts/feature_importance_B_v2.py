import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

RANDOM_STATE = 42
ID_COLS = ['src_ip', 'window_start_epoch', 'window_end_epoch']

df = pd.read_csv('/home/sanja/http_features_dataset.csv')
X = df.drop(columns=['label'] + [c for c in ID_COLS if c in df.columns])
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
)

rf = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
rf.fit(X_train, y_train)

importances = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False)
print(importances.to_string())
