import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

RANDOM_STATE = 42

DATASETS = {
    'A_network_only': '/home/sanja/final_dataset.csv',
    'B_http_only': '/home/sanja/http_features_dataset.csv',
    'C_hybrid': '/home/sanja/hybrid_dataset.csv'
}

def evaluate(y_true, y_pred):
    precision = precision_score(y_true, y_pred, pos_label='malicious', zero_division=0)
    recall = recall_score(y_true, y_pred, pos_label='malicious', zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label='malicious', zero_division=0)

    cm = confusion_matrix(y_true, y_pred, labels=['benign', 'malicious'])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return precision, recall, f1, fpr

def run_model(name, df):
    print(f"\n=== Model {name} ===")
    print(f"Ukupno uzoraka: {len(df)}, raspodela klasa:")
    print(df['label'].value_counts())

    id_cols = ['src_ip', 'window_start_epoch', 'window_end_epoch']
    X = df.drop(columns=['label'] + [c for c in id_cols if c in df.columns])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    results = []

    # RF 
    rf = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    precision, recall, f1, fpr = evaluate(y_test, y_pred)
    results.append(['RF', precision, recall, f1, fpr])

    # KNN 
    knn = KNeighborsClassifier(n_neighbors=5)
    knn.fit(X_train_scaled, y_train)
    y_pred = knn.predict(X_test_scaled)
    precision, recall, f1, fpr = evaluate(y_test, y_pred)
    results.append(['KNN', precision, recall, f1, fpr])

    # SVM 
    svm = SVC(kernel='rbf', C=1, random_state=RANDOM_STATE)
    svm.fit(X_train_scaled, y_train)
    y_pred = svm.predict(X_test_scaled)
    precision, recall, f1, fpr = evaluate(y_test, y_pred)
    results.append(['SVM', precision, recall, f1, fpr])

    result_df = pd.DataFrame(results, columns=['Algoritam', 'Preciznost', 'Odziv', 'F1', 'FPR'])
    result_df.insert(0, 'Model', name)
    print(result_df.to_string(index=False))
    return result_df

def main():
    all_results = []
    for name, path in DATASETS.items():
        df = pd.read_csv(path)
        result_df = run_model(name, df)
        all_results.append(result_df)

    final = pd.concat(all_results, ignore_index=True)
    final.to_csv('/home/sanja/model_results.csv', index=False)
    print("\n\n=== SVI REZULTATI ===")
    print(final.to_string(index=False))
    print("\nSacuvano u /home/sanja/model_results.csv")

if __name__ == "__main__":
    main()
