import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

RANDOM_STATE = 42
N_SPLITS = 5

DATASETS = {
    'A_network_only': '/home/sanja/final_dataset.csv',
    'B_http_only': '/home/sanja/http_features_dataset.csv',
    'C_hybrid': '/home/sanja/hybrid_dataset.csv'
}

ID_COLS = ['src_ip', 'window_start_epoch', 'window_end_epoch']

def evaluate(y_true, y_pred):
    precision = precision_score(y_true, y_pred, pos_label='malicious', zero_division=0)
    recall = recall_score(y_true, y_pred, pos_label='malicious', zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label='malicious', zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=['benign', 'malicious'])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return precision, recall, f1, fpr

def cross_validate(name, df):
    print(f"\n=== Model {name} (StratifiedKFold, k={N_SPLITS}) ===")

    X = df.drop(columns=['label'] + [c for c in ID_COLS if c in df.columns])
    y = df['label'].values

    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)

    algos = {
        'RF': lambda: RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE),
        'KNN': lambda: KNeighborsClassifier(n_neighbors=5),
        'SVM': lambda: SVC(kernel='rbf', C=1, random_state=RANDOM_STATE)
    }

    results = []

    for algo_name, algo_fn in algos.items():
        fold_metrics = []
        for train_idx, test_idx in skf.split(X, y):
            X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
            y_train, y_test = y[train_idx], y[test_idx]

            if algo_name in ('KNN', 'SVM'):
                scaler = StandardScaler()
                X_train = scaler.fit_transform(X_train)
                X_test = scaler.transform(X_test)

            model = algo_fn()
            model.fit(X_train, y_train)
            y_pred = model.predict(X_test)
            fold_metrics.append(evaluate(y_test, y_pred))

        fold_metrics = np.array(fold_metrics)
        means = fold_metrics.mean(axis=0)
        stds = fold_metrics.std(axis=0)

        results.append([algo_name] + [f"{m:.3f} ± {s:.3f}" for m, s in zip(means, stds)])

    result_df = pd.DataFrame(results, columns=['Algoritam', 'Preciznost', 'Odziv', 'F1', 'FPR'])
    result_df.insert(0, 'Model', name)
    print(result_df.to_string(index=False))
    return result_df

def main():
    all_results = []
    for name, path in DATASETS.items():
        df = pd.read_csv(path)
        result_df = cross_validate(name, df)
        all_results.append(result_df)

    final = pd.concat(all_results, ignore_index=True)
    final.to_csv('/home/sanja/model_results_cv.csv', index=False)
    print("\n\n=== SVI REZULTATI (Cross-Validation) ===")
    print(final.to_string(index=False))
    print("\nSacuvano u /home/sanja/model_results_cv.csv")

if __name__ == "__main__":
    main()
