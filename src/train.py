# src/train.py
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
import joblib
from features import extract_features

DATA_PATH = "data/synthetic_urls.csv"
MODEL_OUT = "models/phish_model.joblib"

def featurize_df(df):
    feats = []
    for u in df['url'].tolist():
        feats.append(extract_features(u))
    return pd.DataFrame(feats)

def main():
    Path("models").mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(DATA_PATH)
    X = featurize_df(df)
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:,1]
    print("Classification report:\n", classification_report(y_test, preds))
    try:
        print("ROC AUC:", roc_auc_score(y_test, probs))
    except:
        pass
    joblib.dump((clf, X.columns.tolist()), MODEL_OUT)
    print("Saved model to", MODEL_OUT)

if __name__ == "__main__":
    main()
