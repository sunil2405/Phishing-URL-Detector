# src/api.py
from flask import Flask, request, render_template, jsonify
import joblib
from pathlib import Path
from features import extract_features
import pandas as pd

app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
MODEL_FILE = "models/phish_model.joblib"

def load_model():
    clf, feature_order = joblib.load(MODEL_FILE)
    return clf, feature_order

clf, feat_order = load_model()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/classify", methods=["POST"])
def classify():
    data = request.json or {}
    url = data.get("url") or request.form.get("url")
    if not url:
        return jsonify({"error":"no url provided"}), 400
    feats = extract_features(url)
    df = pd.DataFrame([feats])
    # ensure correct column order
    df = df[feat_order]
    prob = float(clf.predict_proba(df)[:,1][0])
    label = int(prob > 0.5)
    return jsonify({"url": url, "phishing_probability": prob, "label": label})

if __name__ == "__main__":
    app.run(debug=True, port=5000)
