import numpy as np
np.int = int
np.float = float
np.bool = bool

import ember
import joblib

data_dir  = r'C:\Users\User\OneDrive\Documents\malicious-file-detector\backend\ember_dataset'
model_path = r'C:\Users\User\OneDrive\Documents\malicious-file-detector\backend\rf_ember_model.pkl'

print("Loading data and model...")
X_train, y_train, X_test, y_test = ember.read_vectorized_features(data_dir)
model = joblib.load(model_path)

# Get 5 confirmed malicious samples from EMBER test set
mal_idx = np.where(y_test == 1)[0][:5]
ben_idx = np.where(y_test == 0)[0][:5]

print("\n--- MALICIOUS SAMPLES ---")
for i, idx in enumerate(mal_idx):
    features = X_test[idx].reshape(1, -1)
    pred = model.predict(features)[0]
    prob = model.predict_proba(features)[0][1]
    verdict = "MALICIOUS" if pred == 1 else "SAFE"
    print(f"Sample {i+1}: {verdict} ({prob*100:.1f}%)")

print("\n--- BENIGN SAMPLES ---")
for i, idx in enumerate(ben_idx):
    features = X_test[idx].reshape(1, -1)
    pred = model.predict(features)[0]
    prob = model.predict_proba(features)[0][1]
    verdict = "MALICIOUS" if pred == 1 else "SAFE"
    print(f"Sample {i+1}: {verdict} ({prob*100:.1f}%)")