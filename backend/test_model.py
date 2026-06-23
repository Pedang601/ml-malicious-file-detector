import ember
import numpy as np
import joblib
from sklearn.metrics import (
    classification_report, accuracy_score,
    roc_auc_score, confusion_matrix
)

data_dir  = r'C:\Users\User\OneDrive\Documents\malicious-file-detector\backend\ember_dataset'
model_path = r'C:\Users\User\OneDrive\Documents\malicious-file-detector\backend\rf_ember_model.pkl'

print("Loading data and model...")
X_train, y_train, X_test, y_test = ember.read_vectorized_features(data_dir)
model = joblib.load(model_path)

print("Running predictions on full test set (200,000 samples)...")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

# ── Metrics ──
acc = accuracy_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_prob)
cm  = confusion_matrix(y_test, y_pred)

tn, fp, fn, tp = cm.ravel()

print(f"\n{'='*50}")
print(f"  Accuracy        : {acc*100:.2f}%")
print(f"  ROC-AUC         : {auc:.4f}")
print(f"  True Positives  : {tp:,}  (malware correctly detected)")
print(f"  True Negatives  : {tn:,}  (benign correctly identified)")
print(f"  False Positives : {fp:,}  (benign flagged as malware)")
print(f"  False Negatives : {fn:,}  (malware missed)")
print(f"{'='*50}")
print(f"\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign','Malicious']))