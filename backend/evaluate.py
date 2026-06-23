import ember
import numpy as np
import joblib
from sklearn.metrics import (
    classification_report, roc_auc_score,
    confusion_matrix, accuracy_score
)
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # non-interactive backend

data_dir = r'C:\Users\User\OneDrive\Documents\malicious-file-detector\backend\ember_dataset'
model_path = r'C:\Users\User\OneDrive\Documents\malicious-file-detector\backend\rf_ember_model.pkl'

print("Loading data...")
X_train, y_train, X_test, y_test = ember.read_vectorized_features(data_dir)

print("Loading model...")
model = joblib.load(model_path)

print("Running predictions on test set...")
y_prob = model.predict_proba(X_test)[:, 1]

# Use same threshold as app.py to reduce false positives
THRESHOLD = 0.4
y_pred = (y_prob >= THRESHOLD).astype(int)

# ── Metrics ──
acc    = accuracy_score(y_test, y_pred)
auc    = roc_auc_score(y_test, y_prob)
report = classification_report(y_test, y_pred, target_names=['Benign', 'Malicious'])
cm     = confusion_matrix(y_test, y_pred)

print(f"\n{'='*50}")
print(f"  Accuracy  : {acc*100:.2f}%")
print(f"  ROC-AUC   : {auc:.4f}")
print(f"{'='*50}")
print(f"\nClassification Report:\n{report}")
print(f"Confusion Matrix:\n{cm}")

# ── Confusion matrix chart ──
fig, ax = plt.subplots(figsize=(5, 4))
im = ax.imshow(cm, cmap='Blues')
plt.colorbar(im)
ax.set_xticks([0,1]); ax.set_yticks([0,1])
ax.set_xticklabels(['Benign','Malicious'])
ax.set_yticklabels(['Benign','Malicious'])
ax.set_xlabel('Predicted'); ax.set_ylabel('Actual')
ax.set_title('Confusion Matrix')
for i in range(2):
    for j in range(2):
        ax.text(j, i, f'{cm[i,j]:,}', ha='center', va='center',
                color='white' if cm[i,j] > cm.max()/2 else 'black', fontsize=12)
plt.tight_layout()
plt.savefig('confusion_matrix.png', dpi=150)
print("\nConfusion matrix saved as confusion_matrix.png")

# ── ROC curve ──
from sklearn.metrics import roc_curve
fpr, tpr, _ = roc_curve(y_test, y_prob)
fig2, ax2 = plt.subplots(figsize=(5, 4))
ax2.plot(fpr, tpr, color='#6c63ff', lw=2, label=f'ROC (AUC = {auc:.4f})')
ax2.plot([0,1],[0,1], 'k--', lw=1)
ax2.set_xlabel('False Positive Rate')
ax2.set_ylabel('True Positive Rate')
ax2.set_title('ROC Curve')
ax2.legend()
plt.tight_layout()
plt.savefig('roc_curve.png', dpi=150)
print("ROC curve saved as roc_curve.png")