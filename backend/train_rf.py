import numpy as np
import ember
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

data_dir = r'C:\Users\User\OneDrive\Documents\malicious-file-detector\backend\ember_dataset'

print("Loading vectorized features...")
X_train, y_train, X_test, y_test = ember.read_vectorized_features(data_dir)

# Remove unlabeled samples
mask = y_train != -1
X_train = X_train[mask]
y_train = y_train[mask]

print(f"Training on ALL {X_train.shape[0]} labeled samples")

# Train Random Forest with memory-efficient settings
rf = RandomForestClassifier(
    n_estimators=50,    # reduced from 100 to save RAM
    max_depth=20,       # reduced from 25 to save RAM
    n_jobs=-1,
    random_state=42,
    verbose=1
)

print("Training Random Forest on full dataset...")
rf.fit(X_train, y_train)

# Evaluate
print("\nEvaluating...")
y_pred = rf.predict(X_test)
y_prob = rf.predict_proba(X_test)[:, 1]

print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))
print(f"ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}")

# Save model
joblib.dump(rf, 'rf_ember_model.pkl')
print("Model saved as rf_ember_model.pkl")