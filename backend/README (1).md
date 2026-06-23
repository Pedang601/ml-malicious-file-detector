# 🛡️ MalDetect — Machine Learning-Based Detection of Malicious Files

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-REST%20API-black?logo=flask)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Random%20Forest-orange?logo=scikit-learn)](https://scikit-learn.org/)
[![EMBER](https://img.shields.io/badge/Dataset-EMBER%202018-purple)](https://github.com/elastic/ember)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Accuracy](https://img.shields.io/badge/Accuracy-94.30%25-brightgreen)]()
[![ROC-AUC](https://img.shields.io/badge/ROC--AUC-0.9868-brightgreen)]()

> A web-based malicious PE file detection system using Random Forest trained on the EMBER 2018 dataset — with a real-time web dashboard, Flask REST API, and privacy-preserving VirusTotal hash-only community reference.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [API Endpoints](#-api-endpoints)
- [Model Performance](#-model-performance)
- [Security Testing](#-security-testing)
- [Project Structure](#-project-structure)
- [Scope and Limitations](#-scope-and-limitations)
- [Author](#-author)

---

## 🔍 Overview

**MalDetect** is a Final Year Project (FYP2) developed at **Universiti Kuala Lumpur, Malaysian Institute of Information Technology (UniKL MIIT)** under the Bachelor of Information Technology (Hons) in Computer System Security (BCSS) programme.

The system classifies Windows Portable Executable (PE) files — `.exe`, `.dll`, `.sys` — as **Safe** or **Malicious** using static feature analysis and machine learning, without executing the file. It integrates VirusTotal as a secondary community reference using **SHA256 hash only**, ensuring the uploaded file is never transmitted externally.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **ML Classification** | Random Forest trained on 600,000 EMBER 2018 labelled samples |
| 📊 **2,381 Static Features** | Byte histogram, entropy, PE header, imports, sections, strings |
| 🌐 **Web Dashboard** | Drag-and-drop upload, real-time results, risk level display |
| 🔐 **Privacy-Preserving VT** | Only SHA256 hash sent to VirusTotal — file never leaves your system |
| 📄 **PE Metadata** | Entry point, sections, imported DLLs, digital signature status |
| 📜 **Scan History** | Persistent scan history via browser localStorage |
| 📥 **PDF Reports** | Download formatted PDF reports of scan results |
| 🌙 **Dark/Light Mode** | Toggle interface theme with persistent preference |
| 🔒 **Security Headers** | X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│              USER INTERFACE LAYER                        │
│   Browser · index.html · style.css · script.js          │
│              Drag & Drop File Upload                     │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTP POST (multipart/form-data)
┌──────────────────────▼──────────────────────────────────┐
│              APPLICATION LAYER                           │
│   Flask REST API · /analyze · /health · CORS            │
│              HTTP Security Headers                       │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│              FEATURE EXTRACTION LAYER                    │
│   EMBER PEFeatureExtractor · lief PE Parser              │
│              2,381 Static Features per file              │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│              MACHINE LEARNING LAYER                      │
│   Random Forest · 50 Trees · rf_ember_model.pkl         │
│              scikit-learn · predict_proba()              │
└──────────────────────┬──────────────────────────────────┘
                       │ SHA256 Hash Only
┌──────────────────────▼──────────────────────────────────┐
│              EXTERNAL REFERENCE LAYER                    │
│   VirusTotal API v3 · Hash-Only Lookup                  │
│              File NEVER uploaded externally              │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Category | Technology |
|---|---|
| **Language** | Python 3.11 |
| **Machine Learning** | scikit-learn (RandomForestClassifier) |
| **Feature Extraction** | EMBER library, lief 0.12.3 |
| **Backend** | Flask, Flask-CORS |
| **Model Persistence** | joblib |
| **External API** | VirusTotal API v3 |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **PDF Generation** | jsPDF (client-side) |
| **Security Testing** | Burp Suite Community Edition |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11
- pip
- EMBER 2018 dataset (download from [Kaggle](https://www.kaggle.com/))
- VirusTotal API key (free at [virustotal.com](https://www.virustotal.com))

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/Pedang601/MalDetect.git
cd MalDetect
```

**2. Install dependencies**
```bash
pip install flask flask-cors scikit-learn joblib numpy requests lief
```

**3. Install EMBER library**
```bash
pip install git+https://github.com/elastic/ember.git
```

**4. Apply compatibility patches**

Add these lines at the top of `app.py` (already included):
```python
import lief
# lief version compatibility patch
for attr in ['bad_format','bad_file','pe_error','parser_error',
             'read_out_of_bound','not_implemented','conversion_error',
             'type_error','builder_error','integrity_error']:
    if not hasattr(lief, attr):
        setattr(lief, attr, Exception)

# NumPy compatibility patch
import numpy as np
np.int = int
np.float = float
np.bool = bool
```

**5. Download EMBER 2018 dataset**

Download from Kaggle and place in:
```
MalDetect/
└── ember_dataset/
    ├── train_features_0.jsonl
    ├── train_features_1.jsonl
    ├── ...
    ├── test_features.jsonl
    ├── X_train.dat
    ├── y_train.dat
    ├── X_test.dat
    └── y_test.dat
```

**6. Train the model**
```bash
python train_rf.py
```
> ⚠️ Requires ~8-10GB RAM and ~25-35 minutes on an 8-core CPU.

**7. Configure VirusTotal API key**

In `app.py`, replace with your key:
```python
VT_API_KEY = 'your_virustotal_api_key_here'
```

**8. Run the application**
```bash
python app.py
```

**9. Open the dashboard**

Navigate to: [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 💻 Usage

### Scanning a file

1. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser
2. Drag and drop a `.exe`, `.dll`, or `.sys` file into the upload zone
3. Click **Run analysis**
4. View the result:
   - ✅ **Safe** / ⚠️ **Malicious** verdict badge
   - Malicious probability percentage with risk level (LOW / MEDIUM / HIGH)
   - PE file details (entry point, sections, imports, signature)
   - VirusTotal community reference (vendor detection count)

### Risk Levels

| Probability | Risk Level | Verdict |
|---|---|---|
| 0% – 29% | 🟢 LOW | Safe |
| 30% – 69% | 🟡 MEDIUM | Safe |
| 70% – 100% | 🔴 HIGH | **Malicious** |

> Default classification threshold: **50%** (files ≥ 50% malicious probability → Malicious)

---

## 📡 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serves the web dashboard |
| `/health` | GET | Returns API status and model loading status |
| `/analyze` | POST | Accepts PE file upload, returns classification result |
| `/batch-analyze` | POST | Accepts multiple PE files, returns list of results |

### Example: `/health` response
```json
{
  "status": "healthy",
  "model_loaded": true,
  "model_type": "RandomForest (EMBER 2018)",
  "timestamp": "2026-06-19T16:00:00"
}
```

### Example: `/analyze` response
```json
{
  "filename": "test_malicious.exe",
  "is_malicious": true,
  "malicious_probability": 0.769,
  "benign_probability": 0.231,
  "confidence": 0.769,
  "risk_level": "High",
  "pe_info": {
    "entry_point": "0x1000",
    "sections": ["UPX0", "UPX1"],
    "imports": ["kernel32.dll", "ws2_32.dll"],
    "has_signature": false
  },
  "vt_info": {
    "hash": "abc123...",
    "vt_malicious": 51,
    "vt_total": 75,
    "vt_found": true
  }
}
```

---

## 📈 Model Performance

Evaluated on **200,000 EMBER 2018 test samples** (100,000 benign + 100,000 malicious):

| Metric | Value |
|---|---|
| **Overall Accuracy** | **94.30%** |
| **ROC-AUC Score** | **0.9868** |
| Precision (Malicious) | 94% |
| Recall (Malicious) | 95% |
| F1-Score (Malicious) | 94% |
| True Positives | 94,834 |
| True Negatives | 93,774 |
| False Positives | 6,226 (6.23%) |
| False Negatives | 5,166 (5.17%) |

### Model Configuration
```python
RandomForestClassifier(
    n_estimators=50,
    max_depth=20,
    n_jobs=-1,
    random_state=42
)
```

---

## 🔒 Security Testing

Security testing was performed using **Burp Suite Community Edition**:

| Test Case | Attack | Result |
|---|---|---|
| TC-01 | File upload with no file attached | ✅ HTTP 400 — input validation working |
| TC-02 | Oversized file upload (60MB DoS) | ✅ HTTP 413 — rejected before ML processing |
| TC-03 | SQL injection in filename | ✅ HTTP 200 — no effect (no database) |
| TC-04 | Missing security headers check | ✅ All 4 headers confirmed present |

---

## 📁 Project Structure

```
MalDetect/
├── app.py                  # Flask REST API (main backend)
├── train_rf.py             # Model training script
├── evaluate.py             # Model evaluation script
├── index.html              # Web dashboard
├── style.css               # Dashboard styles
├── script.js               # Dashboard JavaScript
├── rf_ember_model.pkl      # Trained model (generated after training)
├── ember_dataset/          # EMBER 2018 dataset (not included)
│   ├── X_train.dat
│   ├── y_train.dat
│   ├── X_test.dat
│   └── y_test.dat
└── sample/
    ├── check.py            # Quick model test script
    └── test_malicious.exe  # Test PE sample
```

---

## ⚠️ Scope and Limitations

### ✅ What MalDetect CAN detect
- Windows PE files (`.exe`, `.dll`, `.sys`) with malware-like **static structural patterns**
- Malware with suspicious API imports (CreateRemoteThread, VirtualAllocEx, etc.)
- Packed malware with UPX section names (`UPX0`, `UPX1`)
- Files lacking ASLR/DEP protection flags
- High-entropy sections indicative of packed/encrypted payloads

### ❌ What MalDetect CANNOT detect
- Non-PE files (PDF, Office, scripts, images)
- Heavily packed/obfuscated malware hiding its static features
- Fileless malware (memory-only)
- Malware compiled after 2018 with no structural similarity to EMBER training data
- Runtime-evasive malware (sandbox detection, environment checks)

---

## 👤 Author

**Muhammad Akmal Bin Norizan**  
Bachelor of Information Technology (Hons) in Computer System Security (BCSS)  
Universiti Kuala Lumpur, Malaysian Institute of Information Technology (UniKL MIIT)  
📧 akmalnorizan01@s.unikl.edu.my  

**Supervisor:** Dr. Nurul Atiqah Abu Talib

---

## 📚 References

- Anderson, H. S., & Roth, P. (2018). EMBER: An open dataset for training static PE malware machine learning models. *arXiv:1804.04637*
- Breiman, L. (2001). Random forests. *Machine Learning, 45*(1), 5–32
- Pedregosa, F. et al. (2011). Scikit-learn: Machine learning in Python. *JMLR, 12*, 2825–2830

---

> ⚠️ **Disclaimer:** MalDetect is developed for academic and research purposes. The test PE files included are synthetic/crafted samples and contain no real malware. Always handle malware samples responsibly in isolated environments.
