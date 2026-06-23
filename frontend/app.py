from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import tempfile
import joblib
import numpy as np
from datetime import datetime
import logging
import hashlib
import requests

# Import lief FIRST and patch ALL missing attributes before ember loads
import lief
_lief_missing = [
    'bad_format', 'bad_file', 'pe_error', 'parser_error',
    'read_out_of_bound', 'not_implemented', 'conversion_error',
    'type_error', 'builder_error', 'integrity_error'
]
for _attr in _lief_missing:
    if not hasattr(lief, _attr):
        setattr(lief, _attr, Exception)

# Import ember AFTER lief is patched
import ember

# Fix numpy compatibility
np.int = int
np.float = float
np.bool = bool

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)

# Classification threshold — 0.4 to detect malicious files
THRESHOLD = 0.4

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# VirusTotal API Key
VT_API_KEY = 'd01cc7fcd456676de38a4eb2c0b0f5d622eab179fceaa1312b741df7e09d2e18'

# Load trained EMBER Random Forest model
model_path = os.path.join(os.path.dirname(__file__), 'rf_ember_model.pkl')
try:
    ml_model = joblib.load(model_path)
    logger.info("Random Forest model loaded successfully")
except Exception as e:
    logger.error(f"Error loading model: {e}")
    ml_model = None

# Initialize EMBER feature extractor
extractor = ember.PEFeatureExtractor(feature_version=2)


def extract_ember_features(file_path):
    """Extract 2381-dim EMBER feature vector from a PE file."""
    try:
        with open(file_path, 'rb') as f:
            bytez = f.read()
        if len(bytez) == 0:
            raise ValueError("File is empty")
        features = extractor.feature_vector(bytez)
        non_zero = (features != 0).sum()
        logger.info(f"Features extracted: {non_zero}/2381 non-zero")
        return features.reshape(1, -1)
    except Exception as e:
        logger.warning(f"Feature extraction failed: {e}, using zero vector")
        return np.zeros((1, 2381), dtype=np.float32)


def get_pe_info(file_path):
    """Extract basic PE metadata for display purposes."""
    try:
        pe = lief.parse(file_path)
        if pe is None or not isinstance(pe, lief.PE.Binary):
            return {}
        info = {}
        try:
            info['imports'] = [lib.name for lib in pe.imports][:10]
        except Exception:
            info['imports'] = []
        try:
            info['sections'] = [s.name for s in pe.sections]
        except Exception:
            info['sections'] = []
        try:
            info['has_signature'] = len(list(pe.signatures)) > 0
        except Exception:
            info['has_signature'] = False
        try:
            info['entry_point'] = hex(pe.optional_header.addressof_entrypoint)
        except Exception:
            info['entry_point'] = 'N/A'
        return info
    except Exception:
        return {}


def get_virustotal_info(file_path):
    """Get VirusTotal community stats using file hash only — file never leaves server."""
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        headers = {'x-apikey': VT_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{file_hash}',
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            attrs = data['data']['attributes']
            stats = attrs.get('last_analysis_stats', {})
            return {
                'hash': file_hash,
                'vt_malicious': stats.get('malicious', 0),
                'vt_suspicious': stats.get('suspicious', 0),
                'vt_undetected': stats.get('undetected', 0),
                'vt_total': sum(stats.values()),
                'vt_found': True,
                'vt_name': attrs.get('meaningful_name', ''),
            }
        elif response.status_code == 404:
            return {
                'hash': file_hash,
                'vt_found': False,
                'vt_note': 'Hash not found in VirusTotal database'
            }
        else:
            return {'hash': file_hash, 'vt_found': False}

    except Exception as e:
        logger.warning(f"VirusTotal lookup failed: {e}")
        return {}


@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('.', filename)


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': ml_model is not None,
        'model_type': 'RandomForest (EMBER 2018)',
        'timestamp': datetime.now().isoformat()
    })


@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    temp_path = None
    try:
        temp_path = os.path.join(tempfile.gettempdir(), 'maldetect_upload.exe')
        file.save(temp_path)

        if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
            return jsonify({'error': 'File could not be saved'}), 500

        logger.info(f"Analyzing file: {file.filename}")
        feature_vector = extract_ember_features(temp_path)

        if ml_model is None:
            return jsonify({'error': 'Model not loaded'}), 500

        probability = ml_model.predict_proba(feature_vector)[0]
        malicious_prob = float(probability[1])
        benign_prob = float(probability[0])
        prediction = 1 if malicious_prob >= THRESHOLD else 0

        if malicious_prob < 0.3:
            risk_level = 'Low'
        elif malicious_prob < 0.7:
            risk_level = 'Medium'
        else:
            risk_level = 'High'

        pe_info = get_pe_info(temp_path)
        vt_info = get_virustotal_info(temp_path)

        return jsonify({
            'filename': file.filename,
            'is_malicious': bool(prediction),
            'malicious_probability': malicious_prob,
            'benign_probability': benign_prob,
            'confidence': float(max(probability)),
            'risk_level': risk_level,
            'pe_info': pe_info,
            'vt_info': vt_info,
            'analysis_timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error analyzing file: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


@app.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    files = request.files.getlist('files')
    results = []
    for file in files:
        temp_path = None
        try:
            temp_path = os.path.join(tempfile.gettempdir(), f'maldetect_{file.filename}')
            file.save(temp_path)
            feature_vector = extract_ember_features(temp_path)
            if ml_model is None:
                results.append({'filename': file.filename, 'error': 'Model not loaded'})
                continue
            probability = ml_model.predict_proba(feature_vector)[0]
            malicious_prob = float(probability[1])
            prediction = 1 if malicious_prob >= THRESHOLD else 0
            vt_info = get_virustotal_info(temp_path)
            results.append({
                'filename': file.filename,
                'is_malicious': bool(prediction),
                'malicious_probability': malicious_prob,
                'benign_probability': float(probability[0]),
                'confidence': float(max(probability)),
                'risk_level': 'High' if malicious_prob > 0.7 else 'Medium' if malicious_prob > 0.3 else 'Low',
                'vt_info': vt_info
            })
        except Exception as e:
            results.append({'filename': file.filename, 'error': str(e)})
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
    return jsonify({
        'total_files': len(results),
        'results': results,
        'analysis_timestamp': datetime.now().isoformat()
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)