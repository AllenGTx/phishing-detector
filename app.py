# Deployment Update: 2026-05-03 22:30
from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from urllib.parse import urlparse
import os
import warnings

warnings.filterwarnings('ignore')

# Memaksa Flask mengenali folder templates di root project
base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, 'templates')
app = Flask(__name__, template_folder=template_dir)

# Load Models dengan Path Absolut agar tidak error di Vercel
try:
    model = joblib.load(os.path.join(base_dir, 'RandomForest_Phishing.joblib'))
    scaler = joblib.load(os.path.join(base_dir, 'scaler_phishing.joblib'))
    # tfidf load jika diperlukan, tapi sesuaikan dengan fitur model Anda
    print("✓ Models Loaded")
except Exception as e:
    print(f"Model Load Error: {e}")

def extract_features(url):
    try:
        parsed_url = urlparse(url)
        return [
            len(url), len(parsed_url.netloc), len(parsed_url.path),
            url.count('.'), url.count('-'), url.count('_'),
            url.count('/'), url.count('?'), url.count('='),
            1 if url.startswith('http') else 0,
            1 if url.startswith('https') else 0,
            1 if ':' in parsed_url.netloc else 0,
            len(parsed_url.netloc.split('.')) - 1
        ]
    except:
        return None

@app.route('/')
@app.route('/index')
def home():
    # Langsung merender tanpa embel-embel folder lagi
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({"status": "ok", "info": "Routing Fixed"}), 200

@app.route('/api/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL Kosong'}), 400
    
    if not url.startswith('http'):
        url = 'http://' + url
        
    features = extract_features(url)
    if not features:
        return jsonify({'error': 'URL Invalid'}), 400
        
    try:
        features_arr = np.array([features])
        features_scaled = scaler.transform(features_arr)
        prediction = model.predict(features_scaled)[0]
        prob = model.predict_proba(features_scaled)[0]
        
        return jsonify({
            'url': url,
            'is_phishing': bool(prediction == 1),
            'confidence': round(float(max(prob)) * 100, 2)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False)