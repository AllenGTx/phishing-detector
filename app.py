# Force Cache Refresh: 2026-05-03 22:20
from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from urllib.parse import urlparse
import warnings
import os

warnings.filterwarnings('ignore')

# Definisi folder templates secara eksplisit untuk Vercel
app = Flask(__name__, template_folder='templates')

# Load models
try:
    # Memastikan path model terbaca di environment Vercel
    base_path = os.path.dirname(__file__)
    model = joblib.load(os.path.join(base_path, 'RandomForest_Phishing.joblib'))
    tfidf = joblib.load(os.path.join(base_path, 'tfidf_phishing.joblib'))
    scaler = joblib.load(os.path.join(base_path, 'scaler_phishing.joblib'))
    print("✓ Models loaded successfully")
except Exception as e:
    print(f"Error loading models: {e}")

def extract_features(url):
    """Extract features dari URL untuk prediksi"""
    try:
        parsed_url = urlparse(url)
        features = {
            'url_length': len(url),
            'domain_length': len(parsed_url.netloc),
            'path_length': len(parsed_url.path),
            'num_dots': url.count('.'),
            'num_dashes': url.count('-'),
            'num_underscores': url.count('_'),
            'num_slashes': url.count('/'),
            'num_question_marks': url.count('?'),
            'num_equals': url.count('='),
            'has_http': 1 if url.startswith('http') else 0,
            'has_https': 1 if url.startswith('https') else 0,
            'has_port': 1 if ':' in parsed_url.netloc else 0,
            'subdomain_count': len(parsed_url.netloc.split('.')) - 1 if '.' in parsed_url.netloc else 0,
        }
        return features, parsed_url
    except:
        return None, None

def generate_llm_explanation(url, is_phishing, confidence, features_dict, parsed_url):
    """Rule-based explanation"""
    reasons = []
    if is_phishing:
        if features_dict['url_length'] > 75: reasons.append("📏 URL sangat panjang")
        if features_dict['num_dots'] > 3: reasons.append("🔴 Terlalu banyak titik")
        if not reasons: reasons.append(f"🚨 Pola mencurigakan ({confidence}%)")
        explanation = "Alasan deteksi PHISHING:\n" + "\n".join(reasons)
    else:
        explanation = "✅ Link ini tampak aman untuk dikunjungi."
    return explanation

# --- ROUTING ---

@app.route('/')
@app.route('/index')
@app.route('/home')
def home():
    # Ini akan mengambil file dari folder templates/index.html
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok', 
        'message': 'Backend is active',
        'timestamp': '2026-05-03 22:20'
    }), 200

@app.route('/api/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL kosong'}), 400
    
    if not url.startswith('http'):
        url = 'http://' + url
        
    try:
        features_dict, parsed_url = extract_features(url)
        basic_features = np.array([list(features_dict.values())])
        feature_scaled = scaler.transform(basic_features)
        
        prediction = model.predict(feature_scaled)[0]
        probability = model.predict_proba(feature_scaled)[0]
        
        is_phishing = int(prediction) == 1
        confidence = float(max(probability)) * 100
        
        return jsonify({
            'url': url,
            'is_phishing': is_phishing,
            'confidence': round(confidence, 2),
            'explanation': generate_llm_explanation(url, is_phishing, confidence, features_dict, parsed_url)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False)