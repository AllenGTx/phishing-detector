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
    model = joblib.load('RandomForest_Phishing.joblib')
    tfidf = joblib.load('tfidf_phishing.joblib')
    scaler = joblib.load('scaler_phishing.joblib')
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
    """Generate penjelasan menggunakan rule-based LLM"""
    reasons = []
    if not features_dict or not parsed_url:
        return "Tidak dapat menganalisis URL ini."
    
    # Logic penjelasan (disingkat untuk efisiensi copas)
    if is_phishing:
        if features_dict['url_length'] > 75: reasons.append("📏 URL sangat panjang")
        if features_dict['num_dots'] > 3: reasons.append("🔴 Terlalu banyak titik")
        if not reasons: reasons.append(f"🚨 Terdeteksi pola phishing ({confidence}%)")
        explanation = "Alasan link ini terdeteksi sebagai PHISHING:\n\n" + "\n".join(f"  {r}" for r in reasons)
    else:
        explanation = "Alasan link ini terdeteksi sebagai AMAN:\n\n✅ Struktur URL tampak normal."
    
    return explanation

def predict_phishing(url):
    """Prediksi apakah URL adalah phishing"""
    try:
        features_dict, parsed_url = extract_features(url)
        if features_dict is None:
            return {'error': 'URL format tidak valid'}, 400
        
        basic_features = np.array([list(features_dict.values())])
        
        # Gunakan scaler sesuai input yang diharapkan model Anda
        feature_scaled = scaler.transform(basic_features)
        
        prediction = model.predict(feature_scaled)[0]
        probability = model.predict_proba(feature_scaled)[0]
        
        is_phishing = int(prediction) == 1
        confidence = float(max(probability)) * 100
        
        explanation = generate_llm_explanation(url, is_phishing, confidence, features_dict, parsed_url)
        
        return {
            'url': url,
            'is_phishing': is_phishing,
            'confidence': round(confidence, 2),
            'risk_level': 'TINGGI' if is_phishing and confidence > 80 else 'SEDANG' if is_phishing else 'RENDAH',
            'explanation': explanation
        }, 200
    except Exception as e:
        return {'error': str(e)}, 500

# --- BAGIAN ROUTING YANG DIPERKUAT ---
@app.route('/')
@app.route('/index')
@app.route('/home')
def home():
    # Memaksa Flask mencari index.html di dalam folder templates
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'message': 'Backend is running'}), 200

@app.route('/api/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL tidak boleh kosong'}), 400
    if not url.startswith('http'):
        url = 'http://' + url
    result, status = predict_phishing(url)
    return jsonify(result), status

if __name__ == '__main__':
    app.run(debug=False)