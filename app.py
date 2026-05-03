from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)

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
        
        # Basic features
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
    
    # Analisis URL characteristics
    url_length = features_dict['url_length']
    domain_length = features_dict['domain_length']
    num_dots = features_dict['num_dots']
    num_dashes = features_dict['num_dashes']
    subdomain_count = features_dict['subdomain_count']
    has_https = features_dict['has_https']
    
    if is_phishing:
        # Phishing explanation
        if url_length > 75:
            reasons.append(f"📏 URL sangat panjang ({url_length} karakter) - tipik phishing untuk menyembunyikan domain asli")
        
        if num_dots > 3:
            reasons.append(f"🔴 Terlalu banyak titik ({num_dots}) dalam URL - tanda subdomain mencurigakan")
        
        if subdomain_count > 2:
            reasons.append(f"🔗 Banyak subdomain ({subdomain_count}) - sering digunakan scammer untuk menipu")
        
        if not has_https:
            reasons.append("🔓 Tidak menggunakan HTTPS - koneksi tidak terenkripsi, risiko pencurian data")
        
        if num_dashes > 2:
            reasons.append(f"➖ Banyak dash/hyphen dalam domain - red flag untuk domain phishing")
        
        if "-" in parsed_url.netloc and "." in parsed_url.netloc:
            domain_part = parsed_url.netloc.split(':')[0]  # Remove port if exists
            if "-" in domain_part.split('.')[0]:  # Check subdomain
                reasons.append("⚠️ Subdomain menggunakan dash - sering digunakan untuk typosquatting")
        
        if len(parsed_url.path) > 50 and len(parsed_url.path) > 0:
            reasons.append("📂 Path yang sangat panjang dengan parameter kompleks - teknik obfuscation")
        
        if '?' in url and url.count('=') > 3:
            reasons.append("⚙️ Banyak parameter query - sering untuk menyembunyikan intent sebenarnya")
        
        if not reasons:
            reasons.append(f"🚨 Model machine learning mendeteksi pola phishing (confidence: {confidence}%)")
        
        explanation = "Alasan link ini terdeteksi sebagai PHISHING:\n\n" + "\n".join(f"  {r}" for r in reasons)
        
    else:
        # Legitimate explanation
        if has_https:
            reasons.append("✅ Menggunakan protokol HTTPS - koneksi aman & terenkripsi")
        
        if domain_length < 30:
            reasons.append("✅ Panjang domain wajar - tidak ada tanda penyamaran")
        
        if num_dots <= 2:
            reasons.append("✅ Struktur domain normal - tidak ada subdomain mencurigakan")
        
        if num_dashes <= 1:
            reasons.append("✅ Tidak ada terlalu banyak dash/hyphen - struktur normal")
        
        if subdomain_count <= 1:
            reasons.append("✅ Subdomain standar - tidak ada teknik obfuscation")
        
        if url_length < 100:
            reasons.append("✅ Panjang URL normal - tidak ada parameter tersembunyi yang mencurigakan")
        
        if len(parsed_url.path) < 50:
            reasons.append("✅ Path URL sederhana dan jelas - bukan teknik obfuscation")
        
        explanation = "Alasan link ini terdeteksi sebagai AMAN:\n\n" + "\n".join(f"  {r}" for r in reasons)
    
    return explanation

def predict_phishing(url):
    """Prediksi apakah URL adalah phishing"""
    try:
        # Extract URL-based features
        features_dict, parsed_url = extract_features(url)
        if features_dict is None:
            return {'error': 'URL format tidak valid'}, 400
        
        # TF-IDF vectorization (for URL content)
        try:
            tfidf_features = tfidf.transform([url]).toarray()
        except:
            tfidf_features = np.zeros((1, 5003))  # Fallback if TF-IDF fails
        
        # Combine features
        basic_features = np.array([list(features_dict.values())])
        combined_features = np.hstack([basic_features, tfidf_features])
        
        # Scale features
        # For now, just use basic features if combined is too large
        feature_scaled = scaler.transform(basic_features)
        
        # Make prediction
        prediction = model.predict(feature_scaled)[0]
        probability = model.predict_proba(feature_scaled)[0]
        
        # 0 = Legitimate, 1 = Phishing
        is_phishing = int(prediction) == 1
        confidence = float(max(probability)) * 100
        
        # Generate LLM explanation
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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL tidak boleh kosong'}), 400
    
    # Tambah http jika belum ada
    if not url.startswith('http'):
        url = 'http://' + url
    
    result, status = predict_phishing(url)
    return jsonify(result), status

@app.route('/api/batch', methods=['POST'])
def batch_check():
    """Cek multiple URLs sekaligus"""
    data = request.get_json()
    urls = data.get('urls', [])
    
    if not isinstance(urls, list) or not urls:
        return jsonify({'error': 'URLs harus berupa list'}), 400
    
    results = []
    for url in urls[:100]:  # Max 100 URLs
        url = url.strip()
        if url:
            if not url.startswith('http'):
                url = 'http://' + url
            result, _ = predict_phishing(url)
            if 'error' not in result:
                results.append(result)
    
    return jsonify({'results': results, 'total': len(results)}), 200

@app.route('/health')
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
