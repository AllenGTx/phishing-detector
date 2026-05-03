# PhishGuard - Phishing Link Detector

Website pendeteksi link phishing menggunakan Machine Learning.

## 🚀 Cara Deploy GRATIS (Pilih 1):

### **OPSI 1: Render.com (REKOMENDASI - PALING MUDAH)**

1. **Buat akun di Render.com**: https://render.com
2. **Push code ke GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/USERNAME/phishing-detector.git
   git push -u origin main
   ```

3. **Di Render Dashboard**:
   - Click "New Web Service"
   - Connect GitHub repository
   - Render akan auto-detect render.yaml
   - Klik "Deploy"
   - Tunggu 5-10 menit ✓

**Keuntungan Render:**
- ✓ Gratis selamanya (free tier)
- ✓ Unlimited bandwidth
- ✓ Auto-deploy dari GitHub
- ✓ Custom domain support
- ✓ HTTPS included

---

### **OPSI 2: Heroku (Gratis dengan verifikasi kartu)**

1. **Install Heroku CLI**: https://devcenter.heroku.com/articles/heroku-cli
2. **Login & setup**:
   ```bash
   heroku login
   heroku create phishing-detector-app
   ```
3. **Deploy**:
   ```bash
   git push heroku main
   ```

---

### **OPSI 3: Railway.app (Gratis $5/bulan)**

1. Signup di: https://railway.app
2. Connect GitHub
3. Auto-deploy, sangat mudah!

---

## 🖥️ Jalankan Lokal (Testing)

```bash
# Install dependencies
pip install -r requirements.txt

# Run app
python app.py
```

Buka: http://localhost:5000

---

## 📋 File Structure

```
phishing-detector/
├── app.py                    # Flask backend
├── requirements.txt          # Python dependencies
├── render.yaml              # Konfigurasi Render
├── templates/
│   └── index.html           # Frontend UI
├── RandomForest_Phishing.joblib
├── tfidf_phishing.joblib
├── scaler_phishing.joblib
└── README.md
```

---

## 🔧 API Endpoints

### Single URL Check
```bash
POST /api/check
Content-Type: application/json

{
  "url": "https://example.com"
}

Response:
{
  "url": "https://example.com",
  "is_phishing": false,
  "confidence": 95.2,
  "risk_level": "RENDAH"
}
```

### Batch Check (Banyak URL)
```bash
POST /api/batch
Content-Type: application/json

{
  "urls": [
    "https://example1.com",
    "https://example2.com"
  ]
}
```

---

## 🎨 Features

✓ Cek URL individual
✓ Batch check hingga 100 URL
✓ Real-time prediction dengan confidence score
✓ User-friendly interface
✓ Mobile responsive
✓ Dark/Light mode ready
✓ Export hasil (di update v2)

---

## ⚠️ Disclaimer

Tool ini adalah untuk **edukasi dan keamanan pribadi**. Selalu:
- Verifikasi link dari sumber terpercaya
- Tidak mengganti verifikasi manual lengkap
- Gunakan bersama tools security lainnya
- Lapor phishing ke cybercrime.gov.id

---

## 🛠️ Update ke versi baru

Pull latest code dan push ke Render:
```bash
git add .
git commit -m "Update features"
git push origin main
# Render auto-redeploy!
```

---

## 📞 Support

Jika ada error:
1. Check Render logs: Dashboard > Service > Logs
2. Pastikan model files (.joblib) ada
3. Pastikan requirements.txt lengkap
4. Cek Python version (3.9+)

---

## 📊 Model Info

- **Model**: Random Forest Classifier
- **Accuracy**: ~95%+ (tergantung training data)
- **Input Features**: URL characteristics (length, dots, dashes, dll)
- **Train Data**: Legitimate + Phishing URLs

---

**Made with ❤️**
