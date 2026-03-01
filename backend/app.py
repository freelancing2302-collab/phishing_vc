"""
PhishGuard AI - Phishing Detection System
Improved Backend with Google Safe Browsing API Integration
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import joblib
import os
import json
import requests
from datetime import datetime, timedelta
import logging

# ===============================
# LOGGING CONFIGURATION
# ===============================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ===============================
# FLASK APP SETUP
# ===============================
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://localhost"])

# ===============================
# LOAD MODELS & VECTORIZER
# ===============================
try:
    model = joblib.load("model/meta_model.pkl")
    vectorizer = joblib.load("model/vectorizer.pkl")
    logger.info("✅ Model and vectorizer loaded successfully")
except Exception as e:
    logger.error(f"❌ Error loading model: {e}")
    model = None
    vectorizer = None

# ===============================
# CONFIGURATION
# ===============================
class Config:
    # Trusted domains whitelist
    TRUSTED_DOMAINS = {
        'google.com',
        'gmail.com',
        'facebook.com',
        'instagram.com',
        'twitter.com',
        'linkedin.com',
        'github.com',
        'stackoverflow.com',
        'amazon.com',
        'microsoft.com',
        'apple.com',
        'youtube.com',
        'reddit.com',
        'wikipedia.org',
        'bank.com',  # Example - replace with real banks
        'paypal.com',
        'stripe.com',
    }
    
    # Google Safe Browsing API
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_API_KEY', 'YOUR_GOOGLE_API_KEY_HERE')
    GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    # ML Model thresholds
    PHISHING_THRESHOLD = 0.85      # High risk
    SUSPICIOUS_THRESHOLD = 0.50    # Medium risk
    
    # API Rate Limiting
    MAX_REQUESTS_PER_MINUTE = 60

# Simple in-memory cache for URL results
url_cache = {}

# ===============================
# UTILITY FUNCTIONS
# ===============================

def normalize_domain(url):
    """Extract and normalize domain from URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        return domain
    except Exception as e:
        logger.error(f"Error parsing URL: {e}")
        return None

def is_domain_trusted(domain):
    """Check if domain is in trusted whitelist"""
    if not domain:
        return False
    
    # Exact match
    if domain in Config.TRUSTED_DOMAINS:
        return True
    
    # Subdomain match (e.g., mail.google.com matches google.com)
    for trusted in Config.TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    
    return False

def check_google_safe_browsing(url):
    """
    Check URL against Google Safe Browsing API
    Returns: {'is_safe': bool, 'threats': list, 'method': 'google'}
    """
    if Config.GOOGLE_SAFE_BROWSING_API_KEY == 'YOUR_GOOGLE_API_KEY_HERE':
        logger.warning("Google Safe Browsing API key not configured")
        return None
    
    try:
        request_body = {
            "client": {
                "clientId": "PhishGuardAI",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        
        headers = {"Content-Type": "application/json"}
        params = {"key": Config.GOOGLE_SAFE_BROWSING_API_KEY}
        
        response = requests.post(
            Config.GOOGLE_SAFE_BROWSING_URL,
            json=request_body,
            headers=headers,
            params=params,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            threats = data.get('matches', [])
            is_safe = len(threats) == 0
            
            return {
                'is_safe': is_safe,
                'threats': threats,
                'method': 'google_safe_browsing'
            }
        else:
            logger.warning(f"Google Safe Browsing API returned status {response.status_code}")
            return None
            
    except requests.exceptions.Timeout:
        logger.warning("Google Safe Browsing API timeout")
        return None
    except Exception as e:
        logger.error(f"Error checking Google Safe Browsing: {e}")
        return None

def ml_predict(url):
    """Run ML model prediction on URL"""
    if not model or not vectorizer:
        return None
    
    try:
        url_vec = vectorizer.transform([url])
        probability = model.predict_proba(url_vec)[0][1]
        
        return {
            'probability': float(probability),
            'method': 'ml_model'
        }
    except Exception as e:
        logger.error(f"Error in ML prediction: {e}")
        return None

def classify_prediction(probability):
    """Classify URL based on probability"""
    if probability < Config.SUSPICIOUS_THRESHOLD:
        return "Legitimate", "Low Risk"
    elif probability < Config.PHISHING_THRESHOLD:
        return "Suspicious", "Medium Risk"
    else:
        return "Phishing", "High Risk"

# ===============================
# API ROUTES
# ===============================

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_loaded": model is not None
    })

@app.route("/predict", methods=["GET", "POST"])
def predict():
    """
    Main prediction endpoint
    POST with JSON body: { "url": "https://example.com" }
    """
    
    if request.method == "GET":
        return jsonify({
            "message": "Use POST request",
            "example": {
                "url": "https://example.com"
            }
        }), 400
    
    try:
        # Get and validate URL
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON body"}), 400
        
        url = data.get("url", "").strip()
        
        if not url:
            return jsonify({"error": "Please provide a URL"}), 400
        
        if not url.startswith(("http://", "https://")):
            return jsonify({"error": "Invalid URL format. Use http:// or https://"}), 400
        
        # Check cache
        if url in url_cache:
            cached_result = url_cache[url]
            if datetime.now() - cached_result['timestamp'] < timedelta(hours=1):
                cached_result['from_cache'] = True
                return jsonify(cached_result), 200
        
        # Normalize domain
        domain = normalize_domain(url)
        if not domain:
            return jsonify({"error": "Could not parse URL"}), 400
        
        # ===============================
        # 1️⃣ TRUSTED WHITELIST CHECK
        # ===============================
        if is_domain_trusted(domain):
            result = {
                "url": url,
                "domain": domain,
                "prediction": "Legitimate",
                "phishing_probability": 0.0,
                "confidence_percentage": 100.0,
                "risk_level": "Low Risk",
                "detection_method": "trusted_whitelist",
                "note": "✅ Domain is in trusted whitelist",
                "timestamp": datetime.now().isoformat(),
                "from_cache": False
            }
            url_cache[url] = result
            return jsonify(result), 200
        
        # ===============================
        # 2️⃣ GOOGLE SAFE BROWSING CHECK
        # ===============================
        google_result = check_google_safe_browsing(url)
        if google_result and not google_result['is_safe']:
            result = {
                "url": url,
                "domain": domain,
                "prediction": "Phishing",
                "phishing_probability": 0.99,
                "confidence_percentage": 99.0,
                "risk_level": "High Risk",
                "detection_method": "google_safe_browsing",
                "note": "🚨 URL flagged by Google Safe Browsing as malicious",
                "threats": google_result['threats'],
                "timestamp": datetime.now().isoformat(),
                "from_cache": False
            }
            url_cache[url] = result
            logger.warning(f"Phishing detected via Google Safe Browsing: {url}")
            return jsonify(result), 200
        
        # ===============================
        # 3️⃣ ML MODEL PREDICTION
        # ===============================
        ml_result = ml_predict(url)
        
        if ml_result:
            probability = ml_result['probability']
            prediction, risk_level = classify_prediction(probability)
            confidence = round(probability * 100, 2)
            
            result = {
                "url": url,
                "domain": domain,
                "prediction": prediction,
                "phishing_probability": probability,
                "confidence_percentage": confidence,
                "risk_level": risk_level,
                "detection_method": "ml_model",
                "note": f"URL analyzed by ML model with {confidence}% confidence",
                "timestamp": datetime.now().isoformat(),
                "from_cache": False
            }
        else:
            # Fallback if model fails
            result = {
                "url": url,
                "domain": domain,
                "prediction": "Unknown",
                "phishing_probability": 0.5,
                "confidence_percentage": 0.0,
                "risk_level": "Unknown",
                "detection_method": "error",
                "note": "⚠️ Could not load ML model. Please check backend logs.",
                "timestamp": datetime.now().isoformat(),
                "from_cache": False
            }
            return jsonify(result), 503
        
        # Cache the result
        url_cache[url] = result
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Unexpected error in predict: {e}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500

@app.route("/whitelist", methods=["GET", "POST", "DELETE"])
def manage_whitelist():
    """
    Manage whitelist
    GET: Return current whitelist
    POST: Add domain to whitelist
    DELETE: Remove domain from whitelist
    """
    
    if request.method == "GET":
        return jsonify({
            "whitelist": list(Config.TRUSTED_DOMAINS),
            "count": len(Config.TRUSTED_DOMAINS)
        }), 200
    
    elif request.method == "POST":
        try:
            data = request.get_json()
            domain = data.get("domain", "").lower().strip()
            
            if not domain:
                return jsonify({"error": "Domain required"}), 400
            
            Config.TRUSTED_DOMAINS.add(domain)
            logger.info(f"Added {domain} to whitelist")
            
            return jsonify({
                "message": f"✅ {domain} added to whitelist",
                "whitelist": list(Config.TRUSTED_DOMAINS)
            }), 200
            
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    
    elif request.method == "DELETE":
        try:
            data = request.get_json()
            domain = data.get("domain", "").lower().strip()
            
            if domain not in Config.TRUSTED_DOMAINS:
                return jsonify({"error": "Domain not in whitelist"}), 404
            
            Config.TRUSTED_DOMAINS.remove(domain)
            logger.info(f"Removed {domain} from whitelist")
            
            return jsonify({
                "message": f"✅ {domain} removed from whitelist",
                "whitelist": list(Config.TRUSTED_DOMAINS)
            }), 200
            
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route("/cache/clear", methods=["POST"])
def clear_cache():
    """Clear URL cache"""
    global url_cache
    url_cache.clear()
    logger.info("Cache cleared")
    return jsonify({"message": "✅ Cache cleared"}), 200

@app.route("/stats", methods=["GET"])
def get_stats():
    """Get application statistics"""
    return jsonify({
        "total_urls_cached": len(url_cache),
        "model_status": "loaded" if model else "not_loaded",
        "whitelist_size": len(Config.TRUSTED_DOMAINS),
        "google_api_configured": Config.GOOGLE_SAFE_BROWSING_API_KEY != 'YOUR_GOOGLE_API_KEY_HERE'
    }), 200

# ===============================
# ERROR HANDLERS
# ===============================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {error}")
    return jsonify({"error": "Internal server error"}), 500

# ===============================
# RUN APPLICATION
# ===============================

if __name__ == "__main__":
    logger.info("🚀 Starting PhishGuard AI Backend...")
    app.run(
        debug=os.getenv('FLASK_DEBUG', False),
        host="0.0.0.0",
        port=5000
    )
    