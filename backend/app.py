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
CORS(app, origins=["*"], supports_credentials=True)

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
# ===============================
# URL CACHE MANAGEMENT
# ===============================
url_cache = {}
cache_timestamps = {}  # Separate dictionary to store when each URL was cached

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

def extract_url_features(url):
    """
    Extract 30 URL features for ML model
    These are the features the model was trained on
    """
    try:
        from urllib.parse import urlparse
        import re
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        
        features = []
        
        # Length features
        features.append(len(url))  # URL length
        features.append(len(domain))  # Domain length
        features.append(len(path))  # Path length
        features.append(len(query))  # Query length
        
        # Count features
        features.append(url.count('.'))  # Dots in URL
        features.append(url.count('-'))  # Hyphens in URL
        features.append(url.count('_'))  # Underscores in URL
        features.append(url.count('?'))  # Question marks
        features.append(url.count('='))  # Equal signs
        features.append(url.count('&'))  # Ampersands
        features.append(url.count('/'))  # Forward slashes
        features.append(domain.count('.'))  # Dots in domain
        features.append(domain.count('-'))  # Hyphens in domain
        
        # Protocol features
        features.append(1 if url.startswith('https') else 0)  # HTTPS used
        features.append(1 if url.startswith('http://') else 0)  # HTTP used
        
        # Special character features
        features.append(len(re.findall(r'[0-9]', url)))  # Digits count
        features.append(len(re.findall(r'[A-Z]', url)))  # Uppercase letters
        features.append(len(re.findall(r'[@#$%&*]', url)))  # Special chars
        
        # Domain features
        features.append(1 if domain.count('.') > 2 else 0)  # Subdomains
        features.append(1 if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', domain) else 0)  # IP address
        features.append(1 if len(domain) > 75 else 0)  # Long domain
        features.append(1 if any(char.isdigit() for char in domain) else 0)  # Digits in domain
        
        # URL structure
        features.append(len(path.split('/')))  # Path segments
        features.append(query.count('&') + 1 if query else 0)  # Query parameters
        features.append(1 if '%' in url else 0)  # URL encoded chars
        features.append(1 if '//' in url[8:] else 0)  # Double slash (except in protocol)
        
        # Entropy/randomness
        unique_chars = len(set(domain))
        features.append(unique_chars)  # Unique characters in domain
        
        # Pad or trim to 30 features if needed
        while len(features) < 30:
            features.append(0)
        features = features[:30]
        
        return features
    except Exception as e:
        logger.error(f"Error extracting features: {e}")
        return [0] * 30

def ml_predict(url):
    """Run ML model prediction on URL"""
    if not model:
        return None
    
    try:
        # Extract 30 URL features instead of using vectorizer
        features = extract_url_features(url)
        import numpy as np
        X = np.array([features])
        
        probability = model.predict_proba(X)[0][1]
        
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
        if url in url_cache and url in cache_timestamps:
            cached_timestamp = cache_timestamps[url]
            if datetime.now() - cached_timestamp < timedelta(hours=1):
                cached_result = url_cache[url].copy()
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
            cache_timestamps[url] = datetime.now()
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
            cache_timestamps[url] = datetime.now()
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
        cache_timestamps[url] = datetime.now()
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
    global url_cache, cache_timestamps
    url_cache.clear()
    cache_timestamps.clear()
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
    