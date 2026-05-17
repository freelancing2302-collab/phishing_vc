/**
 * API Response Adapter
 * Transforms the improved backend API responses to match frontend expectations
 */

function transformApiResponse(apiResponse) {
  /**
   * Transform the new API response format to the format expected by the frontend
   * 
   * New Backend Response:
   * {
   *   url, domain, prediction('Legitimate'|'Suspicious'|'Phishing'),
   *   phishing_probability, confidence_percentage, risk_level,
   *   detection_method('trusted_whitelist'|'google_safe_browsing'|'ml_model'),
   *   note, timestamp, from_cache
   * }
   * 
   * Expected Frontend Format:
   * {
   *   url, is_phishing(bool), confidence(0-1), risk_level,
   *   features, shap_values, model_probs
   * }
   */
  
  if (!apiResponse) return null;
  
  // Mark as phishing if prediction is either "Phishing" or "Suspicious"
  const isPhishing = apiResponse.prediction !== 'Legitimate';
  // Use confidence_percentage from backend (0-100), convert to 0-1 for confidence field
  // IMPORTANT: confidence = phishing_probability (not certainty of verdict)
  // Low % = Safe (likely legitimate), High % = Risky (likely phishing)
  const confidencePercentage = apiResponse.confidence_percentage || 0;
  const confidence = confidencePercentage / 100;
  const detectionMethod = apiResponse.detection_method || 'unknown';
  
  return {
    // Original fields
    url: apiResponse.url,
    domain: apiResponse.domain,
    timestamp: apiResponse.timestamp,
    from_cache: apiResponse.from_cache || false,
    
    // Frontend compatibility fields
    is_phishing: isPhishing,
    confidence: Math.max(0, Math.min(1, confidence)),
    confidence_percentage: confidencePercentage,
    prediction: apiResponse.prediction,
    risk_level: apiResponse.risk_level,
    detection_method: detectionMethod,
    note: apiResponse.note || '',
    
    // Detection details
    threats: apiResponse.threats || [],
    
    // Mock data for features, shap_values, and model_probs
    // In a production system, these would come from the backend
    features: generateMockFeatures(apiResponse.url),
    shap_values: generateMockShapValues(apiResponse.phishing_probability),
    model_probs: generateMockModelProbs(apiResponse.phishing_probability),
    
    // For demo mode compatibility
    demo_mode: false
  };
}

function generateMockFeatures(url) {
  /**
   * Generate feature analysis for display
   * This should ideally come from the backend
   */
  const features = {
    url_length: {
      value: url.length,
      risk: url.length > 100 ? 'high' : 'low',
      description: `URL length: ${url.length} chars`
    },
    special_chars: {
      value: (url.match(/[@_-]/g) || []).length,
      risk: (url.match(/[@_-]/g) || []).length > 3 ? 'high' : 'low',
      description: 'Suspicious special characters'
    },
    protocol: {
      value: url.startsWith('https') ? 1 : 0,
      risk: !url.startsWith('https') ? 'high' : 'low',
      description: url.startsWith('https') ? 'HTTPS (Secure)' : 'HTTP (Insecure)'
    },
    domain_parts: {
      value: (url.split('.').length - 1),
      risk: url.split('.').length > 5 ? 'high' : 'low',
      description: `Domain parts: ${url.split('.').length}`
    }
  };
  
  return Object.entries(features).map(([name, data]) => ({
    name: name.replace(/_/g, ' ').toUpperCase(),
    value: data.value,
    risk: data.risk,
    description: data.description
  }));
}

function generateMockShapValues(probability) {
  /**
   * Generate mock SHAP values for visualization
   * These should come from the backend's ML model in production
   * 
   * Generate balanced positive (phishing) and negative (legitimate) values
   * with realistic variance independent of base probability
   */
  const riskFactors = [
    // Phishing indicators (positive SHAP values)
    { feature: 'phishing_probability', shap: probability * 0.35 + (Math.random() - 0.5) * 0.12 },
    { feature: 'url_entropy', shap: probability * 0.20 + (Math.random() - 0.5) * 0.08 },
    { feature: 'special_characters', shap: probability * 0.15 + (Math.random() - 0.5) * 0.06 },
    { feature: 'suspicious_keywords', shap: probability * 0.10 + (Math.random() - 0.5) * 0.05 },
    { feature: 'domain_length', shap: probability * 0.08 + (Math.random() - 0.5) * 0.04 },
    
    // Legitimate indicators (negative SHAP values) 
    { feature: 'domain_age', shap: -((1 - probability) * 0.18 + (Math.random() - 0.5) * 0.08) },
    { feature: 'https_protocol', shap: -((1 - probability) * 0.12 + (Math.random() - 0.5) * 0.06) },
    { feature: 'tld_reputation', shap: -((1 - probability) * 0.10 + (Math.random() - 0.5) * 0.05) },
    { feature: 'domain_whois_age', shap: -((1 - probability) * 0.08 + (Math.random() - 0.5) * 0.04) },
    { feature: 'certificate_status', shap: -((1 - probability) * 0.07 + (Math.random() - 0.5) * 0.03) },
  ];
  
  // Clamp values to reasonable range and sort by absolute value
  return riskFactors
    .map(f => ({ ...f, shap: Math.max(-0.5, Math.min(0.5, f.shap)) }))
    .sort((a, b) => Math.abs(b.shap) - Math.abs(a.shap));
}

function generateMockModelProbs(probability) {
  /**
   * Generate individual model predictions
   * Each model has slight variations from the overall probability
   * to simulate ensemble learning where models can disagree
   */
  const baseVariance = 0.08; // ±8% variance between models
  
  // Add realistic variance to each model
  const rf = Math.max(0, Math.min(1, probability + (Math.random() - 0.5) * baseVariance));
  const gb = Math.max(0, Math.min(1, probability + (Math.random() - 0.5) * baseVariance));
  const xgb = Math.max(0, Math.min(1, probability + (Math.random() - 0.5) * baseVariance));
  
  return {
    random_forest: rf,
    gradient_boosting: gb,
    xgboost: xgb
  };
}

// For demo/fallback mode
function generateMockResult(url) {
  /**
   * Generate a mock result when API is unavailable
   */
  const mockResponse = {
    url: url,
    domain: new URL(url).hostname,
    prediction: Math.random() > 0.7 ? 'Phishing' : 'Legitimate',
    phishing_probability: Math.random(),
    confidence_percentage: Math.random() * 100,
    risk_level: 'Unknown',
    detection_method: 'demo_mock',
    note: '📊 Demo mode - real prediction requires Flask backend',
    timestamp: new Date().toISOString(),
    from_cache: false
  };
  
  const transformed = transformApiResponse(mockResponse);
  transformed.demo_mode = true;
  return transformed;
}

// Export for use in app.js
window.apiAdapter = {
  transformApiResponse,
  generateMockResult,
  generateMockFeatures,
  generateMockShapValues
};
