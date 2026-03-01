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
  
  const isPishing = apiResponse.prediction === 'Phishing';
  const confidence = apiResponse.phishing_probability || 0;
  const detectionMethod = apiResponse.detection_method || 'unknown';
  
  return {
    // Original fields
    url: apiResponse.url,
    domain: apiResponse.domain,
    timestamp: apiResponse.timestamp,
    from_cache: apiResponse.from_cache || false,
    
    // Frontend compatibility fields
    is_phishing: isPishing,
    confidence: Math.max(0, Math.min(1, confidence)),
    confidence_percentage: apiResponse.confidence_percentage || 0,
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
    model_probs: {
      phishing: apiResponse.phishing_probability,
      legitimate: 1 - apiResponse.phishing_probability,
      suspicious: 0
    },
    
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
   */
  const riskFactors = [
    { feature: 'phishing_probability', shap: probability * 0.4 },
    { feature: 'url_entropy', shap: probability * 0.2 },
    { feature: 'domain_age', shap: (1 - probability) * 0.15 },
    { feature: 'special_characters', shap: probability * 0.15 },
    { feature: 'https_protocol', shap: (1 - probability) * 0.1 },
    { feature: 'suspicious_keywords', shap: probability * 0.08 },
    { feature: 'tld_reputation', shap: (1 - probability) * 0.07 },
    { feature: 'domain_length', shap: probability * 0.05 },
  ];
  
  return riskFactors.sort((a, b) => Math.abs(b.shap) - Math.abs(a.shap));
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
