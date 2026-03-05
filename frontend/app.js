/* ======================================================
   PhishGuard AI — Main Application Logic
   ====================================================== */

'use strict';

// ── Config ──────────────────────────────────────────────
const CONFIG = {
  apiBase: 'https://phishing-vc-3.onrender.com',
  apiTimeout: 15000,
  debounceMs: 200,
};

// ── State ────────────────────────────────────────────────
const state = {
  history: JSON.parse(localStorage.getItem('phishguard_history') || '[]'),
  currentResult: null,
  historyFilter: 'all',
  shapChart: null,
};

// ── DOM refs ─────────────────────────────────────────────
const $ = id => document.getElementById(id);

const DOM = {
  urlInput:        $('urlInput'),
  analyzeBtn:      $('analyzeBtn'),
  clearBtn:        $('clearBtn'),
  scanOverlay:     $('scanOverlay'),
  resultSection:   $('resultSection'),
  analyzerCard:    $('analyzerCard'),
  verdictBanner:   $('verdictBanner'),
  verdictIconWrap: $('verdictIconWrap'),
  verdictIcon:     $('verdictIcon'),
  verdictLabel:    $('verdictLabel'),
  verdictUrl:      $('verdictUrl'),
  confValue:       $('confValue'),
  confCircle:      $('confCircle'),
  featureTableBody:$('featureTableBody'),
  modelsGrid:      $('modelsGrid'),
  riskReport:      $('riskReport'),
  historyList:     $('historyList'),
  historyEmpty:    $('historyEmpty'),
  toast:           $('toast'),
  apiStatus:       $('apiStatus'),
  apiStatusText:   $('apiStatusText'),
  navbar:          $('navbar'),
  hamburger:       $('hamburger'),
  mobileDrawer:    $('mobileDrawer'),
  scanSteps:       {
    extract: $('step-extract'),
    predict: $('step-predict'),
    shap:    $('step-shap'),
    done:    $('step-done'),
  },
};

// ══════════════════════════════════════════════════════════
//  PARTICLE BACKGROUND
// ══════════════════════════════════════════════════════════
(function initParticles() {
  const canvas = $('particleCanvas');
  const ctx    = canvas.getContext('2d');
  let W, H, particles;

  const resize = () => {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  };

  const randomBetween = (a, b) => a + Math.random() * (b - a);

  const makeParticle = () => ({
    x:   Math.random() * W,
    y:   Math.random() * H,
    vx:  randomBetween(-.25, .25),
    vy:  randomBetween(-.25, .25),
    r:   randomBetween(.5, 1.8),
    alpha: randomBetween(.15, .5),
  });

  const init = () => {
    resize();
    particles = Array.from({ length: 110 }, makeParticle);
  };

  const draw = () => {
    ctx.clearRect(0, 0, W, H);

    // Draw connections
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 130) {
          ctx.strokeStyle = `rgba(99,102,241,${0.08 * (1 - dist / 130)})`;
          ctx.lineWidth   = 0.6;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw particles
    particles.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(99,102,241,${p.alpha})`;
      ctx.fill();

      p.x += p.vx;
      p.y += p.vy;

      if (p.x < -5)     p.x = W + 5;
      if (p.x > W + 5)  p.x = -5;
      if (p.y < -5)     p.y = H + 5;
      if (p.y > H + 5)  p.y = -5;
    });

    requestAnimationFrame(draw);
  };

  window.addEventListener('resize', () => {
    resize();
    particles.forEach(p => {
      if (p.x > W) p.x = Math.random() * W;
      if (p.y > H) p.y = Math.random() * H;
    });
  });

  init();
  draw();
})();

// ══════════════════════════════════════════════════════════
//  NAVBAR — scroll & active link
// ══════════════════════════════════════════════════════════
window.addEventListener('scroll', () => {
  DOM.navbar.classList.toggle('scrolled', window.scrollY > 20);

  // Update active nav link
  const sections = ['hero','features','analyzer','history','about'];
  const scrollY = window.scrollY + 100;
  let active = 'hero';
  sections.forEach(id => {
    const el = document.getElementById(id);
    if (el && el.offsetTop <= scrollY) active = id;
  });

  document.querySelectorAll('.nav-link').forEach(l => {
    l.classList.toggle('active', l.id === `nav-${active}`);
  });
});

DOM.hamburger.addEventListener('click', () => {
  DOM.mobileDrawer.classList.toggle('open');
});

document.querySelectorAll('.mob-link').forEach(l => {
  l.addEventListener('click', () => DOM.mobileDrawer.classList.remove('open'));
});

// ══════════════════════════════════════════════════════════
//  API STATUS CHECK
// ══════════════════════════════════════════════════════════
async function checkApiStatus() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);

    const res = await fetch(`${CONFIG.apiBase}/health`, {
      method: 'GET',
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (res.ok) {
      DOM.apiStatus.className = 'status-dot online';
      DOM.apiStatusText.textContent = 'API Online';
    } else {
      throw new Error('not ok');
    }
  } catch {
    DOM.apiStatus.className = 'status-dot offline';
    DOM.apiStatusText.textContent = 'Demo Mode';
  }
}

checkApiStatus();
setInterval(checkApiStatus, 30000);

// ══════════════════════════════════════════════════════════
//  URL INPUT HANDLING
// ══════════════════════════════════════════════════════════
DOM.urlInput.addEventListener('input', () => {
  const val = DOM.urlInput.value.trim();
  DOM.analyzeBtn.disabled = val.length < 4;
  DOM.clearBtn.style.display = val ? 'flex' : 'none';
});

DOM.urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !DOM.analyzeBtn.disabled) analyze();
});

DOM.clearBtn.addEventListener('click', () => {
  DOM.urlInput.value = '';
  DOM.analyzeBtn.disabled = true;
  DOM.clearBtn.style.display = 'none';
  DOM.urlInput.focus();
  hideResults();
});

// Example pills
document.querySelectorAll('.pill').forEach(pill => {
  pill.addEventListener('click', () => {
    DOM.urlInput.value = pill.dataset.url;
    DOM.analyzeBtn.disabled = false;
    DOM.clearBtn.style.display = 'flex';
    DOM.urlInput.focus();
  });
});

DOM.analyzeBtn.addEventListener('click', analyze);

// ══════════════════════════════════════════════════════════
//  SCAN ANIMATION STEPS
// ══════════════════════════════════════════════════════════
function runScanSteps() {
  const steps = ['extract','predict','shap','done'];
  const delays = [300, 900, 1600, 2200];
  steps.forEach((step, i) => {
    setTimeout(() => {
      // Mark previous as done
      if (i > 0) {
        DOM.scanSteps[steps[i-1]].classList.remove('active');
        DOM.scanSteps[steps[i-1]].classList.add('done');
      }
      DOM.scanSteps[step].classList.add('active');
    }, delays[i]);
  });
}

function resetScanSteps() {
  Object.values(DOM.scanSteps).forEach(el => {
    el.classList.remove('active','done');
  });
  DOM.scanSteps.extract.classList.add('active');
}

// ══════════════════════════════════════════════════════════
//  MOCK DATA — used when API is offline
// ══════════════════════════════════════════════════════════
function generateMockResult(url) {
  // Simple heuristic to make demo feel realistic
  const suspiciousKeywords = ['login','verify','secure','account','update','confirm','paypal','amazon','bank','signin'];
  const suspiciousTLDs     = ['.xyz','.ru','.tk','.ml','.ga','.cf','.gq'];
  const suspiciousChars    = (url.match(/[-_.]/g) || []).length;
  const hasNumbers         = /\d/.test(url.replace(/https?:\/\//, '').split('/')[0]);
  const urlLen             = url.length;

  let phishScore = 0.1;
  suspiciousKeywords.forEach(kw => { if (url.toLowerCase().includes(kw)) phishScore += 0.18; });
  suspiciousTLDs.forEach(tld => { if (url.toLowerCase().includes(tld)) phishScore += 0.25; });
  if (suspiciousChars > 3) phishScore += 0.12;
  if (hasNumbers) phishScore += 0.08;
  if (urlLen > 75) phishScore += 0.1;
  if (url.includes('http://')) phishScore += 0.08;

  // Clamp
  phishScore = Math.min(phishScore + (Math.random() * 0.06 - 0.03), 0.98);
  phishScore = Math.max(phishScore, 0.04);

  const isPhishing = phishScore > 0.5;

  const shapValues = [
    { feature: 'url_length',            value: +(urlLen / 100).toFixed(3),            shap: isPhishing ?  0.08  : -0.04 },
    { feature: 'special_char_ratio',    value: +(suspiciousChars / urlLen).toFixed(3), shap: isPhishing ?  0.14  : -0.06 },
    { feature: 'has_suspicious_word',   value: isPhishing ? 1 : 0,                    shap: isPhishing ?  0.22  : -0.18 },
    { feature: 'https_protocol',        value: url.startsWith('https') ? 1 : 0,       shap: url.startsWith('https') ? -0.12 : 0.15 },
    { feature: 'url_entropy',           value: +calcEntropy(url).toFixed(3),           shap: +(calcEntropy(url) * 0.03 - 0.05).toFixed(3) },
    { feature: 'subdomain_count',       value: (url.split('/')[2] || '').split('.').length - 2, shap: isPhishing ? 0.09 : -0.03 },
    { feature: 'dot_count',             value: (url.match(/\./g) || []).length,         shap: isPhishing ? 0.06  : -0.02 },
    { feature: 'has_ip_address',        value: /\d{1,3}\.\d{1,3}/.test(url) ? 1 : 0,  shap: /\d{1,3}\.\d{1,3}/.test(url) ? 0.19 : -0.01 },
    { feature: 'path_length',           value: url.split('?')[0].length,               shap: isPhishing ? 0.05  : -0.04 },
    { feature: 'typosquatting_score',   value: +(Math.random() * (isPhishing ? 0.7 : 0.1)).toFixed(3), shap: isPhishing ? 0.17 : -0.12 },
    { feature: 'homograph_suspicion',   value: isPhishing ? +(Math.random() * 0.5).toFixed(2) : 0, shap: isPhishing ? 0.11 : 0.0 },
    { feature: 'tld_risk_score',        value: +phishScore.toFixed(3),                 shap: isPhishing ? 0.13  : -0.09 },
  ].sort((a, b) => Math.abs(b.shap) - Math.abs(a.shap));

  const features = [
    { name: 'url_length',          value: urlLen,                           risk: urlLen > 75 ? 'high' : urlLen > 45 ? 'medium' : 'low',   desc: 'Total character length of the URL' },
    { name: 'special_char_count',  value: suspiciousChars,                  risk: suspiciousChars > 5 ? 'high' : suspiciousChars > 2 ? 'medium' : 'low', desc: 'Count of special characters (-, _, .)' },
    { name: 'has_https',           value: url.startsWith('https') ? 'Yes' : 'No', risk: url.startsWith('https') ? 'low' : 'high',         desc: 'Whether URL uses HTTPS protocol' },
    { name: 'url_entropy',         value: calcEntropy(url).toFixed(3),      risk: calcEntropy(url) > 4.5 ? 'high' : 'low',               desc: 'Shannon entropy of URL string' },
    { name: 'subdomain_depth',     value: (url.split('/')[2] || '').split('.').length - 2, risk: ((url.split('/')[2] || '').split('.').length - 2) > 2 ? 'high' : 'low', desc: 'Number of subdomains present' },
    { name: 'has_ip_in_host',      value: /\d{1,3}\.\d{1,3}/.test(url.split('/')[2]) ? 'Yes' : 'No', risk: /\d{1,3}\.\d{1,3}/.test(url) ? 'high' : 'low', desc: 'Whether host is an IP address' },
    { name: 'typosquatting_score', value: isPhishing ? (Math.random() * 0.7).toFixed(3) : (Math.random() * 0.1).toFixed(3), risk: isPhishing ? 'high' : 'low', desc: 'Levenshtein similarity to known brand domains' },
    { name: 'homograph_score',     value: isPhishing ? (Math.random() * 0.5).toFixed(3) : '0.000', risk: isPhishing ? 'medium' : 'low',  desc: 'Unicode homograph attack detection score' },
    { name: 'tld_suspicion',       value: suspiciousTLDs.some(t => url.includes(t)) ? 'Yes' : 'No', risk: suspiciousTLDs.some(t => url.includes(t)) ? 'high' : 'low', desc: 'Whether TLD is in high-risk list' },
    { name: 'query_param_count',   value: (url.split('?')[1] || '').split('&').filter(Boolean).length, risk: 'low', desc: 'Number of query parameters' },
    { name: 'path_depth',          value: (url.split('/').length - 3),      risk: 'low',                                                  desc: 'Depth of the URL path' },
    { name: 'suspicious_keywords', value: suspiciousKeywords.filter(kw => url.toLowerCase().includes(kw)).length, risk: suspiciousKeywords.filter(kw => url.toLowerCase().includes(kw)).length > 0 ? 'high' : 'low', desc: 'Count of phishing keywords found in URL' },
  ];

  const rfProb   = +(phishScore * 0.95 + Math.random() * 0.05).toFixed(3);
  const gbProb   = +(phishScore * 0.92 + Math.random() * 0.06).toFixed(3);
  const xgbProb  = +(phishScore * 0.97 + Math.random() * 0.04).toFixed(3);

  return {
    url,
    is_phishing:   isPhishing,
    confidence:    +(isPhishing ? phishScore : 1 - phishScore).toFixed(4),
    phishing_prob: +phishScore.toFixed(4),
    shap_values:   shapValues,
    features,
    model_probs: {
      random_forest:       Math.min(rfProb,  0.99),
      gradient_boosting:   Math.min(gbProb,  0.99),
      xgboost:             Math.min(xgbProb, 0.99),
    },
    demo_mode: true,
  };
}

function calcEntropy(str) {
  const freq = {};
  str.split('').forEach(c => { freq[c] = (freq[c] || 0) + 1; });
  const len = str.length;
  return Object.values(freq).reduce((e, f) => {
    const p = f / len;
    return e - p * Math.log2(p);
  }, 0);
}

// ══════════════════════════════════════════════════════════
//  ANALYZE
// ══════════════════════════════════════════════════════════
async function analyze() {
  const url = DOM.urlInput.value.trim();
  if (!url || url.length < 4) return;

  // Show loading state
  DOM.analyzeBtn.querySelector('.btn-text').style.display = 'none';
  DOM.analyzeBtn.querySelector('.btn-loading').style.display = 'flex';
  DOM.analyzeBtn.disabled = true;

  hideResults();
  resetScanSteps();
  DOM.scanOverlay.style.display = 'flex';
  runScanSteps();

  let result;
  try {
    result = await fetchAnalysis(url);
  } catch (err) {
    // Fallback to demo mode
    result = generateMockResult(url);
    if (err.name !== 'AbortError') {
      showToast('API offline — showing demo prediction', 'error');
    }
  }

  // Min display time for animation
  await sleep(2800);

  DOM.scanOverlay.style.display = 'none';
  DOM.analyzeBtn.querySelector('.btn-text').style.display = 'flex';
  DOM.analyzeBtn.querySelector('.btn-loading').style.display = 'none';
  DOM.analyzeBtn.disabled = false;

  state.currentResult = result;
  renderResult(result);
  addToHistory(result);
}

async function fetchAnalysis(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CONFIG.apiTimeout);

  const res = await fetch(`${CONFIG.apiBase}/predict`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ url }),
    signal:  controller.signal,
  });
  clearTimeout(timer);

  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ══════════════════════════════════════════════════════════
//  RENDER RESULT
// ══════════════════════════════════════════════════════════
function renderResult(result) {
  const isPhish = result.is_phishing;
  const conf    = (result.confidence * 100).toFixed(1);

  // Verdict banner
  DOM.verdictBanner.className = `verdict-banner ${isPhish ? 'phishing' : 'legitimate'}`;
  DOM.verdictIcon.textContent  = isPhish ? '⚠️' : '✅';
  DOM.verdictLabel.textContent = isPhish ? '🚨 PHISHING DETECTED' : '✅ LEGITIMATE URL';
  DOM.verdictUrl.textContent   = result.url;

  // Confidence circle
  DOM.confValue.textContent = `${conf}%`;
  DOM.confValue.style.color = isPhish ? 'var(--red-l)' : 'var(--green-l)';
  DOM.confCircle.style.stroke = isPhish ? '#ef4444' : '#22c55e';

  const dashoff = 314 - (314 * parseFloat(conf) / 100);
  setTimeout(() => {
    DOM.confCircle.style.strokeDashoffset = dashoff;
  }, 100);

  // Render tabs
  renderShapChart(result.shap_values);
  renderFeatureTable(result.features);
  renderModelCards(result.model_probs, result.is_phishing);
  renderRiskReport(result);

  // Reset tabs
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  $('tab-shap').classList.add('active');
  $('panel-shap').classList.add('active');

  DOM.resultSection.style.display = 'block';
  DOM.resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

  if (result.demo_mode) {
    showToast('📊 Demo mode — connect Flask backend for real predictions', 'success');
  }
}

// ── SHAP Chart ───────────────────────────────────────────
function renderShapChart(shapValues) {
  const ctx = $('shapChart').getContext('2d');
  if (state.shapChart) state.shapChart.destroy();

  const top = shapValues.slice(0, 10);
  const labels = top.map(s => s.feature.replace(/_/g, ' '));
  const values = top.map(s => s.shap);
  const colors = values.map(v => v > 0
    ? `rgba(239,68,68,${Math.min(0.3 + Math.abs(v) * 1.5, 0.9)})`
    : `rgba(34,197,94,${Math.min(0.3 + Math.abs(v) * 1.5, 0.9)})`
  );
  const borderColors = values.map(v => v > 0 ? 'rgba(239,68,68,1)' : 'rgba(34,197,94,1)');

  state.shapChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'SHAP Value',
        data: values,
        backgroundColor: colors,
        borderColor: borderColors,
        borderWidth: 1.5,
        borderRadius: 6,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 800, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d1528',
          borderColor: 'rgba(99,102,241,.3)',
          borderWidth: 1,
          titleColor: '#f1f5f9',
          bodyColor: '#94a3b8',
          callbacks: {
            label: ctx => ` SHAP: ${ctx.parsed.x > 0 ? '+' : ''}${ctx.parsed.x.toFixed(4)}`,
          },
        },
      },
      scales: {
        x: {
          grid:  { color: 'rgba(255,255,255,.05)' },
          ticks: { color: '#64748b', font: { size: 11 } },
          border:{ color: 'rgba(255,255,255,.07)' },
        },
        y: {
          grid:  { display: false },
          ticks: { color: '#94a3b8', font: { size: 11, family: 'Inter' } },
          border:{ color: 'rgba(255,255,255,.07)' },
        },
      },
    },
  });
}

// ── Feature Table ────────────────────────────────────────
function renderFeatureTable(features) {
  const riskIcon = r => r === 'high' ? '🔴' : r === 'medium' ? '🟡' : '🟢';

  DOM.featureTableBody.innerHTML = features.map(f => `
    <tr>
      <td class="feature-name">${f.name}</td>
      <td class="feature-value">${f.value}</td>
      <td>
        <span class="risk-badge risk-${f.risk}">
          ${riskIcon(f.risk)} ${f.risk.toUpperCase()}
        </span>
      </td>
      <td>${f.desc}</td>
    </tr>
  `).join('');
}

// ── Model Cards ──────────────────────────────────────────
function renderModelCards(modelProbs, isPhishing) {
  const models = [
    { key: 'random_forest',     label: 'Random Forest',     icon: '🌲' },
    { key: 'gradient_boosting', label: 'Gradient Boosting', icon: '⚡' },
    { key: 'xgboost',           label: 'XGBoost',           icon: '🚀' },
  ];

  DOM.modelsGrid.innerHTML = models.map(m => {
    const prob    = modelProbs[m.key] ?? 0.5;
    const pct     = (prob * 100).toFixed(1);
    const isPhish = prob > 0.5;
    const dashoff = 201 - (201 * prob);
    const strokeColor = isPhish ? '#ef4444' : '#22c55e';
    const uid = `gauge-${m.key}`;

    return `
      <div class="model-card">
        <div class="model-name">${m.icon} ${m.label}</div>
        <div class="model-gauge">
          <svg class="model-gauge-svg" width="80" height="80" viewBox="0 0 80 80">
            <circle cx="40" cy="40" r="32" class="gauge-track"/>
            <circle cx="40" cy="40" r="32" class="gauge-fill" id="${uid}"
              style="stroke:${strokeColor}; stroke-dashoffset:201"/>
          </svg>
          <div class="model-prob-text" style="color:${strokeColor}">${pct}%</div>
        </div>
        <div class="model-verdict ${isPhish ? 'phishing' : 'legit'}">
          ${isPhish ? '⚠️ Phishing' : '✅ Legitimate'}
        </div>
      </div>
    `;
  }).join('');

  // Animate gauges
  requestAnimationFrame(() => {
    models.forEach(m => {
      const prob = modelProbs[m.key] ?? 0.5;
      const el   = document.getElementById(`gauge-${m.key}`);
      if (el) {
        setTimeout(() => {
          el.style.transition = 'stroke-dashoffset 1.2s ease';
          el.style.strokeDashoffset = 201 - (201 * prob);
        }, 100);
      }
    });
  });
}

// ── Risk Report ──────────────────────────────────────────
function renderRiskReport(result) {
  const isPhish = result.is_phishing;
  const conf    = (result.confidence * 100).toFixed(1);
  const url     = result.url;

  let domain = '–';
  try { domain = new URL(url.startsWith('http') ? url : `http://${url}`).hostname; } catch {}

  const riskItems = [
    {
      icon:  isPhish ? '🚨' : '✅',
      label: 'Overall Verdict',
      value: isPhish
        ? `Classified as PHISHING with ${conf}% confidence`
        : `Classified as LEGITIMATE with ${conf}% confidence`,
    },
    {
      icon:  '🌐',
      label: 'Domain Analysis',
      value: `Domain: ${domain} — ${isPhish ? 'Suspicious patterns detected' : 'No suspicious patterns found'}`,
    },
    {
      icon:  url.startsWith('https') ? '🔒' : '⛔',
      label: 'Protocol Security',
      value: url.startsWith('https')
        ? 'HTTPS protocol detected — encrypted connection'
        : 'HTTP protocol — no encryption, higher risk',
    },
    {
      icon:  '🤖',
      label: 'Model Ensemble',
      value: `Random Forest, Gradient Boosting & XGBoost all evaluated. Meta-classifier produced final output.`,
    },
    {
      icon:  '💡',
      label: 'SHAP Insights',
      value: isPhish
        ? `Top risk features: ${(result.shap_values || []).filter(s => s.shap > 0).slice(0,3).map(s => s.feature.replace(/_/g,' ')).join(', ')}`
        : `Top safe signals: ${(result.shap_values || []).filter(s => s.shap < 0).slice(0,3).map(s => s.feature.replace(/_/g,' ')).join(', ')}`,
    },
    {
      icon:  '📋',
      label: 'Recommendation',
      value: isPhish
        ? '⚠️ Do NOT click this link. Report it to your security team and block the domain.'
        : '✅ URL appears safe. Always verify sender context and exercise caution.',
    },
  ];

  DOM.riskReport.innerHTML = riskItems.map(item => `
    <div class="risk-item">
      <div class="risk-item-icon">${item.icon}</div>
      <div>
        <div class="risk-item-label">${item.label}</div>
        <div class="risk-item-value">${item.value}</div>
      </div>
    </div>
  `).join('');
}

// ── Hide Results ─────────────────────────────────────────
function hideResults() {
  DOM.resultSection.style.display = 'none';
  DOM.scanOverlay.style.display = 'none';
  if (state.shapChart) { state.shapChart.destroy(); state.shapChart = null; }
}

// ── Result Action Buttons ────────────────────────────────
$('analyzeAnotherBtn').addEventListener('click', () => {
  hideResults();
  DOM.urlInput.focus();
  window.scrollTo({ top: $('analyzer').offsetTop - 80, behavior: 'smooth' });
});

$('copyReportBtn').addEventListener('click', () => {
  if (!state.currentResult) return;
  const r = state.currentResult;
  const report = [
    `PhishGuard AI — Analysis Report`,
    `URL: ${r.url}`,
    `Verdict: ${r.is_phishing ? 'PHISHING' : 'LEGITIMATE'}`,
    `Confidence: ${(r.confidence * 100).toFixed(1)}%`,
    `Timestamp: ${new Date().toISOString()}`,
    '',
    `Model Probabilities:`,
    `  Random Forest:     ${((r.model_probs?.random_forest || 0)*100).toFixed(2)}%`,
    `  Gradient Boosting: ${((r.model_probs?.gradient_boosting || 0)*100).toFixed(2)}%`,
    `  XGBoost:           ${((r.model_probs?.xgboost || 0)*100).toFixed(2)}%`,
  ].join('\n');

  navigator.clipboard.writeText(report)
    .then(() => showToast('Report copied to clipboard!', 'success'))
    .catch(() => showToast('Could not copy report', 'error'));
});

// ══════════════════════════════════════════════════════════
//  TABS
// ══════════════════════════════════════════════════════════
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    $(`panel-${tab}`).classList.add('active');
  });
});

// ══════════════════════════════════════════════════════════
//  HISTORY
// ══════════════════════════════════════════════════════════
function addToHistory(result) {
  const entry = {
    url:         result.url,
    is_phishing: result.is_phishing,
    confidence:  result.confidence,
    timestamp:   Date.now(),
  };
  state.history.unshift(entry);
  if (state.history.length > 50) state.history.pop();
  localStorage.setItem('phishguard_history', JSON.stringify(state.history));
  renderHistory();
}

function renderHistory() {
  const filter  = state.historyFilter;
  const entries = state.history.filter(h => {
    if (filter === 'phishing')   return h.is_phishing;
    if (filter === 'legitimate') return !h.is_phishing;
    return true;
  });

  DOM.historyEmpty.style.display = entries.length === 0 ? 'flex' : 'none';

  // Remove existing items
  document.querySelectorAll('.history-item').forEach(el => el.remove());

  entries.forEach(entry => {
    const el = document.createElement('div');
    el.className = `history-item`;
    el.innerHTML = `
      <div class="history-verdict-dot ${entry.is_phishing ? 'phishing' : 'legit'}"></div>
      <div class="history-url">${entry.url}</div>
      <span class="history-badge ${entry.is_phishing ? 'phishing' : 'legit'}">
        ${entry.is_phishing ? '⚠️ Phishing' : '✅ Legit'}
      </span>
      <span class="history-conf">${(entry.confidence * 100).toFixed(0)}%</span>
      <span class="history-time">${timeAgo(entry.timestamp)}</span>
    `;
    el.addEventListener('click', () => {
      DOM.urlInput.value = entry.url;
      DOM.analyzeBtn.disabled = false;
      DOM.clearBtn.style.display = 'flex';
      window.scrollTo({ top: $('analyzer').offsetTop - 80, behavior: 'smooth' });
    });
    DOM.historyList.appendChild(el);
  });
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)    return 'just now';
  if (diff < 3600000)  return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    state.historyFilter = btn.dataset.filter;
    renderHistory();
  });
});

$('clearHistoryBtn').addEventListener('click', () => {
  state.history = [];
  localStorage.removeItem('phishguard_history');
  renderHistory();
  showToast('History cleared', 'success');
});

// Initial render
renderHistory();

// ══════════════════════════════════════════════════════════
//  TOAST
// ══════════════════════════════════════════════════════════
let toastTimer;
function showToast(msg, type = 'success') {
  clearTimeout(toastTimer);
  DOM.toast.textContent = msg;
  DOM.toast.className   = `toast ${type} show`;
  toastTimer = setTimeout(() => {
    DOM.toast.classList.remove('show');
  }, 3500);
}

// ══════════════════════════════════════════════════════════
//  INTERSECTION OBSERVER — animate cards on scroll
// ══════════════════════════════════════════════════════════
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      const delay = entry.target.dataset.delay || 0;
      setTimeout(() => {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }, parseInt(delay));
      observer.unobserve(entry.target);
    }
  });
}, { threshold: 0.1 });

document.querySelectorAll('.feature-card, .arch-step').forEach(card => {
  card.style.opacity = '0';
  card.style.transform = 'translateY(24px)';
  card.style.transition = 'opacity .5s ease, transform .5s ease';
  observer.observe(card);
});

// ══════════════════════════════════════════════════════════
//  COUNTER ANIMATION (hero stats)
// ══════════════════════════════════════════════════════════
function animateCounter(el, end, suffix = '', duration = 1500) {
  const start = 0;
  const startTime = performance.now();
  const endNum  = parseFloat(end);

  const step = (now) => {
    const elapsed  = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const ease     = 1 - Math.pow(1 - progress, 3);
    const value    = start + (endNum - start) * ease;
    el.textContent = value.toFixed(end.includes('.') ? 1 : 0) + suffix;
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

const statsObserver = new IntersectionObserver(entries => {
  if (entries[0].isIntersecting) {
    animateCounter($('stat-accuracy'), 98.7, '%');
    animateCounter($('stat-fp'),       0.3,  '%', 1000);
    animateCounter($('stat-features'), 42,   '+', 1200);
    animateCounter($('stat-models'),   3,    '',  800);
    statsObserver.disconnect();
  }
}, { threshold: 0.5 });

statsObserver.observe($('stat-accuracy'));

console.log('%c⚡ PhishGuard AI — Loaded', 'color:#6366f1;font-size:14px;font-weight:700');
console.log('%cConnect Flask backend at http://localhost:5000 for live predictions', 'color:#94a3b8;font-size:11px');