const DEFAULT_BACKEND_URL = '';
const BRAND_DOMAINS = ['microsoft.com', 'paypal.com', 'docusign.com', 'amazon.com', 'google.com', 'apple.com', 'netflix.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'dropbox.com'];

let backendUrl = DEFAULT_BACKEND_URL;
let lastSignature = null;
let currentEmail = null;
let root = null;
let showTechnical = false;

chrome.storage.local.get(['backendUrl'], (data) => {
  if (data.backendUrl) backendUrl = data.backendUrl.replace(/\/+$/, '');
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.backendUrl) {
    backendUrl = (changes.backendUrl.newValue || '').replace(/\/+$/, '');
  }
});

function ensurePanel() {
  if (root) return root;
  root = document.createElement('div');
  root.id = 'phishguard-root';
  root.className = 'phg-hidden';
  root.innerHTML = `
    <div class="phg-header">
      <div class="phg-topbar">
        <div>
          <h2>PhishGuard</h2>
          <div class="phg-subtitle">Email threat analysis with header parsing</div>
        </div>
        <button id="phg-refresh" class="phg-btn">Refresh</button>
      </div>
    </div>
    <div id="phg-content" class="phg-loading">Open an email to analyze it.</div>
  `;
  document.body.appendChild(root);
  root.querySelector('#phg-refresh').addEventListener('click', () => {
    if (currentEmail) analyzeAndRender(currentEmail, true);
  });
  return root;
}

function showPanel() {
  ensurePanel().classList.remove('phg-hidden');
}

function setContent(html) {
  ensurePanel().querySelector('#phg-content').innerHTML = html;
  const toggleBtn = ensurePanel().querySelector('#phg-toggle-details');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      showTechnical = !showTechnical;
      const section = ensurePanel().querySelector('#phg-details-section');
      if (section) section.style.display = showTechnical ? 'block' : 'none';
      toggleBtn.textContent = showTechnical ? 'Hide technical details' : 'Show technical details';
    });
  }
}

function textOrEmpty(el) {
  return (el?.innerText || el?.textContent || '').trim();
}

function extractLinks(emailBodyNode) {
  const anchors = [...(emailBodyNode?.querySelectorAll('a') || [])];
  return anchors.map((a) => ({
    text: textOrEmpty(a).slice(0, 120),
    href: a.href || ''
  })).filter((x) => x.href);
}

function collectEmailFromGmail() {
  const subjectNode = document.querySelector('h2[data-thread-perm-id]') || document.querySelector('h2.hP');
  const bodyNode = document.querySelector('div[role="listitem"] div.a3s') || document.querySelector('div.a3s');
  const fromNode = document.querySelector('span[email]');
  const fromEmail = fromNode?.getAttribute('email') || '';
  const fromName = textOrEmpty(document.querySelector('span.gD')) || fromEmail;
  const snippet = textOrEmpty(bodyNode).slice(0, 8000);
  const subject = textOrEmpty(subjectNode);
  const links = extractLinks(bodyNode);
  const attachments = [...document.querySelectorAll('div[download_url]')].map((el) => {
    const raw = el.getAttribute('download_url') || '';
    const parts = raw.split(':');
    return { filename: parts[1] || 'attachment' };
  });

  if (!subject && !snippet && !fromEmail) return null;

  return {
    source: 'gmail-web',
    subject,
    fromName,
    fromEmail,
    replyTo: '',
    returnPath: '',
    rawHeaders: '',
    bodyText: snippet,
    links,
    attachments,
    observedBrandDomains: BRAND_DOMAINS.filter((d) => snippet.toLowerCase().includes(d.split('.')[0]))
  };
}

function escapeHtml(str) {
  return (str || '').replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

function scoreClass(score) {
  if (score >= 75) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

function renderImpersonation(result) {
  if (!result.impersonation || !result.impersonation.detected) return '';
  const imp = result.impersonation;
  const methodLabel = {
    'typosquatting': 'Typosquatting (Levenshtein distance)',
    'homoglyph': 'Look-alike characters (homoglyph)',
    'brand-in-subdomain': 'Brand name in fake domain',
    'keyword-match': 'Brand keyword in domain',
  }[imp.method] || imp.method;

  return `
    <div class="phg-section phg-alert-red">
      <h3 style="color:#ef4444;">Domain Impersonation Detected</h3>
      <p style="font-size:13px;">This sender appears to impersonate <strong>${escapeHtml(imp.impersonatedBrand)}</strong></p>
      <p style="font-size:11px;color:#94a3b8;margin-top:4px;">Detection: ${escapeHtml(methodLabel)}</p>
    </div>
  `;
}

function renderTimeAnomaly(result) {
  if (!result.timeAnomaly || !result.timeAnomaly.anomalyType) return '';
  const ta = result.timeAnomaly;
  return `
    <div class="phg-section phg-alert-orange">
      <h3 style="color:#f97316;">Unusual Send Time</h3>
      <p style="font-size:13px;">Sent on ${escapeHtml(ta.sendDay || '')} at ${ta.sendHour}:00 UTC</p>
      <p style="font-size:11px;color:#94a3b8;margin-top:4px;">${ta.anomalyType === 'weekend-night' ? 'Weekend late-night emails are a common phishing pattern' : 'Unusual send times may indicate automated phishing campaigns'}</p>
    </div>
  `;
}

function renderTfidf(result) {
  if (!result.tfidfAnalysis || !result.tfidfAnalysis.totalTermsMatched) return '';
  const ta = result.tfidfAnalysis;
  const barColor = ta.phishingScore >= 50 ? '#ef4444' : ta.phishingScore >= 25 ? '#f97316' : '#10b981';
  const terms = (ta.topTerms || []).map((t) =>
    `<span class="phg-tfidf-tag">${escapeHtml(t.term)} <span style="color:#94a3b8">${t.tfidf.toFixed(3)}</span></span>`
  ).join('');

  return `
    <div class="phg-section">
      <h3>TF-IDF Text Analysis</h3>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <span style="font-size:11px;color:#94a3b8;">Phishing Language Score</span>
        <span style="font-weight:600;color:${barColor}">${ta.phishingScore}/100</span>
      </div>
      <div style="width:100%;background:#334155;border-radius:4px;height:6px;margin-bottom:10px;">
        <div style="width:${Math.min(ta.phishingScore, 100)}%;background:${barColor};height:6px;border-radius:4px;transition:width 0.3s;"></div>
      </div>
      ${terms ? `<div style="margin-bottom:8px;font-size:11px;color:#94a3b8;">Top indicators by TF-IDF weight</div><div class="phg-tfidf-tags">${terms}</div>` : ''}
      <div style="font-size:11px;color:#94a3b8;margin-top:6px;">${ta.totalTermsMatched} phishing-related term${ta.totalTermsMatched !== 1 ? 's' : ''} detected</div>
    </div>
  `;
}

function renderResult(result) {
  const sc = scoreClass(result.riskScore);
  const reasons = (result.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('');
  const userActions = (result.userActions || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('');

  let authSection = '';
  if (result.headerAnalysis && result.headerAnalysis.headersParsed) {
    const ha = result.headerAnalysis;
    authSection = `
      <div class="phg-section">
        <h3>Authentication</h3>
        <div class="phg-auth-grid">
          <div class="phg-auth-item">
            <div class="phg-auth-label">SPF</div>
            <div class="phg-auth-status ${ha.spf.status}">${escapeHtml(ha.spf.status)}</div>
          </div>
          <div class="phg-auth-item">
            <div class="phg-auth-label">DKIM</div>
            <div class="phg-auth-status ${ha.dkim.status}">${escapeHtml(ha.dkim.status)}</div>
          </div>
          <div class="phg-auth-item">
            <div class="phg-auth-label">DMARC</div>
            <div class="phg-auth-status ${ha.dmarc.status}">${escapeHtml(ha.dmarc.status)}</div>
          </div>
        </div>
        <div style="margin-top:6px;font-size:11px;color:#94a3b8;">
          ${ha.receivedHops} server hop${ha.receivedHops !== 1 ? 's' : ''} detected
        </div>
      </div>
    `;
  }

  const techEntries = Object.entries(result.technicalDetails || {}).map(([k, v]) => (
    `<div class="phg-keyval"><span class="phg-key">${escapeHtml(k)}</span><span class="phg-val">${escapeHtml(String(v))}</span></div>`
  )).join('');

  setContent(`
    <div class="phg-section">
      <div class="phg-score-wrap">
        <div class="phg-score-circle ${sc}">${result.riskScore}</div>
        <div class="phg-score-info">
          <div class="phg-verdict">${escapeHtml(result.verdict)}</div>
          <div class="phg-confidence">${escapeHtml(result.confidence)} confidence</div>
        </div>
      </div>
    </div>

    ${renderImpersonation(result)}

    ${renderTimeAnomaly(result)}

    ${authSection}

    ${renderTfidf(result)}

    <div class="phg-section">
      <h3>Findings</h3>
      <ul class="phg-list warnings">${reasons || '<li>No strong phishing indicators were found.</li>'}</ul>
    </div>

    <div class="phg-section">
      <h3>Recommended Actions</h3>
      <ul class="phg-list actions">${userActions}</ul>
    </div>

    <button class="phg-toggle-btn" id="phg-toggle-details">Show technical details</button>
    <div id="phg-details-section" style="display:none;">
      <div class="phg-section">
        <h3>Technical Details</h3>
        <div class="phg-grid">${techEntries}</div>
      </div>
    </div>
  `);
}

async function analyzeAndRender(email, force) {
  const signature = JSON.stringify({ subject: email.subject, fromEmail: email.fromEmail, bodyText: (email.bodyText || '').slice(0, 500) });
  if (!force && signature === lastSignature) return;
  lastSignature = signature;
  currentEmail = email;
  showPanel();
  setContent('<div class="phg-loading"><span class="phg-spinner"></span>Analyzing email...</div>');

  if (!backendUrl) {
    setContent(`
      <div class="phg-error">
        <strong>Backend URL not configured.</strong><br><br>
        Click the PhishGuard extension icon and set your backend URL in the popup settings.
      </div>
    `);
    return;
  }

  try {
    const res = await fetch(backendUrl + '/api/analyze-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email)
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || 'Backend error');
    }

    const result = await res.json();
    renderResult(result);
  } catch (err) {
    setContent(`
      <div class="phg-error">
        <strong>Could not analyze the email.</strong><br><br>
        ${escapeHtml(err.message)}<br><br>
        Check that the backend is running at:<br>
        <code style="font-size:11px;background:#f1f5f9;padding:2px 6px;border-radius:4px;">${escapeHtml(backendUrl)}</code>
      </div>
    `);
  }
}

function pollForEmail() {
  ensurePanel();
  const email = collectEmailFromGmail();
  if (email) analyzeAndRender(email, false);
}

setInterval(pollForEmail, 2500);
window.addEventListener('load', pollForEmail);
