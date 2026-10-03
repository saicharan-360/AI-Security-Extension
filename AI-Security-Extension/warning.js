/**
 * Warning Interstitial Script
 * Isolates user controls from malicious target site DOM.
 */

document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url') || '';
  const domain = urlParams.get('domain') || (targetUrl ? new URL(targetUrl).hostname : 'Unknown');
  const risk = urlParams.get('risk') || 'HIGH_RISK';
  const confidence = urlParams.get('confidence') || '90%';
  const reasonsRaw = urlParams.get('reasons') || 'Deceptive characteristics detected.';

  document.getElementById('targetDomain').textContent = domain;
  document.getElementById('riskLevel').textContent = risk;
  document.getElementById('confidenceScore').textContent = confidence;

  const reasonsList = document.getElementById('reasonsList');
  reasonsList.innerHTML = '';

  const reasons = reasonsRaw.split('|').filter(Boolean);
  if (reasons.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'Site exhibits patterns matching credential harvesting or brand deception.';
    reasonsList.appendChild(li);
  } else {
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsList.appendChild(li);
    });
  }

  // Action Handlers
  document.getElementById('btnGoBack').addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://google.com';
    }
  });

  document.getElementById('btnCloseTab').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'CLOSE_CURRENT_TAB' });
  });

  document.getElementById('btnProceed').addEventListener('click', () => {
    const confirmed = window.confirm(
      `SECURITY WARNING:\n\nAre you sure you want to proceed to ${domain}?\n\nThis website has been flagged as dangerous and may steal passwords, financial credentials, or install malicious software.`
    );

    if (confirmed && targetUrl) {
      chrome.runtime.sendMessage({
        action: 'TEMPORARY_BYPASS_URL',
        url: targetUrl,
        domain
      }, () => {
        window.location.href = targetUrl;
      });
    }
  });
});
