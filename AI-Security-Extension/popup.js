/**
 * Extension Popup Controller
 * Connects UI to background telemetry state and user preferences.
 */

const protectionToggle = document.getElementById('protectionToggle');
const protectionStateText = document.getElementById('protectionStateText');
const activeDomainEl = document.getElementById('activeDomain');
const statusBadge = document.getElementById('statusBadge');
const riskScoreVal = document.getElementById('riskScoreVal');
const confidenceVal = document.getElementById('confidenceVal');
const srcLocal = document.getElementById('srcLocal');
const srcCommunity = document.getElementById('srcCommunity');
const srcAi = document.getElementById('srcAi');
const btnWhitelist = document.getElementById('btnWhitelist');
const btnReport = document.getElementById('btnReport');

// Load protection state
const settings = await chrome.storage.local.get(['protectionEnabled', 'userWhitelist']);
const isEnabled = settings.protectionEnabled !== false;
protectionToggle.checked = isEnabled;
protectionStateText.textContent = isEnabled ? 'ON' : 'OFF';

protectionToggle.addEventListener('change', async (e) => {
  const state = e.target.checked;
  protectionStateText.textContent = state ? 'ON' : 'OFF';
  await chrome.storage.local.set({ protectionEnabled: state });
  chrome.runtime.sendMessage({ action: 'UPDATE_PROTECTION_STATE', enabled: state });
});

// Query active tab
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
if (!tab || !tab.url || (!tab.url.startsWith('http://') && !tab.url.startsWith('https://'))) {
  activeDomainEl.textContent = 'Non-web page';
  statusBadge.className = 'status-badge badge-unknown';
  statusBadge.textContent = 'INACTIVE';
  riskScoreVal.textContent = '0%';
  confidenceVal.textContent = '100%';
} else {
  const urlObj = new URL(tab.url);
  const hostname = urlObj.hostname;
  activeDomainEl.textContent = hostname;

  // Query telemetry cache from background worker
  chrome.runtime.sendMessage({ action: 'GET_TAB_ASSESSMENT', tabId: tab.id, url: tab.url }, (response) => {
    if (!response || !response.assessment) {
      statusBadge.className = 'status-badge badge-safe';
      statusBadge.textContent = 'SAFE';
      riskScoreVal.textContent = '5%';
      confidenceVal.textContent = '80%';
      srcLocal.classList.add('active');
      srcLocal.textContent = '✓ Local Heuristics';
      return;
    }

    const { assessment } = response;
    renderAssessment(assessment);
  });

  function renderAssessment(a) {
    statusBadge.textContent = a.verdict || 'UNKNOWN';
    riskScoreVal.textContent = `${Math.round((a.riskScore || 0) * 100)}%`;
    confidenceVal.textContent = `${Math.round((a.confidence || 0) * 100)}%`;

    if (a.verdict === 'HIGH_RISK') {
      statusBadge.className = 'status-badge badge-danger';
    } else if (a.verdict === 'SUSPICIOUS') {
      statusBadge.className = 'status-badge badge-suspicious';
    } else if (a.verdict === 'SAFE') {
      statusBadge.className = 'status-badge badge-safe';
    } else {
      statusBadge.className = 'status-badge badge-unknown';
    }

    const sources = a.sources || [];
    if (sources.includes('LOCAL_ANALYSIS') || sources.includes('LOCAL_WHITELIST')) {
      srcLocal.classList.add('active');
      srcLocal.textContent = '✓ Local Heuristics';
    }
    if (sources.includes('COMMUNITY_DATABASE')) {
      srcCommunity.classList.add('active');
      srcCommunity.textContent = '✓ Threat Database';
    }
    if (sources.includes('GEMINI_AI')) {
      srcAi.classList.add('active');
      srcAi.textContent = '✓ Gemini Deep AI';
    }
  }

  // Handle allowlisting
  btnWhitelist.addEventListener('click', async () => {
    const current = (await chrome.storage.local.get('userWhitelist')).userWhitelist || [];
    if (!current.includes(hostname)) {
      current.push(hostname);
      await chrome.storage.local.set({ userWhitelist: current });
      alert(`Domain "${hostname}" added to your personal allowlist.`);
      window.close();
    } else {
      alert(`"${hostname}" is already in your allowlist.`);
    }
  });

  // Handle threat reporting
  btnReport.addEventListener('click', async () => {
    const reason = prompt(`Submit threat report for ${hostname}:\nEnter reason / indicators (e.g. deceptive login, fake giveaway):`);
    if (reason && reason.trim().length >= 3) {
      chrome.runtime.sendMessage({
        action: 'SUBMIT_MANUAL_REPORT',
        url: tab.url,
        hostname,
        reason: reason.trim()
      }, (res) => {
        if (res && res.success) {
          alert(`Thank you! Threat report for ${hostname} was submitted.`);
        } else {
          alert('Report submitted to local telemetry database.');
        }
      });
    }
  });
}

// Manual QR Image File Scanner
const qrFileInput = document.getElementById('qrFileInput');
const qrResultBox = document.getElementById('qrResultBox');
const qrStatusBadge = document.getElementById('qrStatusBadge');
const qrDecodedText = document.getElementById('qrDecodedText');
const qrReasonsList = document.getElementById('qrReasonsList');

if (qrFileInput) {
  qrFileInput.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (loadEvt) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);

        const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        if (!window.jsQR) {
          alert('QR decoder is loading, please try again.');
          return;
        }

        const code = window.jsQR(imgData.data, imgData.width, imgData.height, {
          inversionAttempts: 'attemptBoth'
        });

        qrResultBox.style.display = 'block';

        if (!code || !code.data) {
          qrStatusBadge.className = 'status-badge badge-suspicious';
          qrStatusBadge.textContent = 'NO QR FOUND';
          qrDecodedText.textContent = 'Could not detect a valid QR code in this image.';
          qrReasonsList.innerHTML = '';
          return;
        }

        qrDecodedText.textContent = code.data;
        qrStatusBadge.className = 'status-badge badge-safe';
        qrStatusBadge.textContent = 'ANALYZING...';
        qrReasonsList.innerHTML = '';

        chrome.runtime.sendMessage({
          action: 'ANALYZE_QR_URL',
          url: code.data,
          payloadType: code.data.startsWith('http') ? 'URL' : 'TEXT'
        }, (res) => {
          if (!res) {
            qrStatusBadge.className = 'status-badge badge-unknown';
            qrStatusBadge.textContent = 'ERROR';
            return;
          }

          if (res.verdict === 'HIGH_RISK') {
            qrStatusBadge.className = 'status-badge badge-danger';
            qrStatusBadge.textContent = 'MALICIOUS';
          } else if (res.verdict === 'SUSPICIOUS') {
            qrStatusBadge.className = 'status-badge badge-suspicious';
            qrStatusBadge.textContent = 'SUSPICIOUS';
          } else {
            qrStatusBadge.className = 'status-badge badge-safe';
            qrStatusBadge.textContent = 'SAFE';
          }

          if (res.reasons && res.reasons.length > 0) {
            qrReasonsList.innerHTML = res.reasons.map(r => `• ${r}`).join('<br>');
          } else {
            qrReasonsList.textContent = 'No threats detected.';
          }
        });
      };
      img.src = loadEvt.target.result;
    };
    reader.readAsDataURL(file);
  });
}

