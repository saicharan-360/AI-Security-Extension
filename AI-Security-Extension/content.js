/**
 * AI Security Shield - Content Script
 * Advanced In-Page QR Code Detection, Local Decoding, Real-Time Threat Analysis & Prevention
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if (window.__AI_SHIELD_CONTENT_SCRIPT_INITIALIZED__) return;
  window.__AI_SHIELD_CONTENT_SCRIPT_INITIALIZED__ = true;

  console.log('[AI Shield] Content script active with QR threat protection.');

  // =========================================================================
  // 1. Caches & State
  // =========================================================================
  const scannedElements = new WeakSet();
  const scannedSourcesCache = new Map(); // src/data -> { hasQr: boolean, payload: string|null }
  const payloadAssessmentCache = new Map(); // normalizedUrl/payload -> AssessmentResult
  const activeQrBadges = new Map(); // element -> badgeElement

  let isScanning = false;
  let scanDebounceTimer = null;
  const SCAN_DEBOUNCE_MS = 350;
  const MAX_SCAN_DIMENSION = 600; // Downscale large images to reduce CPU/memory
  const MIN_DIMENSION = 35; // Skip tiny icons/favicons

  // Reusable offscreen canvas for high-performance decoding
  let sharedCanvas = null;
  let sharedCtx = null;

  function getCanvas() {
    if (!sharedCanvas) {
      sharedCanvas = document.createElement('canvas');
      sharedCtx = sharedCanvas.getContext('2d', { willReadFrequently: true });
    }
    return { canvas: sharedCanvas, ctx: sharedCtx };
  }

  // =========================================================================
  // 2. Payload Classification
  // =========================================================================
  function classifyQrPayload(rawPayload) {
    if (!rawPayload || typeof rawPayload !== 'string') {
      return { type: 'TEXT', normalizedValue: '', preview: 'Empty Payload' };
    }

    const trimmed = rawPayload.trim();

    // Web URLs
    if (/^https?:\/\//i.test(trimmed)) {
      return {
        type: 'URL',
        normalizedValue: trimmed,
        preview: trimmed.length > 50 ? trimmed.slice(0, 47) + '...' : trimmed
      };
    }

    // Email
    if (/^mailto:/i.test(trimmed)) {
      const email = trimmed.replace(/^mailto:/i, '').split('?')[0];
      return { type: 'EMAIL', normalizedValue: trimmed, preview: `Email: ${email}` };
    }

    // Phone / SMS
    if (/^tel:/i.test(trimmed)) {
      return { type: 'PHONE', normalizedValue: trimmed, preview: `Call: ${trimmed.replace(/^tel:/i, '')}` };
    }
    if (/^sms:/i.test(trimmed)) {
      return { type: 'SMS', normalizedValue: trimmed, preview: `SMS: ${trimmed.replace(/^sms:/i, '').split('?')[0]}` };
    }

    // WiFi Configuration
    if (/^WIFI:/i.test(trimmed)) {
      const ssidMatch = trimmed.match(/S:([^;]+)/i);
      const ssid = ssidMatch ? ssidMatch[1] : 'Network';
      return { type: 'WIFI', normalizedValue: trimmed, preview: `Wi-Fi Network: ${ssid}` };
    }

    // Cryptocurrency & Payment addresses
    if (/^(bitcoin|ethereum|solana|litecoin|upi|lightning):/i.test(trimmed)) {
      const protocol = trimmed.split(':')[0].toUpperCase();
      return { type: 'CRYPTO_PAYMENT', normalizedValue: trimmed, preview: `${protocol} Payment Address` };
    }

    // App Links / Deep Links
    if (/^[a-zA-Z0-9_.-]+:\/\//i.test(trimmed)) {
      const scheme = trimmed.split('://')[0];
      return { type: 'DEEP_LINK', normalizedValue: trimmed, preview: `${scheme} App Link` };
    }

    // Plain Text / Other
    return {
      type: 'TEXT',
      normalizedValue: trimmed,
      preview: trimmed.length > 40 ? trimmed.slice(0, 37) + '...' : trimmed
    };
  }

  // =========================================================================
  // 3. UI Layer (Shadow DOM Isolation)
  // =========================================================================
  let shadowRoot = null;

  function ensureShadowRoot() {
    if (shadowRoot) return shadowRoot;

    let host = document.getElementById('ai-shield-qr-host');
    if (!host) {
      host = document.createElement('div');
      host.id = 'ai-shield-qr-host';
      host.style.cssText = 'all: initial !important; position: static !important; z-index: 2147483647 !important;';
      document.documentElement.appendChild(host);
    }

    shadowRoot = host.attachShadow({ mode: 'open' });

    // Styles for Badges & Modals
    const style = document.createElement('style');
    style.textContent = `
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      }

      .ai-shield-badge {
        position: absolute;
        z-index: 2147483640;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 5px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.3px;
        cursor: pointer;
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
        transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s;
        user-select: none;
      }
      .ai-shield-badge:hover {
        transform: translateY(-2px) scale(1.04);
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.45);
      }

      .badge-safe {
        background: rgba(16, 185, 129, 0.92);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.4);
      }
      .badge-suspicious {
        background: rgba(245, 158, 11, 0.95);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.4);
      }
      .badge-malicious {
        background: rgba(239, 68, 68, 0.95);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.4);
        animation: pulse 2s infinite;
      }
      .badge-nonurl {
        background: rgba(59, 130, 246, 0.92);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.4);
      }

      @keyframes pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.6); }
        50% { box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
      }

      /* Modal Overlay */
      .ai-shield-overlay {
        position: fixed;
        inset: 0;
        background: rgba(7, 10, 19, 0.85);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
        z-index: 2147483646;
        animation: fadeIn 0.2s ease-out;
      }
      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      .ai-shield-card {
        background: #111827;
        border: 1px solid #374151;
        border-radius: 16px;
        width: 100%;
        max-width: 480px;
        padding: 26px;
        color: #f3f4f6;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
        animation: slideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes slideUp {
        from { opacity: 0; transform: translateY(20px) scale(0.97); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }

      .card-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 16px;
      }
      .card-icon {
        font-size: 28px;
        line-height: 1;
      }
      .card-title {
        font-size: 18px;
        font-weight: 800;
        letter-spacing: -0.2px;
      }
      .title-malicious { color: #f87171; }
      .title-suspicious { color: #fbbf24; }
      .title-safe { color: #34d399; }
      .title-info { color: #60a5fa; }

      .card-desc {
        font-size: 13.5px;
        color: #9ca3af;
        line-height: 1.5;
        margin-bottom: 16px;
      }

      .dest-box {
        background: #1f2937;
        border: 1px solid #374151;
        border-radius: 10px;
        padding: 12px 14px;
        margin-bottom: 16px;
      }
      .dest-label {
        font-size: 11px;
        font-weight: 700;
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 4px;
      }
      .dest-url {
        font-size: 13px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        color: #e5e7eb;
        word-break: break-all;
      }

      .reasons-box {
        background: rgba(239, 68, 68, 0.1);
        border-left: 3px solid #ef4444;
        padding: 10px 14px;
        border-radius: 6px;
        margin-bottom: 20px;
      }
      .reasons-title {
        font-size: 12px;
        font-weight: 700;
        color: #f87171;
        margin-bottom: 6px;
      }
      .reason-item {
        font-size: 12.5px;
        color: #fca5a5;
        margin-bottom: 4px;
        line-height: 1.4;
      }

      .actions {
        display: flex;
        gap: 12px;
        justify-content: flex-end;
      }
      .btn {
        padding: 10px 18px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        border: none;
        transition: all 0.15s ease;
      }
      .btn-primary {
        background: #3b82f6;
        color: #ffffff;
      }
      .btn-primary:hover {
        background: #2563eb;
      }
      .btn-safe-action {
        background: #10b981;
        color: #ffffff;
      }
      .btn-safe-action:hover {
        background: #059669;
      }
      .btn-bypass {
        background: transparent;
        color: #9ca3af;
        border: 1px solid #4b5563;
      }
      .btn-bypass:hover {
        background: rgba(255, 255, 255, 0.05);
        color: #ef4444;
        border-color: #ef4444;
      }
    `;
    shadowRoot.appendChild(style);
    return shadowRoot;
  }

  // =========================================================================
  // 4. Modal Display Logic
  // =========================================================================
  function showModal(details) {
    const root = ensureShadowRoot();

    // Remove any existing modal
    const existing = root.querySelector('.ai-shield-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.className = 'ai-shield-overlay';

    const isMalicious = details.verdict === 'HIGH_RISK';
    const isSuspicious = details.verdict === 'SUSPICIOUS';
    const isSafe = details.verdict === 'SAFE';

    let icon = '🛡️';
    let titleClass = 'title-info';
    let titleText = 'QR CODE DETECTED';
    let description = 'Information about the detected QR code payload.';

    if (isMalicious) {
      icon = '🚨';
      titleClass = 'title-malicious';
      titleText = 'QR CODE BLOCKED';
      description = 'This QR code leads to a confirmed high-risk destination. Navigation has been automatically blocked to protect your credentials and device.';
    } else if (isSuspicious) {
      icon = '⚠️';
      titleClass = 'title-suspicious';
      titleText = 'DANGEROUS QR CODE';
      description = 'This QR code points to an unverified or suspicious destination. Proceed with caution.';
    } else if (isSafe) {
      icon = '🟢';
      titleClass = 'title-safe';
      titleText = 'SAFE QR CODE';
      description = 'This QR code has been verified by the AI Security Shield defense engine.';
    }

    const reasonsHtml = (details.reasons && details.reasons.length > 0)
      ? `
        <div class="reasons-box">
          <div class="reasons-title">Detected Indicators:</div>
          ${details.reasons.slice(0, 4).map(r => `<div class="reason-item">• ${escapeHtml(r)}</div>`).join('')}
        </div>
      `
      : '';

    let buttonsHtml = '';
    if (isMalicious) {
      buttonsHtml = `
        <button class="btn btn-primary" id="btn-stay-safe">Go Back (Stay Safe)</button>
        <button class="btn btn-bypass" id="btn-proceed-bypass">Proceed Anyway</button>
      `;
    } else if (isSuspicious) {
      buttonsHtml = `
        <button class="btn btn-primary" id="btn-close-modal">Go Back</button>
        <button class="btn btn-bypass" id="btn-view-dest">View Destination</button>
      `;
    } else if (details.payloadType === 'URL') {
      buttonsHtml = `
        <button class="btn btn-safe-action" id="btn-visit-safe">Open Website</button>
        <button class="btn btn-bypass" id="btn-close-modal">Close</button>
      `;
    } else {
      buttonsHtml = `
        <button class="btn btn-primary" id="btn-close-modal">Done</button>
      `;
    }

    overlay.innerHTML = `
      <div class="ai-shield-card">
        <div class="card-header">
          <div class="card-icon">${icon}</div>
          <div class="card-title ${titleClass}">${titleText}</div>
        </div>
        <div class="card-desc">${description}</div>
        <div class="dest-box">
          <div class="dest-label">Payload (${escapeHtml(details.payloadType || 'URL')}):</div>
          <div class="dest-url">${escapeHtml(details.destination || details.preview || 'N/A')}</div>
        </div>
        ${reasonsHtml}
        <div class="actions">
          ${buttonsHtml}
        </div>
      </div>
    `;

    root.appendChild(overlay);

    // Event listeners inside Shadow DOM
    const closeBtn = overlay.querySelector('#btn-close-modal');
    if (closeBtn) closeBtn.onclick = () => overlay.remove();

    const staySafeBtn = overlay.querySelector('#btn-stay-safe');
    if (staySafeBtn) staySafeBtn.onclick = () => overlay.remove();

    const visitSafeBtn = overlay.querySelector('#btn-visit-safe');
    if (visitSafeBtn) {
      visitSafeBtn.onclick = () => {
        window.open(details.destination, '_blank', 'noopener,noreferrer');
        overlay.remove();
      };
    }

    const viewDestBtn = overlay.querySelector('#btn-view-dest');
    if (viewDestBtn) {
      viewDestBtn.onclick = () => {
        if (confirm(`⚠️ Warning: This destination was flagged as suspicious.\n\nURL: ${details.destination}\n\nDo you want to proceed?`)) {
          window.open(details.destination, '_blank', 'noopener,noreferrer');
          overlay.remove();
        }
      };
    }

    const bypassBtn = overlay.querySelector('#btn-proceed-bypass');
    if (bypassBtn) {
      bypassBtn.onclick = () => {
        if (confirm(`🚨 CRITICAL SECURITY WARNING:\n\nYou are about to bypass protection to visit a high-risk destination:\n${details.destination}\n\nThis site may attempt to steal passwords or compromise your system. Proceed anyway?`)) {
          window.location.href = details.destination;
          overlay.remove();
        }
      };
    }

    // Close on overlay backdrop click if safe
    if (!isMalicious) {
      overlay.onclick = (e) => {
        if (e.target === overlay) overlay.remove();
      };
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // =========================================================================
  // 5. Badge Rendering on QR Elements
  // =========================================================================
  function attachSecurityBadge(element, assessment) {
    if (activeQrBadges.has(element)) return;

    const root = ensureShadowRoot();
    const badge = document.createElement('div');
    activeQrBadges.set(element, badge);

    const isMalicious = assessment.verdict === 'HIGH_RISK';
    const isSuspicious = assessment.verdict === 'SUSPICIOUS';
    const isSafe = assessment.verdict === 'SAFE';

    let badgeClass = 'badge-nonurl';
    let icon = 'ℹ️';
    let label = 'QR Content';

    if (assessment.payloadType === 'URL') {
      if (isMalicious) {
        badgeClass = 'badge-malicious';
        icon = '🔴';
        label = 'Malicious QR';
      } else if (isSuspicious) {
        badgeClass = 'badge-suspicious';
        icon = '🟡';
        label = 'Suspicious QR';
      } else {
        badgeClass = 'badge-safe';
        icon = '🟢';
        label = 'Safe QR';
      }
    } else {
      label = `QR: ${assessment.payloadType}`;
    }

    badge.className = `ai-shield-badge ${badgeClass}`;
    badge.innerHTML = `<span>${icon}</span><span>${label}</span>`;
    badge.title = `AI Security Shield: Click to inspect (${assessment.destination || assessment.preview})`;

    // Position updating
    function updateBadgePosition() {
      const rect = element.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return;

      const top = rect.top + window.scrollY + 6;
      const left = rect.left + window.scrollX + 6;

      badge.style.top = `${top}px`;
      badge.style.left = `${left}px`;
    }

    updateBadgePosition();
    root.appendChild(badge);

    // Keep badge aligned with scrolling/resizing
    window.addEventListener('scroll', updateBadgePosition, { passive: true });
    window.addEventListener('resize', updateBadgePosition, { passive: true });

    // Open detail modal when clicking badge
    badge.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      showModal(assessment);
    };

    // Block or intercept interactions with the QR code element
    if (isMalicious || isSuspicious) {
      // Intercept clicks on the element and any wrapping link
      const interceptHandler = (e) => {
        e.preventDefault();
        e.stopPropagation();
        showModal(assessment);
      };

      element.addEventListener('click', interceptHandler, true);
      const parentLink = element.closest('a');
      if (parentLink) {
        parentLink.addEventListener('click', interceptHandler, true);
      }
    }
  }

  // =========================================================================
  // 6. Local QR Decoding with jsQR
  // =========================================================================
  async function decodeElement(element) {
    if (!window.jsQR) {
      console.warn('[AI Shield] jsQR library not yet available in content context.');
      return null;
    }

    const { canvas, ctx } = getCanvas();

    try {
      let width = 0;
      let height = 0;

      if (element.tagName === 'IMG') {
        if (!element.complete || element.naturalWidth === 0) return null;
        width = element.naturalWidth;
        height = element.naturalHeight;
      } else if (element.tagName === 'CANVAS') {
        width = element.width;
        height = element.height;
      } else {
        return null;
      }

      // Filter out tiny elements or non-square aspect ratios
      if (width < MIN_DIMENSION || height < MIN_DIMENSION) return null;
      const aspectDiff = Math.abs(width - height) / Math.max(width, height);
      if (aspectDiff > 0.35) return null; // QR codes are square

      // Downscale to max dimension to optimize CPU & memory
      let renderWidth = width;
      let renderHeight = height;
      if (renderWidth > MAX_SCAN_DIMENSION || renderHeight > MAX_SCAN_DIMENSION) {
        const scale = Math.min(MAX_SCAN_DIMENSION / renderWidth, MAX_SCAN_DIMENSION / renderHeight);
        renderWidth = Math.round(renderWidth * scale);
        renderHeight = Math.round(renderHeight * scale);
      }

      canvas.width = renderWidth;
      canvas.height = renderHeight;
      ctx.clearRect(0, 0, renderWidth, renderHeight);

      // Draw element
      ctx.drawImage(element, 0, 0, renderWidth, renderHeight);

      // Extract raw image data
      const imageData = ctx.getImageData(0, 0, renderWidth, renderHeight);
      const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'attemptBoth'
      });

      if (code && code.data && code.data.trim()) {
        return code.data.trim();
      }
      return null;
    } catch (err) {
      // Tainted cross-origin canvas or render error handled gracefully
      return null;
    }
  }

  // =========================================================================
  // 7. Analysis & Verification Workflow
  // =========================================================================
  async function processCandidate(element) {
    if (scannedElements.has(element)) return;
    scannedElements.add(element);

    const src = element.currentSrc || element.src || '';
    let rawPayload = null;

    if (src && scannedSourcesCache.has(src)) {
      rawPayload = scannedSourcesCache.get(src);
    } else {
      rawPayload = await decodeElement(element);
      if (src) {
        scannedSourcesCache.set(src, rawPayload);
      }
    }

    if (!rawPayload) return;

    const payload = classifyQrPayload(rawPayload);
    const cacheKey = payload.normalizedValue;

    // Check payload assessment cache
    if (payloadAssessmentCache.has(cacheKey)) {
      const cached = payloadAssessmentCache.get(cacheKey);
      attachSecurityBadge(element, cached);
      return;
    }

    if (payload.type !== 'URL') {
      const nonUrlAssessment = {
        verdict: 'SAFE',
        riskScore: 0.0,
        confidence: 1.0,
        payloadType: payload.type,
        destination: payload.normalizedValue,
        preview: payload.preview,
        reasons: [`Decoded ${payload.type} data. No web navigation risk.`]
      };
      payloadAssessmentCache.set(cacheKey, nonUrlAssessment);
      attachSecurityBadge(element, nonUrlAssessment);
      return;
    }

    // Send to background service worker for layered security analysis
    try {
      chrome.runtime.sendMessage(
        {
          action: 'ANALYZE_QR_URL',
          url: payload.normalizedValue,
          payloadType: 'URL'
        },
        (response) => {
          if (chrome.runtime.lastError || !response) {
            console.warn('[AI Shield] Background analysis error:', chrome.runtime.lastError?.message);
            return;
          }

          const assessment = {
            verdict: response.verdict || 'UNKNOWN',
            riskScore: response.riskScore ?? 0.5,
            confidence: response.confidence ?? 0.0,
            payloadType: 'URL',
            destination: response.destination || payload.normalizedValue,
            hostname: response.hostname || '',
            reasons: response.reasons || [],
            summary: response.summary || ''
          };

          payloadAssessmentCache.set(cacheKey, assessment);
          attachSecurityBadge(element, assessment);
        }
      );
    } catch (err) {
      console.warn('[AI Shield] Extension messaging error:', err.message);
    }
  }

  // =========================================================================
  // 8. Scanning Loop & MutationObserver (Optimized for Mobile/Battery)
  // =========================================================================
  function scanPageImages() {
    // If tab is inactive or hidden, save CPU & battery
    if (document.hidden) return;

    const candidates = Array.from(document.querySelectorAll('img, canvas'));
    for (const el of candidates) {
      if (!scannedElements.has(el)) {
        processCandidate(el);
      }
    }
  }

  function scheduleScan() {
    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      if ('requestIdleCallback' in window) {
        window.requestIdleCallback(() => scanPageImages());
      } else {
        scanPageImages();
      }
    }, SCAN_DEBOUNCE_MS);
  }

  // Observe dynamically added images
  const observer = new MutationObserver((mutations) => {
    if (document.hidden) return;
    let shouldScan = false;

    for (const m of mutations) {
      if (m.addedNodes.length > 0) {
        for (const node of m.addedNodes) {
          if (node.nodeType === 1) {
            if (node.tagName === 'IMG' || node.tagName === 'CANVAS' || node.querySelector?.('img, canvas')) {
              shouldScan = true;
              break;
            }
          }
        }
      }
      if (shouldScan) break;
    }

    if (shouldScan) {
      scheduleScan();
    }
  });

  observer.observe(document.documentElement || document.body, {
    childList: true,
    subtree: true
  });

  // Pause on hidden, resume on visible
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      scheduleScan();
    }
  });

  // Initial scan after DOM settles
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scheduleScan);
  } else {
    scheduleScan();
  }
})();
