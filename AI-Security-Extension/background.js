/**
 * Background Service Worker - AI Security Shield
 * Manifest V3 Module
 */

import { CONFIG } from './config.js';
import { DecisionEngine } from './detection/decision_engine.js';
import { reportThreatToCommunity, signalLocalNetworkBlocker, Logger } from './services/api.js';

// In-Memory Assessment Cache: domain -> { decision, expiresAt }
const assessmentCache = new Map();

// Tab Debounce Tracker: tabId -> debounceTimeout
const pendingTabChecks = new Map();

// Temporary User Bypasses (for "Proceed Anyway" overrides): hostname -> expiresAt
const temporaryBypasses = new Map();

/**
 * Checks if URL is an inspectable web resource.
 */
function isInspectableUrl(url) {
  if (!url || typeof url !== 'string') return false;
  return url.startsWith('http://') || url.startsWith('https://');
}

/**
 * Normalizes domain for cache lookup.
 */
function getCacheKey(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

/**
 * Cleans expired entries from cache.
 */
function purgeExpiredCache() {
  const now = Date.now();
  for (const [key, val] of assessmentCache.entries()) {
    if (val.expiresAt <= now) {
      assessmentCache.delete(key);
    }
  }
  for (const [host, expiry] of temporaryBypasses.entries()) {
    if (expiry <= now) {
      temporaryBypasses.delete(host);
    }
  }
}

/**
 * Main URL processing workflow with debouncing, caching, and layered defense.
 */
async function inspectTabNavigation(tabId, url) {
  if (!isInspectableUrl(url)) return;

  // Check protection toggle
  const settings = await chrome.storage.local.get(['protectionEnabled', 'userWhitelist']);
  if (settings.protectionEnabled === false) {
    Logger.log('URL_CHECK', 'Protection currently paused by user.');
    return;
  }

  const hostname = new URL(url).hostname.toLowerCase();

  // Check user whitelist
  const userWhitelist = settings.userWhitelist || [];
  if (userWhitelist.includes(hostname)) {
    Logger.log('URL_CHECK', `Domain ${hostname} is in user allowlist.`);
    return;
  }

  // Check temporary bypass (user clicked "Proceed Anyway" on warning page)
  purgeExpiredCache();
  if (temporaryBypasses.has(hostname)) {
    Logger.log('URL_CHECK', `Domain ${hostname} has active user bypass.`);
    return;
  }

  // Check in-memory cache
  const cacheKey = getCacheKey(url);
  let decision = null;
  const cached = assessmentCache.get(cacheKey);

  if (cached && cached.expiresAt > Date.now()) {
    Logger.log('URL_CHECK', `Using cached assessment for ${hostname}: ${cached.decision.verdict}`);
    decision = cached.decision;
  } else {
    // Execute complete multi-layer pipeline
    decision = await DecisionEngine.evaluateUrl(url);

    // Cache the result
    assessmentCache.set(cacheKey, {
      decision,
      expiresAt: Date.now() + CONFIG.cacheTtlMs
    });
  }

  // Execute mitigation actions if HIGH_RISK
  if (decision.verdict === 'HIGH_RISK') {
    Logger.log('DECISION', `Mitigation triggered for HIGH_RISK domain: ${hostname}`);

    // 1. Report threat to backend community database (fire and forget / async)
    reportThreatToCommunity(url, decision).catch((err) => {
      Logger.warn('REPORT', `Community report error: ${err.message}`);
    });

    // 2. Attempt local OS firewall blocking (fails gracefully if offline)
    signalLocalNetworkBlocker(hostname).catch((err) => {
      Logger.warn('BLOCK', `Firewall blocker notice: ${err.message}`);
    });

    // 3. Isolated Warning Interstitial (Prevents malicious site script execution)
    const warningUrl = chrome.runtime.getURL('warning.html') +
      `?url=${encodeURIComponent(url)}` +
      `&domain=${encodeURIComponent(hostname)}` +
      `&risk=${encodeURIComponent(decision.verdict)}` +
      `&confidence=${encodeURIComponent(Math.round(decision.confidence * 100) + '%')}` +
      `&reasons=${encodeURIComponent((decision.reasons || []).slice(0, 4).join('|'))}`;

    try {
      await chrome.tabs.update(tabId, { url: warningUrl });
      Logger.log('BLOCK', `Tab ${tabId} redirected to secure warning interstitial.`);
    } catch (err) {
      Logger.error('BLOCK', `Failed to redirect tab to warning: ${err.message}`);
    }
  }
}

/**
 * Tab listener with debounce to prevent duplicate processing.
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only process when URL is finalized or completed
  const targetUrl = changeInfo.url || (changeInfo.status === 'complete' ? tab.url : null);
  if (!targetUrl || !isInspectableUrl(targetUrl)) return;

  // Don't inspect our own extension warning or popup pages
  if (targetUrl.startsWith(chrome.runtime.getURL(''))) return;

  // Debounce rapid tab updates
  if (pendingTabChecks.has(tabId)) {
    clearTimeout(pendingTabChecks.get(tabId));
  }

  const timeoutId = setTimeout(() => {
    pendingTabChecks.delete(tabId);
    inspectTabNavigation(tabId, targetUrl).catch((err) => {
      Logger.error('ERROR', `Error processing tab navigation: ${err.message}`);
    });
  }, CONFIG.debounceDelayMs);

  pendingTabChecks.set(tabId, timeoutId);
});

/**
 * Message dispatcher for popup and warning page communication.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) return false;

  switch (message.action) {
    case 'GET_TAB_ASSESSMENT': {
      const cacheKey = message.url ? getCacheKey(message.url) : '';
      const cached = assessmentCache.get(cacheKey);
      sendResponse({ assessment: cached ? cached.decision : null });
      break;
    }

    case 'TEMPORARY_BYPASS_URL': {
      if (message.domain) {
        // Grant 15 minute temporary bypass for explicit user override
        temporaryBypasses.set(message.domain.toLowerCase(), Date.now() + (15 * 60 * 1000));
        Logger.log('USER_ACTION', `Temporary bypass recorded for ${message.domain}`);
      }
      sendResponse({ success: true });
      break;
    }

    case 'CLOSE_CURRENT_TAB': {
      if (sender.tab && sender.tab.id) {
        chrome.tabs.remove(sender.tab.id);
      }
      sendResponse({ success: true });
      break;
    }

    case 'UPDATE_PROTECTION_STATE': {
      Logger.log('USER_ACTION', `Protection state toggled to: ${message.enabled}`);
      sendResponse({ success: true });
      break;
    }

    case 'SUBMIT_MANUAL_REPORT': {
      const threatData = {
        hostname: message.hostname,
        threatType: 'PHISHING',
        riskLevel: 'HIGH_RISK',
        reason: message.reason,
        confidence: 0.85
      };
      reportThreatToCommunity(message.url, threatData).then((ok) => {
        sendResponse({ success: ok });
      });
      return true; // Keep message channel open for async response
    }

    case 'ANALYZE_QR_URL': {
      (async () => {
        try {
          const rawUrl = message.url;
          const payloadType = message.payloadType || 'URL';

          if (!rawUrl || typeof rawUrl !== 'string') {
            sendResponse({ success: false, error: 'Empty QR payload' });
            return;
          }

          // If not an HTTP/HTTPS URL (e.g. plain text, WiFi, tel, mailto, crypto address)
          if (payloadType !== 'URL' || !isInspectableUrl(rawUrl)) {
            sendResponse({
              success: true,
              verdict: 'SAFE',
              riskScore: 0.0,
              confidence: 1.0,
              payloadType: payloadType || 'TEXT',
              destination: rawUrl,
              reasons: [`Non-HTTP destination (${payloadType || 'TEXT'}). No malicious web navigation risk.`],
              summary: `Decoded ${payloadType || 'TEXT'} content safely.`
            });
            return;
          }

          // Check protection toggle
          const settings = await chrome.storage.local.get(['protectionEnabled', 'userWhitelist']);
          if (settings.protectionEnabled === false) {
            sendResponse({
              success: true,
              verdict: 'SAFE',
              riskScore: 0.0,
              confidence: 1.0,
              payloadType: 'URL',
              destination: rawUrl,
              hostname: new URL(rawUrl).hostname.toLowerCase(),
              reasons: ['Protection currently disabled by user.'],
              summary: 'Protection paused.'
            });
            return;
          }

          const hostname = new URL(rawUrl).hostname.toLowerCase();

          // Check user whitelist
          const userWhitelist = settings.userWhitelist || [];
          if (userWhitelist.includes(hostname)) {
            sendResponse({
              success: true,
              verdict: 'SAFE',
              riskScore: 0.0,
              confidence: 1.0,
              payloadType: 'URL',
              destination: rawUrl,
              hostname,
              reasons: ['Domain is in user allowlist.'],
              summary: 'Domain is in user allowlist.'
            });
            return;
          }

          // Check temporary user bypasses
          purgeExpiredCache();
          if (temporaryBypasses.has(hostname)) {
            sendResponse({
              success: true,
              verdict: 'SAFE',
              riskScore: 0.0,
              confidence: 1.0,
              payloadType: 'URL',
              destination: rawUrl,
              hostname,
              reasons: ['Active temporary bypass for this domain.'],
              summary: 'Temporarily bypassed by user.'
            });
            return;
          }

          // In-memory assessment cache
          const cacheKey = getCacheKey(rawUrl);
          let decision = null;
          const cached = assessmentCache.get(cacheKey);

          if (cached && cached.expiresAt > Date.now()) {
            Logger.log('QR_CHECK', `Using cached assessment for QR URL ${hostname}: ${cached.decision.verdict}`);
            decision = cached.decision;
          } else {
            decision = await DecisionEngine.evaluateUrl(rawUrl);
            assessmentCache.set(cacheKey, {
              decision,
              expiresAt: Date.now() + CONFIG.cacheTtlMs
            });
          }

          // If HIGH_RISK, trigger defense signals: Community threat telemetry & OS network blocker
          if (decision.verdict === 'HIGH_RISK') {
            reportThreatToCommunity(rawUrl, decision).catch((err) => {
              Logger.warn('REPORT', `QR threat telemetry error: ${err.message}`);
            });
            signalLocalNetworkBlocker(hostname).catch((err) => {
              Logger.warn('BLOCK', `QR firewall blocker notice: ${err.message}`);
            });
          }

          sendResponse({
            success: true,
            verdict: decision.verdict,
            riskScore: decision.riskScore,
            confidence: decision.confidence,
            payloadType: 'URL',
            destination: rawUrl,
            hostname,
            reasons: decision.reasons || [],
            summary: decision.summary || ''
          });
        } catch (err) {
          Logger.error('QR_ERROR', `Error analyzing QR destination: ${err.message}`);
          sendResponse({
            success: false,
            verdict: 'UNKNOWN',
            riskScore: 0.5,
            confidence: 0.0,
            payloadType: message.payloadType || 'URL',
            destination: message.url,
            reasons: [`Analysis error: ${err.message}`],
            summary: 'Error during security evaluation'
          });
        }
      })();
      return true; // Keep message channel open for async response
    }

    default:
      sendResponse({ error: 'Unknown action' });
  }

  // Return false (or undefined) for synchronous cases to close the message port immediately
  return false;
});

Logger.log('INIT', 'AI Security Shield background service worker activated.');
