/**
 * External Telemetry, Community Threat DB & AI API Client
 * Built with strict timeouts, structured logging, and offline resilience.
 */

import { CONFIG } from '../config.js';
import { sanitizeUrlForPrivacy } from '../utils/domain.js';

/**
 * Structured logger for extension lifecycle and telemetry events.
 */
export const Logger = {
  log: (tag, ...args) => {
    if (CONFIG.enableDebugLogs) {
      console.log(`[${tag}]`, ...args);
    }
  },
  warn: (tag, ...args) => {
    console.warn(`[${tag}]`, ...args);
  },
  error: (tag, ...args) => {
    console.error(`[${tag}]`, ...args);
  }
};

/**
 * Executes a fetch request with timeout protection.
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = CONFIG.requestTimeoutMs) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(id);
    return response;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

/**
 * Checks domain against community threat intelligence backend.
 */
export async function queryCommunityThreatDb(rawUrl) {
  const sanitizedUrl = sanitizeUrlForPrivacy(rawUrl);
  if (!sanitizedUrl) return null;

  try {
    const endpoint = `${CONFIG.backendUrl}/api/check?url=${encodeURIComponent(sanitizedUrl)}`;
    Logger.log('THREAT_INTEL', `Querying backend database for ${new URL(rawUrl).hostname}`);

    const res = await fetchWithTimeout(endpoint);
    if (!res.ok) {
      Logger.warn('THREAT_INTEL', `Backend returned HTTP status ${res.status}`);
      return null;
    }

    const data = await res.json();
    if (data.isMalicious && data.threat) {
      Logger.log('THREAT_INTEL', `Community DB Match: ${data.threat.reason}`);
      return {
        isMalicious: true,
        threat: data.threat,
        source: 'COMMUNITY_DATABASE'
      };
    }

    return {
      isMalicious: false,
      source: 'COMMUNITY_DATABASE'
    };
  } catch (err) {
    const isTimeout = err.name === 'AbortError';
    Logger.warn('THREAT_INTEL', `Community DB offline or unreachable (${isTimeout ? 'Timeout' : err.message}). Fallback to local heuristic.`);
    return null;
  }
}

/**
 * Requests deep AI domain assessment through the secure backend proxy.
 */
export async function requestAiAnalysis(rawUrl, localFeatures) {
  const sanitizedUrl = sanitizeUrlForPrivacy(rawUrl);
  if (!sanitizedUrl) return null;

  try {
    const endpoint = `${CONFIG.backendUrl}/api/ai-analyze`;
    Logger.log('AI_ANALYSIS', `Requesting server-side AI evaluation for ${localFeatures?.hostname || rawUrl}`);

    // Transmit only non-sensitive structural features
    const safePayload = {
      url: sanitizedUrl,
      features: {
        hostEntropy: localFeatures.hostEntropy,
        urlLength: localFeatures.urlLength,
        subdomainCount: localFeatures.subdomainCount,
        hyphenCount: localFeatures.hyphenCount,
        hasSuspiciousTld: localFeatures.hasSuspiciousTld,
        isRawIpHost: localFeatures.isRawIpHost,
        impersonatedBrand: localFeatures.impersonatedBrand,
        isPunycode: localFeatures.isPunycode,
        protocol: localFeatures.protocol
      }
    };

    const res = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(safePayload)
    }, CONFIG.requestTimeoutMs + 2000);

    if (!res.ok) {
      Logger.warn('AI_ANALYSIS', `Backend AI endpoint returned HTTP status ${res.status}`);
      return null;
    }

    const data = await res.json();
    if (data.success && data.result) {
      Logger.log('AI_ANALYSIS', `AI verdict: ${data.result.classification} (Score: ${data.result.riskScore})`);
      return data.result;
    }

    return null;
  } catch (err) {
    Logger.warn('AI_ANALYSIS', `Backend AI proxy unavailable (${err.message})`);
    return null;
  }
}

/**
 * Reports a confirmed threat to the community database.
 */
export async function reportThreatToCommunity(rawUrl, threatData) {
  const sanitizedUrl = sanitizeUrlForPrivacy(rawUrl);
  if (!sanitizedUrl) return false;

  try {
    const endpoint = `${CONFIG.backendUrl}/api/report`;
    Logger.log('REPORT', `Reporting confirmed threat: ${threatData.hostname}`);

    const res = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: sanitizedUrl,
        threatType: threatData.threatType || 'PHISHING',
        riskLevel: threatData.riskLevel || 'HIGH_RISK',
        reason: threatData.summary || threatData.reason || 'Flagged by AI Security Defense Pipeline',
        confidence: threatData.confidence || 0.90
      })
    });

    if (res.ok) {
      Logger.log('REPORT', `Threat report successfully submitted.`);
      return true;
    } else {
      Logger.warn('REPORT', `Threat report rejected with HTTP ${res.status}`);
      return false;
    }
  } catch (err) {
    Logger.warn('REPORT', `Failed to report threat to backend (${err.message})`);
    return false;
  }
}

/**
 * Sends a signal to the local OS network blocker on port 8080.
 * Reports actual execution status; never falsely claims success when offline.
 */
export async function signalLocalNetworkBlocker(hostname) {
  if (!hostname) return { success: false, reason: 'Missing hostname' };

  try {
    Logger.log('BLOCK', `Signaling OS kernel firewall blocker for: ${hostname}`);
    const res = await fetchWithTimeout(CONFIG.networkBlockerUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hostname })
    }, 2500);

    if (res.ok) {
      const data = await res.json();
      Logger.log('BLOCK', `Network blocker executed: ${data.message || 'Rule injected'}`);
      return { success: true, offline: false, details: data };
    }

    return { success: false, offline: false, reason: `HTTP status ${res.status}` };
  } catch (err) {
    Logger.warn('BLOCK', `Local network defender on port 8080 is offline or unreachable. (Browser-level protection remains active)`);
    return { success: false, offline: true, reason: 'Service unreachable' };
  }
}
