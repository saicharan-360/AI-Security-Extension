/**
 * Local Feature Extraction & Weighted Risk Scoring Model
 */

import {
  calculateShannonEntropy,
  isRawIpHost,
  parseDomainParts,
  detectPunycodeHomograph,
  detectBrandImpersonation,
  isUrlShortener,
  TOP_SAFE_DOMAINS,
  SUSPICIOUS_TLDS,
  SUSPICIOUS_KEYWORDS
} from '../utils/domain.js';

import { CONFIG } from '../config.js';

/**
 * Extracts comprehensive structural and semantic features from a URL.
 */
export function extractUrlFeatures(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;

  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const fullUrl = rawUrl.toLowerCase();

    const { registrableDomain, subdomains, subdomainCount } = parseDomainParts(hostname);
    const punycodeInfo = detectPunycodeHomograph(hostname);
    const brandInfo = detectBrandImpersonation(hostname, registrableDomain);

    const isRawIp = isRawIpHost(hostname);
    const hostEntropy = calculateShannonEntropy(hostname);

    const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => fullUrl.includes(kw));

    let hasSuspiciousTld = false;
    for (const tld of SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) {
        hasSuspiciousTld = true;
        break;
      }
    }

    const isWhitelisted = TOP_SAFE_DOMAINS.has(registrableDomain) ||
      TOP_SAFE_DOMAINS.has(hostname) ||
      (brandInfo.isOfficialBrand && !punycodeInfo.isPunycode);

    const atSymbolCount = (fullUrl.match(/@/g) || []).length;
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const doubleSlashInPath = pathname.includes('//') ? 1 : 0;
    const hasSuspiciousPort = parsed.port && !['80', '443', '3000', '5000', '8080'].includes(parsed.port) ? 1 : 0;
    const isHttps = parsed.protocol === 'https:';

    return {
      rawUrl,
      hostname,
      registrableDomain,
      subdomains,
      subdomainCount,
      protocol: parsed.protocol,
      isHttps,
      urlLength: fullUrl.length,
      hostLength: hostname.length,
      hyphenCount,
      atSymbolCount,
      doubleSlashInPath,
      hasSuspiciousPort,
      port: parsed.port || (isHttps ? '443' : '80'),
      hostEntropy,
      isRawIpHost: isRawIp ? 1 : 0,
      hasSuspiciousTld: hasSuspiciousTld ? 1 : 0,
      isUrlShortener: isUrlShortener(hostname) ? 1 : 0,
      isPunycode: punycodeInfo.isPunycode,
      hasHomographPattern: punycodeInfo.hasHomographPattern,
      punycodeParts: punycodeInfo.punycodeParts,
      impersonatedBrand: brandInfo.isImpersonating ? brandInfo.targetBrand : null,
      impersonationDetail: brandInfo.detail || null,
      matchedKeywords,
      isWhitelisted
    };
  } catch (err) {
    return null;
  }
}

/**
 * Evaluates extracted URL features using a balanced, weighted multi-factor heuristic.
 * Avoids single-feature false positives while strongly penalizing compound phishing indicators.
 */
export function evaluateLocalModel(features) {
  if (!features) {
    return {
      verdict: 'UNKNOWN',
      riskScore: 0.5,
      confidence: 0.0,
      reasons: ['URL structure could not be parsed.'],
      summary: 'Invalid URL structure'
    };
  }

  // Whitelisted or verified official high-reputation domain
  if (features.isWhitelisted && features.matchedKeywords.length === 0) {
    return {
      verdict: 'SAFE',
      riskScore: 0.02,
      confidence: 0.98,
      reasons: ['Verified high-reputation or official brand domain.'],
      summary: 'Trusted domain'
    };
  }

  let riskScore = 0.04;
  const reasons = [];

  // 1. Brand Impersonation (High indicator)
  if (features.impersonatedBrand) {
    riskScore += 0.45;
    reasons.push(`Suspected brand impersonation targeting "${features.impersonatedBrand}".`);
  }

  // 2. Punycode / IDN Homograph
  if (features.isPunycode || features.hasHomographPattern) {
    riskScore += features.impersonatedBrand ? 0.35 : 0.25;
    reasons.push('Punycode / Internationalized Domain Name spoofing pattern detected.');
  }

  // 3. Obfuscation (@ symbol or double slashes in path)
  if (features.atSymbolCount > 0) {
    riskScore += 0.35;
    reasons.push('URL contains "@" symbol, a common browser redirection obfuscation.');
  }
  if (features.doubleSlashInPath > 0) {
    riskScore += 0.20;
    reasons.push('Abnormal double-slash sequence in URL path.');
  }

  // 4. Raw IP Hostname
  if (features.isRawIpHost) {
    riskScore += features.matchedKeywords.length > 0 ? 0.35 : 0.20;
    reasons.push(`Direct IP address used instead of domain name: ${features.hostname}.`);
  }

  // 5. Suspicious TLD (Weighted: does NOT trigger block alone)
  if (features.hasSuspiciousTld) {
    riskScore += features.matchedKeywords.length > 0 ? 0.25 : 0.12;
    reasons.push(`Registered on a low-reputation top-level domain.`);
  }

  // 6. Suspicious Keyword Compound
  if (features.matchedKeywords.length > 0) {
    const keywordWeight = Math.min(0.30, features.matchedKeywords.length * 0.10);
    riskScore += keywordWeight;
    reasons.push(`Credential/security keywords present: ${features.matchedKeywords.slice(0, 4).join(', ')}.`);
  }

  // 7. Insecure HTTP on security/login pages
  if (!features.isHttps && features.matchedKeywords.length > 0) {
    riskScore += 0.22;
    reasons.push('Unencrypted HTTP protocol on sensitive login/security keyword path.');
  }

  // 8. Abnormal Structure: Subdomains & Hyphens
  if (features.subdomainCount >= 3 || features.hyphenCount >= 3) {
    riskScore += 0.15;
    reasons.push(`Complex host structure (${features.subdomainCount} subdomains, ${features.hyphenCount} hyphens).`);
  }

  // 9. Hostname Entropy (Randomness / DGA)
  if (features.hostEntropy > 3.85 && !features.isWhitelisted) {
    riskScore += 0.16;
    reasons.push(`High randomness in hostname characters (Entropy: ${features.hostEntropy.toFixed(2)}).`);
  }

  // 10. URL Shortener (Hiding Destination in QR / phishing campaign)
  if (features.isUrlShortener) {
    riskScore += 0.25;
    reasons.push('URL shortener service detected, which masks the final destination.');
  }

  // Clamp risk score to [0, 1]
  riskScore = Math.min(1.0, Math.max(0.0, Number(riskScore.toFixed(2))));

  // Confidence metric: Distance from uncertain center (0.50), weighted by number of corroborating indicators
  const distance = Math.abs(riskScore - 0.50) * 2; // 0 (at 0.5) to 1.0 (at 0 or 1.0)
  const corroboration = reasons.length >= 2 ? 0.2 : (reasons.length === 1 ? 0.1 : 0);
  const confidence = Math.min(0.99, Math.max(0.40, Number((distance * 0.8 + corroboration).toFixed(2))));

  // Decision classification based on configured thresholds
  let verdict = 'SUSPICIOUS';
  if (riskScore <= CONFIG.scoring.safeThreshold) {
    verdict = 'SAFE';
  } else if (riskScore >= CONFIG.scoring.highRiskThreshold && confidence >= 0.70) {
    verdict = 'HIGH_RISK';
  } else {
    verdict = 'SUSPICIOUS';
  }

  return {
    verdict,
    riskScore,
    confidence,
    reasons,
    summary: reasons.length > 0 ? reasons.join(' ') : 'Standard web traffic patterns.'
  };
}
