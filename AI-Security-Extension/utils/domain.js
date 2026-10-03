/**
 * Domain, URL, Homograph & Privacy Sanitization Utilities
 */

// Two-part country-code top-level domains for proper registrable domain parsing
const KNOWN_TWO_PART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'com.br', 'net.br', 'org.br',
  'co.jp', 'ne.jp', 'or.jp',
  'co.in', 'net.in', 'org.in', 'gen.in', 'ind.in',
  'co.za', 'org.za',
  'com.sg', 'edu.sg',
  'com.mx', 'edu.mx',
  'com.tr', 'edu.tr'
]);

// Protected high-profile target brands
export const PROTECTED_BRANDS = [
  'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
  'chase', 'wellsfargo', 'bankofamerica', 'citi', 'binance', 'coinbase',
  'meta', 'facebook', 'instagram', 'whatsapp', 'linkedin', 'github',
  'dropbox', 'adobe', 'steam', 'roblox', 'twitter', 'x'
];

// High reputation trusted official domains
export const TOP_SAFE_DOMAINS = new Set([
  'google.com', 'google.co.in', 'google.co.uk',
  'youtube.com', 'github.com', 'microsoft.com',
  'apple.com', 'amazon.com', 'wikipedia.org',
  'cloudflare.com', 'mozilla.org', 'w3.org',
  'gov.in', 'gov.uk', 'gov', 'edu'
]);

// Known suspicious or low-reputation TLDs often abused in high-volume phishing
export const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.top', '.buzz', '.work', '.click', '.monster',
  '.cc', '.info', '.live', '.fit', '.gq', '.ml', '.cf',
  '.tk', '.ga', '.zip', '.mov', '.surf', '.icu', '.cam'
]);

// Security / credential sensitive keywords
export const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'update', 'account',
  'banking', 'secure', 'security', 'wallet', 'crypto', 'airdrop',
  'confirm', 'password', 'billing', 'support', 'recover', 'kyc',
  'passcode', 'credential', 'authenticate', 'unusual-activity'
];

// Sensitive query parameters that MUST be stripped for user privacy
const SENSITIVE_QUERY_PARAMS = new Set([
  'token', 'access_token', 'id_token', 'refresh_token', 'jwt',
  'auth', 'authorization', 'key', 'apikey', 'api_key', 'secret',
  'password', 'pass', 'pwd', 'code', 'verification_code', 'otp',
  'session', 'sessionid', 'phpsessid', 'jsessionid',
  'email', 'user', 'username', 'card', 'cvv', 'ssn'
]);

/**
 * Calculates the Shannon Entropy of a string to detect randomized/DGA strings.
 */
export function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string') return 0;
  const len = str.length;
  if (len === 0) return 0;

  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Checks if hostname is a direct IPv4 or IPv6 address.
 */
export function isRawIpHost(hostname) {
  if (!hostname) return false;
  // IPv4 format
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return true;
  // IPv6 format
  if (/^\[?[a-fA-F0-9:]+\]?$/.test(hostname) && hostname.includes(':')) return true;
  return false;
}

/**
 * Parses and extracts the accurate registrable domain and subdomains.
 */
export function parseDomainParts(hostname) {
  const cleanHost = (hostname || '').toLowerCase().replace(/\.+$/, '');
  const parts = cleanHost.split('.').filter(Boolean);

  if (parts.length <= 1) {
    return {
      hostname: cleanHost,
      registrableDomain: cleanHost,
      subdomains: '',
      subdomainCount: 0
    };
  }

  let registrableDomain = cleanHost;
  let subdomains = '';

  const lastTwo = parts.slice(-2).join('.');
  const lastThree = parts.slice(-3).join('.');

  if (parts.length >= 3 && KNOWN_TWO_PART_TLDS.has(lastTwo)) {
    registrableDomain = lastThree;
    subdomains = parts.slice(0, -3).join('.');
  } else {
    registrableDomain = lastTwo;
    subdomains = parts.slice(0, -2).join('.');
  }

  const subdomainCount = subdomains ? subdomains.split('.').length : 0;

  return {
    hostname: cleanHost,
    registrableDomain,
    subdomains,
    subdomainCount
  };
}

/**
 * Detects Punycode (IDN) and homograph attacks.
 */
export function detectPunycodeHomograph(hostname) {
  if (!hostname) return { isPunycode: false, hasHomographPattern: false, punycodeParts: [] };

  const parts = hostname.toLowerCase().split('.');
  const punycodeParts = parts.filter(p => p.startsWith('xn--'));
  const isPunycode = punycodeParts.length > 0;

  // Check for mixed scripts or typical look-alike homographs in non-Punycode unicode strings
  let hasHomographPattern = false;
  if (isPunycode) {
    // Punycode on any domain trying to imitate a known brand is an immediate strong flag
    hasHomographPattern = true;
  } else {
    // Check for mixed Latin/Cyrillic character ranges (e.g. Cyrillic 'а', 'е', 'о', 'р')
    const cyrillicLookalikes = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445]/;
    if (cyrillicLookalikes.test(hostname)) {
      hasHomographPattern = true;
    }
  }

  return {
    isPunycode,
    hasHomographPattern,
    punycodeParts
  };
}

/**
 * Detects whether a domain is attempting brand impersonation.
 * Properly checks registrable domain rather than naive substring matching.
 */
export function detectBrandImpersonation(hostname, registrableDomain) {
  const host = (hostname || '').toLowerCase();
  const regDomain = (registrableDomain || '').toLowerCase();

  for (const brand of PROTECTED_BRANDS) {
    // Check if the registrable domain is the official brand domain (e.g. paypal.com or paypal.co.uk)
    const brandRegPrefix = brand + '.';
    const isOfficial = regDomain === `${brand}.com` ||
      regDomain === `${brand}.org` ||
      regDomain === `${brand}.net` ||
      regDomain.startsWith(brandRegPrefix);

    if (isOfficial) {
      return { isImpersonating: false, targetBrand: null, isOfficialBrand: true };
    }

    // Check if the brand appears in subdomains or hyphenated deceptive domain (e.g. paypal-security.xyz)
    const hostHasBrand = host.includes(brand);
    if (hostHasBrand) {
      return {
        isImpersonating: true,
        targetBrand: brand,
        isOfficialBrand: false,
        detail: `Brand "${brand}" used outside its official registered domain`
      };
    }
  }

  return { isImpersonating: false, targetBrand: null, isOfficialBrand: false };
}

/**
 * Privacy-preserving URL sanitization.
 * Strips user credentials, tokens, session IDs, and hashes before external transmission.
 */
export function sanitizeUrlForPrivacy(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    // Strip HTTP Basic Auth credentials
    parsed.username = '';
    parsed.password = '';
    // Strip hash/fragment
    parsed.hash = '';

    // Sanitize query parameters
    const safeSearchParams = new URLSearchParams();
    for (const [key, value] of parsed.searchParams.entries()) {
      if (SENSITIVE_QUERY_PARAMS.has(key.toLowerCase())) {
        safeSearchParams.append(key, '[REDACTED]');
      } else {
        // Keep non-sensitive query keys with truncated values if long
        safeSearchParams.append(key, value.slice(0, 50));
      }
    }

    parsed.search = safeSearchParams.toString();
    return parsed.toString();
  } catch (err) {
    // If invalid, return empty string
    return '';
  }
}

// Known URL shortener services commonly leveraged in QR phishing to disguise real destinations
export const KNOWN_URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly',
  'buff.ly', 'cutt.ly', 'rb.gy', 'v.gd', 'qr.ae', 'linktr.ee',
  'shorturl.at', 'bl.ink', 'cli.re', 'snip.ly', 'soo.gd'
]);

/**
 * Checks if a hostname belongs to a known URL shortener service.
 */
export function isUrlShortener(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const clean = hostname.toLowerCase().trim();
  return KNOWN_URL_SHORTENERS.has(clean);
}

/**
 * Categorizes and parses the payload of a scanned QR code.
 * Differentiates URLs, deep links, crypto wallets, contact data, WiFi, and plain text.
 */
export function classifyQrPayload(rawPayload) {
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

  // App Links / Deep Links (custom schemes like intent:, tg:, whatsapp:)
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

