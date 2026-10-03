const { z } = require('zod');

// Multi-part country/second-level TLDs to properly extract registrable domain
const KNOWN_TWO_PART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'com.br', 'net.br', 'org.br',
  'co.jp', 'ne.jp', 'or.jp',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'co.za', 'org.za',
  'com.sg', 'edu.sg',
  'com.mx', 'edu.mx',
  'com.tr', 'edu.tr'
]);

/**
 * Extracts a normalized hostname and registrable domain from a raw URL or hostname string.
 */
function parseDomainDetails(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    throw new Error('Input URL/hostname must be a non-empty string');
  }

  let cleaned = rawInput.trim();
  // If no scheme present, add https:// to allow URL parsing
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = 'https://' + cleaned;
  }

  let parsed;
  try {
    parsed = new URL(cleaned);
  } catch (err) {
    throw new Error(`Invalid URL format: ${rawInput}`);
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
  const hostParts = hostname.split('.');

  let registrableDomain = hostname;
  if (hostParts.length >= 2) {
    const lastTwo = hostParts.slice(-2).join('.');
    const lastThree = hostParts.slice(-3).join('.');

    if (hostParts.length >= 3 && KNOWN_TWO_PART_TLDS.has(lastTwo)) {
      registrableDomain = lastThree;
    } else {
      registrableDomain = lastTwo;
    }
  }

  return {
    hostname,
    registrableDomain,
    pathname: parsed.pathname,
    protocol: parsed.protocol
  };
}

const checkQuerySchema = z.object({
  url: z.string().url().min(1).max(2048)
});

const reportBodySchema = z.object({
  url: z.string().min(1).max(2048),
  hostname: z.string().max(255).optional(),
  threatType: z.enum(['PHISHING', 'MALWARE', 'SCAM', 'BRAND_IMPERSONATION', 'SUSPICIOUS', 'OTHER']).default('PHISHING'),
  riskLevel: z.enum(['SAFE', 'SUSPICIOUS', 'HIGH_RISK', 'UNKNOWN']).default('HIGH_RISK'),
  reason: z.string().min(3).max(500),
  confidence: z.number().min(0).max(1).optional().default(0.90),
  source: z.enum(['COMMUNITY_REPORT', 'AI_ANALYSIS', 'HEURISTIC', 'ADMIN']).default('COMMUNITY_REPORT')
});

const aiAnalyzeBodySchema = z.object({
  url: z.string().min(1).max(2048),
  features: z.object({
    urlLength: z.number().optional(),
    hostLength: z.number().optional(),
    subdomainCount: z.number().optional(),
    hyphenCount: z.number().optional(),
    hasSuspiciousTld: z.number().optional(),
    hostEntropy: z.number().optional(),
    isRawIpHost: z.number().optional(),
    impersonatedBrand: z.string().nullable().optional(),
    isPunycode: z.boolean().optional(),
    protocol: z.string().optional()
  }).optional()
});

module.exports = {
  parseDomainDetails,
  checkQuerySchema,
  reportBodySchema,
  aiAnalyzeBodySchema
};
