import * as domainUtils from '../../AI-Security-Extension/utils/domain.js';
import * as localModel from '../../AI-Security-Extension/detection/local_model.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✓ ${message}`);
    passed++;
  } else {
    console.error(`  ✗ FAILED: ${message}`);
    failed++;
  }
}

console.log('\n=== Running Heuristics & Detection Engine Verification ===\n');

// 1. Shannon Entropy
console.log('Test Suite 1: Shannon Entropy');
const lowEntropy = domainUtils.calculateShannonEntropy('aaaaaa');
assert(lowEntropy === 0, 'Repetitive string has zero entropy');
const standardHost = domainUtils.calculateShannonEntropy('google.com');
const randomHost = domainUtils.calculateShannonEntropy('x89qf7z2m1p0w4l9.com');
assert(randomHost > standardHost && randomHost > 3.5, 'Random/DGA domain has higher entropy than standard host');

// 2. Safe URL Heuristics
console.log('\nTest Suite 2: Normal Safe URLs');
const safeFeatures = localModel.extractUrlFeatures('https://www.google.com/search?q=cybersecurity');
const safeEval = localModel.evaluateLocalModel(safeFeatures);
assert(safeEval.verdict === 'SAFE', `Google search is classified as SAFE (got ${safeEval.verdict})`);
assert(safeEval.riskScore <= 0.25, `Google search risk score <= 0.25 (got ${safeEval.riskScore})`);

// 3. Brand Impersonation
console.log('\nTest Suite 3: Brand Impersonation');
const brandCheck = domainUtils.detectBrandImpersonation('paypal-login-verify.com', 'paypal-login-verify.com');
assert(brandCheck.isImpersonating === true, 'paypal-login-verify.com is flagged as impersonating');
assert(brandCheck.targetBrand === 'paypal', 'Target brand identified as paypal');

const officialCheck = domainUtils.detectBrandImpersonation('developer.paypal.com', 'paypal.com');
assert(officialCheck.isOfficialBrand === true && officialCheck.isImpersonating === false, 'Official developer.paypal.com is not flagged as impersonation');

const impersonationFeatures = localModel.extractUrlFeatures('https://paypal-login-verify.com/account');
const impersonationEval = localModel.evaluateLocalModel(impersonationFeatures);
assert(impersonationEval.riskScore >= 0.50, `Impersonation URL has high risk score (got ${impersonationEval.riskScore})`);

// 4. Suspicious TLD (.xyz with credential keyword)
console.log('\nTest Suite 4: Suspicious TLD Heuristic');
const tldFeatures = localModel.extractUrlFeatures('http://secure-account.xyz/login');
const tldEval = localModel.evaluateLocalModel(tldFeatures);
assert(tldFeatures.hasSuspiciousTld === 1, '.xyz domain detected as suspicious TLD');
assert(tldEval.riskScore >= 0.50, `Suspicious TLD + keyword scores high risk (got ${tldEval.riskScore})`);

// 5. Raw IP Hostname
console.log('\nTest Suite 5: Raw IP Hostname');
const ipFeatures = localModel.extractUrlFeatures('http://192.168.1.50/login');
const ipEval = localModel.evaluateLocalModel(ipFeatures);
assert(ipFeatures.isRawIpHost === 1, 'Raw IP detected');
assert(ipEval.riskScore >= 0.50, `Raw IP with login keyword has high risk score (got ${ipEval.riskScore})`);

// 6. URL with @ obfuscation
console.log('\nTest Suite 6: URL Obfuscation');
const atFeatures = localModel.extractUrlFeatures('https://google.com@phishing-attacker.com/login');
const atEval = localModel.evaluateLocalModel(atFeatures);
assert(atFeatures.atSymbolCount === 1, '@ symbol obfuscation detected');
assert(atEval.riskScore >= 0.50, `@ symbol scores high risk (got ${atEval.riskScore})`);

// 7. Punycode / IDN Homograph
console.log('\nTest Suite 7: Punycode & IDN Homograph');
const punyCheck = domainUtils.detectPunycodeHomograph('xn--pypal-4ve.com');
assert(punyCheck.isPunycode === true, 'xn-- prefix correctly detected as Punycode');
const punyFeatures = localModel.extractUrlFeatures('https://xn--pypal-4ve.com/signin');
const punyEval = localModel.evaluateLocalModel(punyFeatures);
assert(punyEval.riskScore >= 0.50, `Punycode with signin scores high risk (got ${punyEval.riskScore})`);

// 8. Privacy Sanitization
console.log('\nTest Suite 8: Privacy & Data Minimization');
const rawSensitiveUrl = 'https://user:password@target-bank.com/portal?token=SECRET_JWT_KEY_12345&sessionid=XYZ999&search=term#credentials';
const sanitized = domainUtils.sanitizeUrlForPrivacy(rawSensitiveUrl);
assert(!sanitized.includes('password'), 'Passwords stripped');
assert(!sanitized.includes('SECRET_JWT_KEY_12345'), 'Authentication tokens stripped');
assert(!sanitized.includes('XYZ999'), 'Session IDs stripped');
assert(!sanitized.includes('credentials'), 'Hash fragments stripped');
assert(sanitized.includes('search=term'), 'Benign query parameters preserved');

// 9. Invalid URL Handling
console.log('\nTest Suite 9: Fault Tolerance & Safe Degradation');
const invalidFeatures = localModel.extractUrlFeatures('not-a-valid-url');
assert(invalidFeatures === null, 'Invalid URL returns null safely');
const nullEval = localModel.evaluateLocalModel(null);
assert(nullEval.verdict === 'UNKNOWN', 'Null features produce UNKNOWN verdict');

// 10. False Positive Prevention
console.log('\nTest Suite 10: False-Positive Prevention');
const portfolioFeatures = localModel.extractUrlFeatures('https://portfolio-showcase.xyz/about');
const portfolioEval = localModel.evaluateLocalModel(portfolioFeatures);
assert(portfolioEval.verdict !== 'HIGH_RISK', 'Benign .xyz portfolio site is not falsely classified as HIGH_RISK');

// 11. QR Code Payload Classification
console.log('\nTest Suite 11: QR Code Payload Classification');
const normalUrlPayload = domainUtils.classifyQrPayload('https://www.google.com/search?q=cybersecurity');
assert(normalUrlPayload.type === 'URL', 'HTTPS destination categorized as URL');

const textPayload = domainUtils.classifyQrPayload('Table 14 - Guest WiFi Menu');
assert(textPayload.type === 'TEXT', 'Non-URL plain text categorized as TEXT');

const wifiPayload = domainUtils.classifyQrPayload('WIFI:T:WPA;S:CoffeeShop_Guest;P:guest1234;;');
assert(wifiPayload.type === 'WIFI', 'WiFi payload categorized as WIFI');

const cryptoPayload = domainUtils.classifyQrPayload('bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.001');
assert(cryptoPayload.type === 'CRYPTO_PAYMENT', 'Crypto address categorized as CRYPTO_PAYMENT');

const mailPayload = domainUtils.classifyQrPayload('mailto:support@bank.com?subject=Help');
assert(mailPayload.type === 'EMAIL', 'Mailto link categorized as EMAIL');

// 12. QR Phishing: URL Shortener Masking
console.log('\nTest Suite 12: QR Phishing & URL Shorteners');
const isShortener = domainUtils.isUrlShortener('bit.ly');
assert(isShortener === true, 'bit.ly recognized as URL shortener');

const shortenerFeatures = localModel.extractUrlFeatures('https://tinyurl.com/fake-login-verify');
assert(shortenerFeatures.isUrlShortener === 1, 'tinyurl.com flagged as URL shortener in features');
const shortenerEval = localModel.evaluateLocalModel(shortenerFeatures);
assert(shortenerEval.riskScore >= 0.25, `URL shortener increases risk score (got ${shortenerEval.riskScore})`);
assert(shortenerEval.reasons.some(r => r.includes('shortener')), 'Reason highlights URL shortener hiding destination');

// 13. QR Malicious Destination Detection & Blocking
console.log('\nTest Suite 13: QR Malicious Test Case (Brand Impersonation)');
const qrMaliciousFeatures = localModel.extractUrlFeatures('https://paypal-login-verify.com/account');
const qrMaliciousEval = localModel.evaluateLocalModel(qrMaliciousFeatures);
assert(qrMaliciousEval.verdict === 'HIGH_RISK', `Phishing QR destination triggers HIGH_RISK verdict (got ${qrMaliciousEval.verdict})`);
assert(qrMaliciousEval.riskScore >= 0.80, `High risk score for malicious QR target (got ${qrMaliciousEval.riskScore})`);

console.log(`\n========================================`);
console.log(`Summary: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}

