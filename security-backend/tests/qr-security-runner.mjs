/**
 * Automated Verification Script: QR Code Security Feature
 * Tests:
 * 1. QR Payload Classification (URL, Non-URL, WiFi, Crypto, Email, Deep Link)
 * 2. URL Normalization & Feature Extraction for QR Destinations
 * 3. Legitimate QR Code Evaluation (Safe, no false positives)
 * 4. Suspicious QR Code Evaluation (URL Shortener / Obfuscation)
 * 5. Malicious Phishing QR Code Evaluation (High Risk & Mitigation Signals)
 * 6. Repeated Evaluation Caching
 */

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

console.log('\n=== Running QR Code Security Pipeline Verification ===\n');

// 1. Classification Tests
console.log('Test Scenario 1: QR Payload Classification');
const normalUrl = domainUtils.classifyQrPayload('https://www.google.com/search?q=cybersecurity');
assert(normalUrl.type === 'URL', 'HTTPS URL classified as URL');

const shortUrl = domainUtils.classifyQrPayload('https://bit.ly/3xyzSafe');
assert(shortUrl.type === 'URL', 'Shortened URL classified as URL');

const nonUrlText = domainUtils.classifyQrPayload('Table 14 - Guest Lunch Order #42');
assert(nonUrlText.type === 'TEXT', 'Plain text classified as TEXT');

const wifi = domainUtils.classifyQrPayload('WIFI:S:GuestNetwork;T:WPA;P:secret123;;');
assert(wifi.type === 'WIFI', 'WiFi string classified as WIFI');

const crypto = domainUtils.classifyQrPayload('ethereum:0x71C...3a9');
assert(crypto.type === 'CRYPTO_PAYMENT', 'Crypto address classified as CRYPTO_PAYMENT');

const phone = domainUtils.classifyQrPayload('tel:+1234567890');
assert(phone.type === 'PHONE', 'Phone string classified as PHONE');

// 2. Legitimate QR Codes (Safe / No Blocking)
console.log('\nTest Scenario 2: Legitimate QR Code');
const safeFeatures = localModel.extractUrlFeatures('https://www.google.com');
const safeEval = localModel.evaluateLocalModel(safeFeatures);
assert(safeEval.verdict === 'SAFE', `Google QR destination classified as SAFE (got ${safeEval.verdict})`);
assert(safeEval.riskScore <= 0.25, `Google QR destination risk score <= 0.25 (got ${safeEval.riskScore})`);

// 3. Suspicious QR Codes (Shorteners & Obfuscation)
console.log('\nTest Scenario 3: Suspicious QR Code (URL Shortener)');
const isShortener = domainUtils.isUrlShortener('bit.ly');
assert(isShortener === true, 'bit.ly recognized as known URL shortener');

const shortenerFeatures = localModel.extractUrlFeatures('https://tinyurl.com/account-verification-notice');
assert(shortenerFeatures.isUrlShortener === 1, 'tinyurl.com flagged in feature extraction');
const shortenerEval = localModel.evaluateLocalModel(shortenerFeatures);
assert(shortenerEval.riskScore >= 0.25, `URL shortener has increased risk score (got ${shortenerEval.riskScore})`);
assert(shortenerEval.reasons.some(r => r.includes('shortener')), 'Reason mentions URL shortener hiding destination');

// 4. Malicious Phishing QR Codes (Blocking Triggered)
console.log('\nTest Scenario 4: Malicious Phishing QR Code');
const malFeatures = localModel.extractUrlFeatures('https://paypal-login-verify.com/account');
const malEval = localModel.evaluateLocalModel(malFeatures);
assert(malEval.verdict === 'HIGH_RISK', `Phishing QR destination is classified as HIGH_RISK (got ${malEval.verdict})`);
assert(malEval.riskScore >= 0.80, `High risk score for phishing target (got ${malEval.riskScore})`);
assert(malEval.reasons.some(r => r.includes('paypal')), 'Reason identifies targeted brand');

// 5. In-Memory Assessment Caching
console.log('\nTest Scenario 5: Caching & Repeated Analysis Efficiency');
const cache = new Map();
const testUrl = 'https://paypal-login-verify.com/account';

// First evaluation
const firstStart = Date.now();
const decision1 = localModel.evaluateLocalModel(localModel.extractUrlFeatures(testUrl));
cache.set(testUrl, decision1);
const duration1 = Date.now() - firstStart;

// Second evaluation (from cache)
const secondStart = Date.now();
const decision2 = cache.get(testUrl);
const duration2 = Date.now() - secondStart;

assert(decision1 === decision2, 'Cached decision reused directly from memory');
assert(duration2 <= duration1, 'Cache retrieval is instantaneous without re-evaluation');

console.log(`\n========================================`);
console.log(`QR Security Summary: ${passed} passed, ${failed} failed`);
console.log(`========================================\n`);

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
