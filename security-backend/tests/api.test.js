const request = require('supertest');
const { app } = require('../server');
const threatDb = require('../src/threatDb');
const geminiService = require('../src/geminiService');
const { parseDomainDetails } = require('../src/validation');

// Increase Jest timeout for robust testing
jest.setTimeout(15000);

describe('Security Backend API & Validation Tests', () => {

  describe('11. Invalid URL Handling', () => {
    test('Correctly extracts standard hostname and registrable domain', () => {
      const result = parseDomainDetails('https://sub.example.com/login?token=secret');
      expect(result.hostname).toBe('sub.example.com');
      expect(result.registrableDomain).toBe('example.com');
    });

    test('Throws error for empty or invalid input', () => {
      expect(() => parseDomainDetails('')).toThrow();
      expect(() => parseDomainDetails('http://')).toThrow();
    });

    test('GET /api/check returns 400 when url parameter is missing or malformed', async () => {
      const res = await request(app).get('/api/check');
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);

      const res2 = await request(app).get('/api/check?url=not-a-valid-url');
      expect(res2.status).toBe(400);
    });
  });

  describe('1. Supabase Connection & 9. Supabase Failure', () => {
    test('GET /api/health gracefully reports database health mode (memory or supabase)', async () => {
      const res = await request(app).get('/api/health');
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.status).toBe('ONLINE');
      // The database mode must exist and be defined, even if Supabase is offline (memory fallback)
      expect(res.body.database).toBeDefined();
      expect(res.body.database.mode).toBeDefined();
    });

    test('threatDb.withTimeout rejects slowly resolving promises smoothly', async () => {
      const slowPromise = new Promise(resolve => setTimeout(resolve, 3000));
      await expect(threatDb.withTimeout(slowPromise, 500)).rejects.toThrow('Operation timed out');
    });
  });

  describe('5. SAFE result & 3. URL lookup', () => {
    test('GET /api/check returns isMalicious: false for an unknown safe domain', async () => {
      const res = await request(app).get('/api/check?url=https://clean-example-test.org');
      expect(res.status).toBe(200);
      expect(res.body.isMalicious).toBe(false);
      expect(res.body.hostname).toBe('clean-example-test.org');
    });
  });

  describe('2. URL insertion & 4. Known malicious URL detection & 7. HIGH RISK & 12. Repeated cache', () => {
    test('POST /api/report accepts valid threat report and registers threat', async () => {
      const reportPayload = {
        url: 'https://paypal-security-update.xyz/login',
        threatType: 'PHISHING',
        riskLevel: 'HIGH_RISK',
        reason: 'Impersonating PayPal credential portal',
        confidence: 0.95
      };

      const reportRes = await request(app).post('/api/report').send(reportPayload);
      expect(reportRes.status).toBe(201);
      expect(reportRes.body.success).toBe(true);
      expect(reportRes.body.threat.hostname).toBe('paypal-security-update.xyz');
      expect(reportRes.body.threat.riskLevel).toBe('HIGH_RISK');

      // Now query check endpoint - should find the recorded threat
      const checkRes = await request(app).get('/api/check?url=https://paypal-security-update.xyz/account');
      expect(checkRes.status).toBe(200);
      expect(checkRes.body.isMalicious).toBe(true);
      expect(checkRes.body.threat.hostname).toBe('paypal-security-update.xyz');
      expect(checkRes.body.threat.riskLevel).toBe('HIGH_RISK');

      // Re-report to test cache / increment behavior
      const repeatRes = await request(app).post('/api/report').send(reportPayload);
      expect(repeatRes.status).toBe(201);
      // memoryDb handles the report count increment transparently
    });
  });

  describe('6. REVIEW result & 8. Gemini failure', () => {
    test('POST /api/ai-analyze safely falls back when Gemini API is unconfigured/fails', async () => {
      // Intentionally break gemini API key for this test
      const originalKey = geminiService.apiKey;
      geminiService.apiKey = '';

      const res = await request(app).post('/api/ai-analyze').send({
        url: 'https://suspicious-unknown-site.top',
        features: { hostEntropy: 3.8, hasSuspiciousTld: 1 }
      });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.result).toBeDefined();
      // It should gracefully return an UNKNOWN or fallback response, not a 500 error
      expect(['SAFE', 'SUSPICIOUS', 'HIGH_RISK', 'UNKNOWN']).toContain(res.body.result.classification);
      
      // Restore key
      geminiService.apiKey = originalKey;
    });
  });

  describe('10. Backend Failure Resilience (Mocking API Client)', () => {
    test('Ensures that the API routes respond properly and do not crash the Node.js process', async () => {
      // By wrapping internal methods that could fail with try/catch in server.js,
      // invalid data formats should be safely caught.
      const res = await request(app).post('/api/report').send({
         url: 'https://example.com',
         reason: '' // too short, should fail validation
      });
      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error).toMatch(/Validation error/);
    });
  });

});
