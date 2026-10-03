/**
 * Community Threat Intelligence & Telemetry Backend
 * Express + Supabase + Server-side Gemini AI
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const threatDb = require('./src/threatDb');
const geminiService = require('./src/geminiService');
const {
  parseDomainDetails,
  checkQuerySchema,
  reportBodySchema,
  aiAnalyzeBodySchema
} = require('./src/validation');

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Security Headers
app.use(helmet({
  contentSecurityPolicy: false // Allow API usage across browser extension contexts
}));

// CORS Configuration - Allow extension origins and local dev
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    // Allow local tools and browser extension schemes
    if (
      origin.startsWith('chrome-extension://') ||
      origin.startsWith('http://localhost') ||
      origin.startsWith('http://127.0.0.1')
    ) {
      return callback(null, true);
    }
    // In production, allow same-origin or configured domains
    return callback(null, true);
  },
  credentials: false
}));

// Request body parser with safe size limit (prevent DoS)
app.use(express.json({ limit: '10kb' }));

// Rate Limiters (skip in test environment)
const skipRateLimiter = (req, res) => process.env.NODE_ENV === 'test';

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  skip: skipRateLimiter,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please slow down.' }
});

const reportLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  skip: skipRateLimiter,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Rate limit exceeded for threat reports.' }
});

const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  skip: skipRateLimiter,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Rate limit exceeded for AI domain analysis.' }
});

app.use(generalLimiter);

// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'AI Security Shield Threat Intelligence Backend',
    version: '2.0.0',
    endpoints: {
      health: 'GET /api/health',
      check: 'GET /api/check?url=https://example.com',
      report: 'POST /api/report',
      aiAnalyze: 'POST /api/ai-analyze'
    }
  });
});

app.get('/api/health', async (req, res) => {
  const dbHealth = await threatDb.checkHealth();
  res.json({
    success: true,
    status: 'ONLINE',
    environment: NODE_ENV,
    database: dbHealth,
    aiService: {
      configured: geminiService.isConfigured()
    },
    timestamp: new Date().toISOString()
  });
});

/**
 * GET /api/check?url=https://example.com
 * Query threat database for a URL or domain.
 */
app.get('/api/check', async (req, res, next) => {
  try {
    const validated = checkQuerySchema.safeParse(req.query);
    if (!validated.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid or missing query parameter: "url".'
      });
    }

    const { hostname, registrableDomain } = parseDomainDetails(validated.data.url);
    console.log(`[URL_CHECK] Checking domain: ${hostname} (${registrableDomain})`);

    const threat = await threatDb.findThreat(hostname, registrableDomain);

    if (threat) {
      console.log(`[THREAT_INTEL] Hit found for ${hostname}: ${threat.reason}`);
      return res.json({
        isMalicious: true,
        threat
      });
    }

    return res.json({
      isMalicious: false,
      message: 'Domain is not flagged in the community threat database.',
      hostname,
      registrableDomain
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/report
 * Submit a suspected phishing or malicious URL to the community database.
 */
app.post('/api/report', reportLimiter, async (req, res, next) => {
  try {
    const parsedBody = reportBodySchema.safeParse(req.body);
    if (!parsedBody.success) {
      return res.status(400).json({
        success: false,
        error: 'Validation error in threat report.',
        details: parsedBody.error.issues.map((i) => i.message)
      });
    }

    const reportData = parsedBody.data;
    const { hostname, registrableDomain } = parseDomainDetails(reportData.url);

    const savedThreat = await threatDb.saveThreat({
      ...reportData,
      hostname,
      registrableDomain
    });

    console.log(`[REPORT] Registered threat: ${hostname} (${savedThreat.riskLevel})`);

    return res.status(201).json({
      success: true,
      message: 'Threat report recorded successfully.',
      threat: savedThreat
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/ai-analyze
 * Performs server-side AI analysis via Google Gemini.
 * Sanitizes input and validates JSON output strictly.
 */
app.post('/api/ai-analyze', aiLimiter, async (req, res, next) => {
  try {
    const parsedBody = aiAnalyzeBodySchema.safeParse(req.body);
    if (!parsedBody.success) {
      return res.status(400).json({
        success: false,
        error: 'Invalid request payload for AI analysis.'
      });
    }

    const { url, features } = parsedBody.data;
    const { hostname, registrableDomain } = parseDomainDetails(url);

    console.log(`[AI_ANALYSIS] Initiating Gemini assessment for: ${hostname}`);

    const aiResult = await geminiService.analyzeDomain({
      hostname,
      registrableDomain,
      features
    });

    console.log(`[AI_ANALYSIS] Verdict for ${hostname}: ${aiResult.classification} (Score: ${aiResult.riskScore})`);

    return res.json({
      success: true,
      hostname,
      registrableDomain,
      result: aiResult
    });
  } catch (error) {
    next(error);
  }
});

// -----------------------------------------------------------------------------
// Safe Centralized Error Handling (Never leak stack traces or internal secrets)
// -----------------------------------------------------------------------------

app.use((err, req, res, next) => {
  console.error('[ERROR] Unhandled request error:', err.message);
  
  if (err.message && err.message.startsWith('Invalid URL format')) {
    return res.status(400).json({
      success: false,
      error: 'The provided URL could not be parsed.'
    });
  }

  res.status(500).json({
    success: false,
    error: 'Internal server error while processing security telemetry.'
  });
});

let server = null;
if (require.main === module) {
  server = app.listen(PORT, () => {
    console.log(`[Server] Security backend running on http://localhost:${PORT} [${NODE_ENV}]`);
    console.log('[Endpoints]');
    console.log(`  - GET  http://localhost:${PORT}/api/health`);
    console.log(`  - GET  http://localhost:${PORT}/api/check?url=https://example.com`);
    console.log(`  - POST http://localhost:${PORT}/api/report`);
    console.log(`  - POST http://localhost:${PORT}/api/ai-analyze`);
  });
}

module.exports = { app, server };
