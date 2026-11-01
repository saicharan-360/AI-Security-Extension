/**
 * Server-Side Gemini AI Phishing / Malicious Domain Analysis Service
 * Securely communicates with Google Generative Language API using server credentials.
 */

const GEMINI_MODEL = 'gemini-3.5-flash-lite';
const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

class GeminiService {
  constructor() {
    this.apiKey = process.env.GEMINI_API_KEY || '';
  }

  isConfigured() {
    return Boolean(this.apiKey && this.apiKey.trim().length > 5);
  }

  /**
   * Analyzes domain features using Gemini with strict timeout and structured schema validation.
   * @param {Object} input - { hostname, registrableDomain, features }
   * @returns {Promise<{ classification: string, riskScore: number, confidence: number, reasons: string[] }>}
   */
  async analyzeDomain({ hostname, registrableDomain, features }) {
    if (!this.isConfigured()) {
      return {
        classification: 'UNKNOWN',
        riskScore: 0.5,
        confidence: 0.0,
        reasons: ['AI security engine not configured on server. Falling back to local defense.'],
        source: 'AI_FALLBACK'
      };
    }

    const featureSummary = features ? JSON.stringify(features, null, 2) : 'None provided';
    
    const prompt = `You are a specialized cybersecurity threat intelligence model evaluating whether a domain is likely used for phishing, social engineering, credential harvesting, or brand impersonation.

Domain Under Inspection: "${hostname}" (Registrable Domain: "${registrableDomain}")
Extracted Structural Features:
${featureSummary}

Evaluation Guidelines:
1. Do NOT classify a domain as malicious simply because it contains words like 'login', 'update', or 'account' unless structural and domain patterns indicate deceptive impersonation.
2. Consider whether the domain uses character spoofing (Punycode / IDN homograph), brand name hijacking in subdomains/hyphenations (e.g., brand-login.com), or abnormal high entropy.
3. Return a STRICT JSON object only. No markdown fences, no explanatory pre-text.

JSON Output Schema:
{
  "classification": "SAFE" | "SUSPICIOUS" | "HIGH_RISK" | "UNKNOWN",
  "riskScore": <number between 0.0 and 1.0>,
  "confidence": <number between 0.0 and 1.0>,
  "reasons": [<list of specific concise technical observations>]
}`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000); // 6 second strict timeout

    try {
      const endpoint = `${GEMINI_API_BASE}/${GEMINI_MODEL}:generateContent`;
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': this.apiKey.trim()
        },
        signal: controller.signal,
        body: JSON.stringify({
          contents: [
            {
              parts: [{ text: prompt }]
            }
          ],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 500,
            responseMimeType: 'application/json'
          }
        })
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        console.warn(`[GeminiService] API returned status ${response.status}`);
        return {
          classification: 'UNKNOWN',
          riskScore: 0.5,
          confidence: 0.0,
          reasons: [`AI service responded with HTTP status ${response.status}`],
          source: 'AI_SERVICE_ERROR'
        };
      }

      const data = await response.json();
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
      
      return this.parseAndValidateResponse(rawText);
    } catch (err) {
      clearTimeout(timeoutId);
      const isTimeout = err.name === 'AbortError';
      console.warn(`[GeminiService] Error: ${isTimeout ? 'Request timed out' : err.message}`);
      return {
        classification: 'UNKNOWN',
        riskScore: 0.5,
        confidence: 0.0,
        reasons: [isTimeout ? 'AI analysis timed out' : 'AI analysis temporarily unavailable'],
        source: 'AI_SERVICE_UNAVAILABLE'
      };
    }
  }

  /**
   * Safely parses and validates structured JSON output from Gemini.
   */
  parseAndValidateResponse(rawText) {
    try {
      // Strip potential markdown code blocks if returned
      let cleaned = rawText.trim();
      if (cleaned.startsWith('```')) {
        cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
      }

      const parsed = JSON.parse(cleaned);

      const validClassifications = ['SAFE', 'SUSPICIOUS', 'HIGH_RISK', 'UNKNOWN'];
      const classification = validClassifications.includes(parsed.classification)
        ? parsed.classification
        : 'UNKNOWN';

      let riskScore = typeof parsed.riskScore === 'number' ? parsed.riskScore : 0.5;
      riskScore = Math.max(0, Math.min(1, riskScore));

      let confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.5;
      confidence = Math.max(0, Math.min(1, confidence));

      const reasons = Array.isArray(parsed.reasons)
        ? parsed.reasons.map((r) => String(r).slice(0, 200)).filter(Boolean)
        : ['AI evaluation completed.'];

      return {
        classification,
        riskScore,
        confidence,
        reasons,
        source: 'GEMINI_AI'
      };
    } catch (err) {
      console.warn('[GeminiService] Failed to parse model output as JSON:', rawText);
      return {
        classification: 'UNKNOWN',
        riskScore: 0.5,
        confidence: 0.0,
        reasons: ['Unable to parse structured model response.'],
        source: 'AI_PARSE_ERROR'
      };
    }
  }
}

module.exports = new GeminiService();
