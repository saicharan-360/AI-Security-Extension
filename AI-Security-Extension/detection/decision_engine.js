/**
 * Centralized Multi-Layer Security Decision Engine
 *
 * Implements the layered defense pipeline:
 * 1. URL Validation & Normalization
 * 2. Local Feature Extraction
 * 3. Local Model Evaluation (Weighted Heuristics)
 * 4. Community Threat Intelligence Lookup
 * 5. Conditional AI Deep Analysis (Only invoked for ambiguous/suspicious cases)
 * 6. Evidence Arbitration into: SAFE | SUSPICIOUS | HIGH_RISK | UNKNOWN
 */

import { extractUrlFeatures, evaluateLocalModel } from './local_model.js';
import { queryCommunityThreatDb, requestAiAnalysis, Logger } from '../services/api.js';

export class DecisionEngine {
  /**
   * Processes a target URL through the complete layered defense pipeline.
   * @param {string} rawUrl - Full URL to evaluate
   * @returns {Promise<Object>} Final arbitration decision
   */
  static async evaluateUrl(rawUrl) {
    Logger.log('URL_CHECK', `Evaluating URL: ${rawUrl}`);

    // Step 1: Basic URL Validation
    if (!rawUrl || typeof rawUrl !== 'string' || (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://'))) {
      return {
        verdict: 'UNKNOWN',
        riskScore: 0.5,
        confidence: 0.0,
        reasons: ['Non-HTTP(S) protocol or invalid URL structure.'],
        summary: 'Cannot inspect non-web protocols',
        sources: []
      };
    }

    // Step 2: Local Feature Extraction
    const features = extractUrlFeatures(rawUrl);
    if (!features) {
      return {
        verdict: 'UNKNOWN',
        riskScore: 0.5,
        confidence: 0.0,
        reasons: ['Malformed URL structure.'],
        summary: 'Failed to parse URL features',
        sources: ['LOCAL_PARSER']
      };
    }

    // Step 3: Local Model Evaluation
    const localEval = evaluateLocalModel(features);
    Logger.log('LOCAL_ANALYSIS', `Local verdict: ${localEval.verdict} (Risk: ${localEval.riskScore}, Conf: ${localEval.confidence})`);

    // Fast-path: Verified whitelist domain with zero negative indicators
    if (features.isWhitelisted && localEval.verdict === 'SAFE') {
      return {
        verdict: 'SAFE',
        riskScore: localEval.riskScore,
        confidence: localEval.confidence,
        hostname: features.hostname,
        reasons: localEval.reasons,
        summary: 'Verified trusted high-reputation domain.',
        sources: ['LOCAL_WHITELIST']
      };
    }

    const sources = ['LOCAL_ANALYSIS'];
    const consolidatedReasons = [...localEval.reasons];
    let finalRiskScore = localEval.riskScore;
    let finalConfidence = localEval.confidence;

    // Step 4: Community Threat Intelligence Lookup
    const communityResult = await queryCommunityThreatDb(rawUrl);
    if (communityResult) {
      sources.push('COMMUNITY_DATABASE');
      if (communityResult.isMalicious && communityResult.threat) {
        Logger.log('DECISION', `Domain flagged in community threat database: ${communityResult.threat.reason}`);
        consolidatedReasons.unshift(`Community Threat DB Match: ${communityResult.threat.reason}`);
        return {
          verdict: 'HIGH_RISK',
          riskScore: 0.98,
          confidence: 0.99,
          hostname: features.hostname,
          threatType: communityResult.threat.threatType || 'PHISHING',
          reasons: consolidatedReasons,
          summary: `Identified malicious threat: ${communityResult.threat.reason}`,
          sources
        };
      }
    }

    // Step 5: Conditional AI Deep Analysis
    // Only invoke AI when local heuristics indicate SUSPICIOUS or UNCERTAIN risk,
    // avoiding unnecessary latency and costs on obvious SAFE or already confirmed HIGH_RISK domains.
    const shouldInvokeAi = localEval.verdict === 'SUSPICIOUS' ||
      (localEval.riskScore >= 0.35 && localEval.riskScore < 0.85);

    if (shouldInvokeAi) {
      Logger.log('AI_ANALYSIS', `Triggering AI deep inspection for ${features.hostname} (Local score: ${localEval.riskScore})`);
      const aiResult = await requestAiAnalysis(rawUrl, features);

      if (aiResult && aiResult.classification !== 'UNKNOWN') {
        sources.push('GEMINI_AI');
        // Blend AI risk score with local heuristics (60% AI weight, 40% local weight)
        finalRiskScore = Number((aiResult.riskScore * 0.60 + localEval.riskScore * 0.40).toFixed(2));
        finalConfidence = Number(((aiResult.confidence + localEval.confidence) / 2).toFixed(2));

        if (aiResult.reasons && aiResult.reasons.length > 0) {
          consolidatedReasons.push(...aiResult.reasons.map(r => `AI: ${r}`));
        }

        if (aiResult.classification === 'HIGH_RISK') {
          finalRiskScore = Math.max(finalRiskScore, 0.80);
        } else if (aiResult.classification === 'SAFE') {
          finalRiskScore = Math.min(finalRiskScore, 0.30);
        }
      }
    }

    // Step 6: Final Arbitration Decision
    let verdict = 'SUSPICIOUS';
    if (finalRiskScore <= 0.25) {
      verdict = 'SAFE';
    } else if (finalRiskScore >= 0.70) {
      verdict = 'HIGH_RISK';
    } else {
      verdict = 'SUSPICIOUS';
    }

    const decision = {
      verdict,
      riskScore: finalRiskScore,
      confidence: finalConfidence,
      hostname: features.hostname,
      threatType: features.impersonatedBrand ? 'BRAND_IMPERSONATION' : 'PHISHING',
      reasons: consolidatedReasons,
      summary: consolidatedReasons.length > 0
        ? consolidatedReasons.slice(0, 2).join('; ')
        : 'Standard web traffic patterns.',
      sources
    };

    Logger.log('DECISION', `Final Verdict: ${decision.verdict} | Risk: ${(decision.riskScore * 100).toFixed(0)}% | Conf: ${(decision.confidence * 100).toFixed(0)}% | Sources: [${sources.join(', ')}]`);

    return decision;
  }
}
