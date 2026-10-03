/**
 * AI Security Shield - Environment and Runtime Configuration
 */

export const ENVIRONMENTS = {
  development: {
    name: 'development',
    backendUrl: 'http://localhost:5000',
    networkBlockerUrl: 'http://localhost:8080/block-traffic',
    requestTimeoutMs: 5000,
    enableDebugLogs: true
  },
  staging: {
    name: 'staging',
    backendUrl: 'https://staging-shield.example.com',
    networkBlockerUrl: 'http://localhost:8080/block-traffic',
    requestTimeoutMs: 6000,
    enableDebugLogs: true
  },
  production: {
    name: 'production',
    backendUrl: 'https://shield-api.example.com',
    networkBlockerUrl: 'http://localhost:8080/block-traffic',
    requestTimeoutMs: 6000,
    enableDebugLogs: false
  }
};

// Default environment - Change to 'production' for store release
export const CURRENT_ENV = 'development';

export const CONFIG = {
  ...ENVIRONMENTS[CURRENT_ENV],
  version: '2.0.0',
  cacheTtlMs: 10 * 60 * 1000, // 10 minutes cache TTL
  debounceDelayMs: 350,       // Tab update debounce delay
  scoring: {
    safeThreshold: 0.25,
    highRiskThreshold: 0.70,
    minConfidence: 0.75
  }
};
