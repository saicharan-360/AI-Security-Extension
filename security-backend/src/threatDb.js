const { createClient } = require('@supabase/supabase-js');

class ThreatDatabase {
  constructor() {
    this.supabaseUrl = process.env.SUPABASE_URL;
    this.supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
    this.memoryDb = new Map();
    this.isSupabaseConnected = false;
    this.client = null;

    this.init();
  }

  init() {
    if (this.supabaseUrl && this.supabaseKey) {
      try {
        this.client = createClient(this.supabaseUrl, this.supabaseKey, {
          auth: { persistSession: false }
        });
        this.isSupabaseConnected = true;
        console.log('[ThreatDb] Supabase client initialized.');
      } catch (err) {
        console.warn('[ThreatDb] Failed to initialize Supabase client:', err.message);
        this.isSupabaseConnected = false;
      }
    } else {
      console.warn('[ThreatDb] SUPABASE_URL or SUPABASE_KEY not set. Using in-memory database.');
    }
  }

  async withTimeout(promise, ms = 2500) {
    let timer;
    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Operation timed out after ${ms}ms`)), ms);
    });
    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      clearTimeout(timer);
    }
  }

  async checkHealth() {
    if (!this.isSupabaseConnected || !this.client) {
      return {
        mode: 'memory',
        connected: false,
        memoryCount: this.memoryDb.size
      };
    }

    try {
      const { error } = await this.withTimeout(
        this.client.from('threats').select('id').limit(1)
      );

      if (error) {
        return {
          mode: 'supabase',
          connected: false,
          error: error.message,
          memoryCount: this.memoryDb.size
        };
      }

      return {
        mode: 'supabase',
        connected: true,
        memoryCount: this.memoryDb.size
      };
    } catch (err) {
      return {
        mode: 'supabase',
        connected: false,
        error: err.message,
        memoryCount: this.memoryDb.size
      };
    }
  }

  async findThreat(hostname, registrableDomain) {
    const cleanHost = (hostname || '').toLowerCase().trim();
    const cleanReg = (registrableDomain || '').toLowerCase().trim();

    // 1. Try Supabase query if connected
    if (this.isSupabaseConnected && this.client) {
      try {
        const { data, error } = await this.withTimeout(
          this.client.from('threats')
            .select('*')
            .eq('status', 'ACTIVE')
            .or(`hostname.eq.${cleanHost},registrable_domain.eq.${cleanReg}`)
            .limit(1)
        );

        if (!error && data && data.length > 0) {
          return this.serializeThreat(data[0]);
        }
      } catch (err) {
        console.warn(`[ThreatDb] Supabase lookup error for ${cleanHost}:`, err.message);
      }
    }

    // 2. Fallback to in-memory store
    const memRecord = this.memoryDb.get(cleanHost) || (cleanReg ? this.memoryDb.get(cleanReg) : null);
    if (memRecord && memRecord.status === 'ACTIVE') {
      return this.serializeThreat(memRecord);
    }

    return null;
  }

  async saveThreat(report) {
    const cleanHost = (report.hostname || '').toLowerCase().trim();
    const cleanReg = (report.registrableDomain || cleanHost).toLowerCase().trim();
    const now = new Date().toISOString();

    const record = {
      hostname: cleanHost,
      registrable_domain: cleanReg,
      threat_type: report.threatType || 'PHISHING',
      risk_level: report.riskLevel || 'HIGH_RISK',
      reason: report.reason || 'Reported by community threat intelligence',
      source: report.source || 'COMMUNITY_REPORT',
      confidence: report.confidence != null ? report.confidence : 0.90,
      report_count: 1,
      status: 'ACTIVE',
      first_seen: now,
      last_seen: now,
      updated_at: now
    };

    // Save to memory store first for instant availability
    const existingMem = this.memoryDb.get(cleanHost);
    if (existingMem) {
      record.report_count = (existingMem.report_count || 1) + 1;
      record.first_seen = existingMem.first_seen || now;
      record.id = existingMem.id;
    } else {
      record.id = `mem-${Buffer.from(cleanHost).toString('base64url')}`;
    }
    this.memoryDb.set(cleanHost, record);
    if (cleanReg) this.memoryDb.set(cleanReg, record);

    // Persist to Supabase if connected
    if (this.isSupabaseConnected && this.client) {
      try {
        const { data, error } = await this.withTimeout(
          this.client.from('threats')
            .upsert(
              {
                hostname: record.hostname,
                registrable_domain: record.registrable_domain,
                threat_type: record.threat_type,
                risk_level: record.risk_level,
                reason: record.reason,
                source: record.source,
                confidence: record.confidence,
                last_seen: now,
                status: 'ACTIVE'
              },
              { onConflict: 'hostname' }
            )
            .select()
            .single()
        );

        if (!error && data) {
          return this.serializeThreat(data);
        } else if (error) {
          console.warn('[ThreatDb] Supabase upsert error:', error.message);
        }
      } catch (err) {
        console.warn('[ThreatDb] Supabase save error:', err.message);
      }
    }

    return this.serializeThreat(record);
  }

  serializeThreat(raw) {
    if (!raw) return null;
    return {
      id: raw.id,
      hostname: raw.hostname,
      registrableDomain: raw.registrable_domain || raw.registrableDomain,
      threatType: raw.threat_type || raw.threatType || 'PHISHING',
      riskLevel: raw.risk_level || raw.riskLevel || 'HIGH_RISK',
      reason: raw.reason,
      source: raw.source || 'COMMUNITY_REPORT',
      confidence: typeof raw.confidence === 'number' ? raw.confidence : 0.90,
      reportCount: raw.report_count || raw.reportCount || 1,
      status: raw.status || 'ACTIVE',
      firstSeen: raw.first_seen || raw.firstSeen,
      lastSeen: raw.last_seen || raw.lastSeen
    };
  }
}

module.exports = new ThreatDatabase();
