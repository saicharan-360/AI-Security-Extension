-- ==============================================================================
-- Community Threat Database Schema (Supabase / PostgreSQL)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS threats (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  hostname text NOT NULL UNIQUE,
  registrable_domain text NOT NULL,
  threat_type text NOT NULL DEFAULT 'PHISHING' CHECK (threat_type IN ('PHISHING', 'MALWARE', 'SCAM', 'BRAND_IMPERSONATION', 'SUSPICIOUS', 'OTHER')),
  risk_level text NOT NULL CHECK (risk_level IN ('SAFE', 'SUSPICIOUS', 'HIGH_RISK', 'UNKNOWN')) DEFAULT 'HIGH_RISK',
  reason text NOT NULL DEFAULT 'Deceptive phishing or scam website',
  source text NOT NULL DEFAULT 'COMMUNITY_REPORT' CHECK (source IN ('COMMUNITY_REPORT', 'AI_ANALYSIS', 'HEURISTIC', 'ADMIN')),
  first_seen timestamp with time zone DEFAULT now(),
  last_seen timestamp with time zone DEFAULT now(),
  confidence numeric(3, 2) DEFAULT 0.90 CHECK (confidence >= 0.0 AND confidence <= 1.0),
  report_count integer DEFAULT 1 CHECK (report_count >= 1),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'PENDING_REVIEW', 'RESOLVED', 'FALSE_POSITIVE')) DEFAULT 'ACTIVE',
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now()
);

-- Optimized Indexes for High-Traffic Lookups
CREATE INDEX IF NOT EXISTS idx_threats_hostname ON threats (hostname);
CREATE INDEX IF NOT EXISTS idx_threats_registrable_domain ON threats (registrable_domain);
CREATE INDEX IF NOT EXISTS idx_threats_status ON threats (status);
CREATE INDEX IF NOT EXISTS idx_threats_risk_level ON threats (risk_level);

-- Enable Row Level Security (RLS)
ALTER TABLE threats ENABLE ROW LEVEL SECURITY;

-- Drop prior permissive policies if they exist, then recreate
DROP POLICY IF EXISTS "Enable read access for all users" ON threats;
DROP POLICY IF EXISTS "Enable insert access for all users" ON threats;
DROP POLICY IF EXISTS "Enable update access for all users" ON threats;

CREATE POLICY "Enable read access for all users" ON threats 
  FOR SELECT USING (status = 'ACTIVE');

CREATE POLICY "Enable insert access for all users" ON threats 
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Enable update access for all users" ON threats 
  FOR UPDATE USING (true);
