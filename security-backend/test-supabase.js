require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ CONNECTION ERROR: SUPABASE_URL and either SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY must be in .env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

async function testConnection() {
  const { data, error } = await supabase.from('threats').select('id').limit(1);

  if (error) {
    if (error.code === '42P01') {
       console.warn('⚠️ CONNECTED TO SUPABASE, BUT "threats" TABLE DOES NOT EXIST YET.');
       console.log('Please execute the SQL commands in schema.sql in your Supabase SQL editor.');
       process.exit(0);
    } else {
       console.error('❌ CONNECTION ERROR:', error.message);
       process.exit(1);
    }
  }

  console.log('✅ CONNECTED SUCCESSFULLY TO SUPABASE AND "threats" TABLE EXISTS.');
  process.exit(0);
}

testConnection();
