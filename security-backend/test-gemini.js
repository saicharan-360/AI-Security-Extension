require('dotenv').config();

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

if (!GEMINI_API_KEY || GEMINI_API_KEY.trim() === '') {
  console.error('❌ GEMINI_API_KEY is missing from .env');
  process.exit(1);
}

const GEMINI_API_ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent`;

async function test() {
  console.log('Testing Gemini API connectivity...');
  try {
    const response = await fetch(GEMINI_API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': GEMINI_API_KEY.trim()
      },
      body: JSON.stringify({
        contents: [{ parts: [{ text: "Hello, reply with just 'OK'" }] }]
      })
    });
    console.log("Status:", response.status);
    const text = await response.text();
    console.log("Response:", text);
    
    if (response.ok) {
        console.log('✅ GEMINI_API_KEY IS VALID AND WORKING!');
    } else {
        console.error('❌ Gemini API returned an error status.');
    }
  } catch (err) {
    console.error('❌ Connection failed:', err.message);
  }
}
test();
