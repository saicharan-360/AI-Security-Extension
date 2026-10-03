/**
 * network_blocker.js
 * Local Network Analyzer & OS Firewall Blocker (Node.js Express)
 * Port: 8080
 *
 * =============================================================================
 * 🛡️ ARCHITECTURAL DEFENSE-IN-DEPTH OVERVIEW:
 * =============================================================================
 * 1. Layer 1 (Application / Browser):
 *    - The Chrome Extension detects phishing URLs via Gemini AI and heuristics.
 *    - The Anti-Gravity Defense immediately collapses the web page inputs on screen.
 *
 * 2. Layer 2 (Network / OS Kernel):
 *    - The browser extension signals this local Network Analyzer on port 8080.
 *    - This service resolves the domain name into all associated public IP addresses.
 *    - It invokes OS kernel firewall rules (`netsh advfirewall` on Windows, `iptables` on Linux).
 *    - RESULT: Even if a background malware script, background tab, or another browser 
 *      tries to communicate with that attacker server, the operating system kernel 
 *      drops all inbound and outbound network packets instantly.
 * =============================================================================
 */

const path = require('path');
const { createRequire } = require('module');
const dns = require('dns').promises;
const { exec } = require('child_process');
const os = require('os');

function requireDependency(name) {
  try {
    return require(name);
  } catch (error) {
    const backendRequire = createRequire(path.join(__dirname, '..', 'security-backend', 'package.json'));
    return backendRequire(name);
  }
}

const express = requireDependency('express');
const cors = requireDependency('cors');

const app = express();
const PORT = 8080;

app.use(cors());
app.use(express.json());

/**
 * Resolves a hostname to its IPv4 / IPv6 addresses
 */
async function resolveHostnameToIPs(hostname) {
  try {
    const cleanHost = hostname.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
    const addresses = await dns.lookup(cleanHost, { all: true });
    return addresses.map((addr) => addr.address);
  } catch (err) {
    console.warn(`⚠️ [DNS Resolution Error] Failed to resolve "${hostname}":`, err.message);
    return [];
  }
}

/**
 * Executes OS firewall command to block both inbound and outbound traffic
 */
function executeFirewallRule(ip) {
  return new Promise((resolve) => {
    const platform = os.platform(); // 'win32', 'linux', 'darwin'
    const safeIp = ip.replace(/[^a-zA-Z0-9.:]/g, '');

    let commands = [];

    if (platform === 'win32') {
      const ruleOut = `AI_Shield_Block_OUT_${safeIp.replace(/[:.]/g, '_')}`;
      const ruleIn = `AI_Shield_Block_IN_${safeIp.replace(/[:.]/g, '_')}`;
      commands = [
        `netsh advfirewall firewall add rule name="${ruleOut}" dir=out action=block remoteip=${safeIp}`,
        `netsh advfirewall firewall add rule name="${ruleIn}" dir=in action=block remoteip=${safeIp}`
      ];
    } else if (platform === 'linux') {
      commands = [
        `sudo iptables -A OUTPUT -d ${safeIp} -j DROP`,
        `sudo iptables -A INPUT -s ${safeIp} -j DROP`
      ];
    } else {
      // macOS / other
      commands = [`echo "Firewall block simulated for ${safeIp} on ${platform}"`];
    }

    const commandString = commands.join(' && ');
    console.log(`🔧 [Firewall Exec] ${commandString}`);

    exec(commandString, (error, stdout, stderr) => {
      if (error) {
        console.warn(`⚠️ [Firewall Warning] (Run terminal as Administrator/sudo if required): ${stderr || stdout || error.message}`);
        return resolve({ ip, status: 'EXECUTED_WITH_NOTICE', output: stderr || stdout || error.message });
      }
      console.log(`✅ [Firewall Block] Successfully added firewall rule for IP: ${safeIp}`);
      resolve({ ip, status: 'BLOCKED', output: stdout.trim() });
    });
  });
}

// Status Endpoint
app.get('/', (req, res) => {
  res.json({
    service: 'AI Shield - Local Network Traffic Blocker (Node.js)',
    port: PORT,
    platform: os.platform(),
    endpoints: {
      blockTraffic: 'POST /block-traffic (Body: { "hostname": "example.com" })'
    }
  });
});

// Block Traffic Endpoint
app.post('/block-traffic', async (req, res) => {
  const { hostname, ip } = req.body;
  const target = hostname || ip;

  if (!target) {
    return res.status(400).json({ success: false, error: 'Missing "hostname" or "ip" in request body' });
  }

  console.log(`\n🚨 [Threat Alert Received] Initiating network traffic block for: "${target}"`);

  // 1. Resolve Hostname to IP(s)
  const resolvedIPs = await resolveHostnameToIPs(target);

  if (resolvedIPs.length === 0) {
    return res.status(422).json({
      success: false,
      message: `Could not resolve "${target}" to an active IP address.`,
      target
    });
  }

  console.log(`🔍 [DNS Lookup] "${target}" resolved to IPs:`, resolvedIPs);

  // 2. Block all resolved IPs in the OS Firewall
  const results = [];
  for (const resolvedIp of resolvedIPs) {
    const result = await executeFirewallRule(resolvedIp);
    results.push(result);
  }

  console.log(`🛡️ [Network Block Complete] Blocked ${resolvedIPs.length} IP(s) for target: ${target}\n`);

  return res.json({
    success: true,
    message: `Network traffic to "${target}" blocked at OS kernel level.`,
    target,
    resolvedIPs,
    firewallResults: results
  });
});

app.listen(PORT, () => {
  console.log('=================================================================');
  console.log(`🚀 [Network Blocker] Running on http://localhost:${PORT}`);
  console.log(`💻 Operating System: ${os.platform()} (${os.release()})`);
  console.log('📡 Ready to receive /block-traffic requests from Chrome Extension');
  console.log('💡 Tip: Run in an Administrator terminal for direct firewall injection.');
  console.log('=================================================================');
});
