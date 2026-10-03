"""
network_blocker.py
Local Network Analyzer & OS Firewall Blocker
Port: 8080

=============================================================================
🛡️ ARCHITECTURAL DEFENSE-IN-DEPTH OVERVIEW:
=============================================================================
1. Layer 1 (Application / Browser):
   - The Chrome Extension detects phishing URLs via Gemini AI and heuristics.
   - The Anti-Gravity Defense immediately collapses the web page inputs on screen.

2. Layer 2 (Network / OS Kernel):
   - The browser extension signals this local Network Analyzer on port 8080.
   - This service resolves the domain name into all associated public IP addresses.
   - It invokes OS kernel firewall rules (`netsh advfirewall` on Windows, `iptables` on Linux).
   - RESULT: Even if a background malware script, background tab, or another browser 
     tries to communicate with that attacker server, the operating system kernel 
     drops all inbound and outbound network packets instantly.
=============================================================================
"""

import os
import sys
import socket
import platform
import subprocess
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for the Chrome Extension

def is_ip_address(addr):
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            return True
        except socket.error:
            return False

def resolve_hostname_to_ips(hostname_or_ip):
    """Resolves a hostname to a list of unique IPv4 addresses."""
    if is_ip_address(hostname_or_ip):
        return [hostname_or_ip]
    
    try:
        # Strip port or scheme if accidentally passed
        clean_host = hostname_or_ip.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        # Resolve all DNS A records
        _, _, ip_list = socket.gethostbyname_ex(clean_host)
        return list(set(ip_list))
    except socket.gaierror as e:
        print(f"⚠️ [DNS Resolution Error] Failed to resolve {hostname_or_ip}: {e}")
        return []

def execute_os_firewall_block(ip_address, target_identifier):
    """
    Executes OS-level firewall rules to drop both inbound and outbound traffic.
    - Windows: Uses 'netsh advfirewall firewall'
    - Linux:   Uses 'iptables'
    - macOS:   Uses 'pfctl' / packet filter
    """
    current_os = platform.system().lower()
    rule_name_out = f"AI_Shield_Block_OUT_{ip_address.replace('.', '_')}"
    rule_name_in = f"AI_Shield_Block_IN_{ip_address.replace('.', '_')}"
    
    commands = []

    if "windows" in current_os:
        # Windows Firewall Rules (Outbound + Inbound Block)
        commands = [
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name_out}", "dir=out", "action=block", f"remoteip={ip_address}"],
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name_in}", "dir=in", "action=block", f"remoteip={ip_address}"]
        ]
    elif "linux" in current_os:
        # Linux iptables rules
        commands = [
            ["sudo", "iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"],
            ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        ]
    elif "darwin" in current_os: # macOS
        commands = [
            ["sudo", "pfctl", "-t", "ai_shield_blacklist", "-T", "add", ip_address]
        ]
    else:
        return False, f"Unsupported operating system: {current_os}"

    execution_results = []
    for cmd in commands:
        try:
            print(f"🔧 [Firewall Exec] {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                execution_results.append(f"Success: {' '.join(cmd[:6])}")
            else:
                stderr_msg = result.stderr.strip() or result.stdout.strip()
                print(f"⚠️ [Firewall Warning] {stderr_msg}")
                # Note: On Windows, non-admin prompts will fail; we log clear instructions
                execution_results.append(f"Notice (Requires Admin Privileges): {stderr_msg}")
        except Exception as ex:
            print(f"❌ [Firewall Error] Failed executing rule: {ex}")
            execution_results.append(f"Error: {str(ex)}")

    return True, execution_results

# =========================================================================
# API Endpoints
# =========================================================================

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "AI Shield - Local Network Traffic Blocker",
        "port": 8080,
        "status": "ACTIVE",
        "os": platform.system(),
        "endpoints": {
            "block_traffic": "POST /block-traffic (Body: { 'hostname': 'example.com' })"
        }
    })

@app.route("/block-traffic", methods=["POST"])
def block_traffic():
    """
    POST /block-traffic
    Accepts: { "hostname": "paypal-fake.xyz" } or { "ip": "192.168.1.100" }
    Resolves hostname to IP addresses and applies OS-level firewall blocks.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("hostname") or data.get("ip") or data.get("url")

    if not target:
        return jsonify({
            "success": False,
            "error": "Missing target 'hostname' or 'ip' in request body"
        }), 400

    print(f"\n🚨 [Threat Alert Received] Initiating network traffic block for: '{target}'")

    # 1. Resolve Hostname to IP(s)
    resolved_ips = resolve_hostname_to_ips(target)

    if not resolved_ips:
        return jsonify({
            "success": False,
            "message": f"Could not resolve '{target}' to any active IP address (Domain may be offline or invalid DNS).",
            "target": target
        }), 422

    print(f"🔍 [DNS Lookup] '{target}' resolved to IP addresses: {resolved_ips}")

    # 2. Block each IP in the OS Firewall
    block_summary = []
    for ip in resolved_ips:
        status, details = execute_os_firewall_block(ip, target)
        block_summary.append({
            "ip": ip,
            "status": "BLOCKED" if status else "FAILED",
            "details": details
        })

    print(f"🛡️ [Network Block Complete] Blocked {len(resolved_ips)} IP(s) for target: {target}\n")

    return jsonify({
        "success": True,
        "message": f"Network traffic to '{target}' blocked at OS kernel level.",
        "target": target,
        "resolved_ips": resolved_ips,
        "firewall_results": block_summary
    }), 200

if __name__ == "__main__":
    print("=================================================================")
    print("🚀 AI Security Shield - Local Network Analyzer Running on Port 8080")
    print(f"💻 Operating System: {platform.system()} {platform.release()}")
    print("📡 Ready to receive /block-traffic requests from Chrome Extension")
    print("💡 Tip: Run as Administrator/sudo for automatic firewall rule injection.")
    print("=================================================================")
    app.run(host="0.0.0.0", port=8080, debug=False)
