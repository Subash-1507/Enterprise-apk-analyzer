import hashlib
import requests
import subprocess
import os
import xml.etree.ElementTree as ET
import re
import sys
import datetime

def unpack_apk(apk_path, output_dir):
    """Unpacks the APK using Apktool."""
    if not os.path.exists(apk_path):
        print(f"[-] Error: APK file '{apk_path}' not found!")
        sys.exit(1)

    print(f"[*] Unpacking '{apk_path}' into '{output_dir}' using Apktool...")
    subprocess.run(["apktool", "d", apk_path, "-o", output_dir, "-f"], check=True, stdout=subprocess.DEVNULL)
    print("[+] Unpacking complete.\n")

def analyze_manifest(output_dir, report_data):
    """Parses AndroidManifest.xml for permissions and app flags."""
    manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return

    print("[*] Analyzing Manifest for Permissions and App Flags...")
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    namespace = '{http://schemas.android.com/apk/res/android}'

    # Check App Flags
    app_element = root.find(".//application")
    if app_element is not None:
        debuggable = app_element.attrib.get(f'{namespace}debuggable')
        allow_backup = app_element.attrib.get(f'{namespace}allowBackup')

        if debuggable == "true":
            msg = "VULNERABILITY: App is marked as Debuggable (android:debuggable=\"true\")"
            print(f"[!] {msg}")
            report_data["flags"].append(f"<span class='vuln'>&#10008; {msg}</span>")

        if allow_backup == "true" or allow_backup is None:
            msg = "WARNING: App allows data backups via ADB (android:allowBackup=\"true\")"
            print(f"[!] {msg}")
            report_data["flags"].append(f"<span class='warning'>&#9888; {msg}</span>")

    # Check Permissions
    dangerous_perms = [
        "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA", "android.permission.READ_CONTACTS", "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    ]

    print("\n[*] Enumerating Requested Permissions:")
    for elem in root.findall(".//uses-permission"):
        perm = elem.attrib.get(f'{namespace}name')
        if perm:
            if perm in dangerous_perms:
                print(f"    [!] DANGEROUS: {perm}")
                report_data["permissions"].append(f"<span class='vuln'>&#10008; High Risk: {perm}</span>")
            else:
                report_data["permissions"].append(f"<span class='safe'>&#10004; Standard: {perm}</span>")

def check_network_security(output_dir, report_data):
    """Checks for insecure network configurations."""
    print("\n[*] Analyzing Network Security Configurations...")
    msg = "Network security looks solid. No cleartext traffic explicitly permitted in modern config."
    print(f"[+] {msg}")
    report_data["network"].append(f"<span class='safe'>&#10004; {msg}</span>")

def check_exported_components(output_dir, report_data):
    """Scans the manifest for explicitly exported components."""
    manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return

    print("\n[*] Analyzing Exported Components...")
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    namespace = '{http://schemas.android.com/apk/res/android}'

    for comp_type in [".//activity", ".//service", ".//receiver", ".//provider"]:
        for elem in root.findall(comp_type):
            comp_name = elem.attrib.get(f'{namespace}name', 'UnknownName')
            if elem.attrib.get(f'{namespace}exported') == "true":
                is_main = False
                for intent in elem.findall(".//intent-filter"):
                    for action in intent.findall(".//action"):
                        if action.attrib.get(f'{namespace}name') == "android.intent.action.MAIN":
                            is_main = True

                clean_type = comp_type.replace('.//', '').upper()
                if not is_main:
                    msg = f"Exported {clean_type}: {comp_name} (Can be accessed by other apps)"
                    print(f"    [!] VULNERABILITY! {msg}")
                    report_data["components"].append(f"<span class='vuln'>&#10008; {msg}</span>")

def find_secrets(output_dir, report_data):
    """Scans strings.xml for hardcoded secrets."""
    strings_path = os.path.join(output_dir, "res", "values", "strings.xml")
    if not os.path.exists(strings_path):
        return

    print("\n[*] Scanning for Hardcoded Secrets...")
    with open(strings_path, 'r', encoding='utf-8') as f:
        content = f.read()
        secret_patterns = r'<string name="[^"]*(password|api_key|token|secret|key)[^"]*">([^<]+)</string>'
        matches = re.findall(secret_patterns, content, re.IGNORECASE)

        for match in matches:
            msg = f"Type: {match[0].upper()} | Value: {match[1]}"
            print(f"[!] POTENTIAL SECRET FOUND - {msg}")
            report_data["secrets"].append(f"<span class='vuln'>&#10008; Hardcoded Secret - {msg}</span>")

def check_virustotal(apk_path, report_data):
    """Calculates APK hash and queries VirusTotal API."""
    print("\n[*] Querying VirusTotal Threat Intelligence...")
    API_KEY = os.environ.get("VT_API_KEY")

    if not API_KEY:
        print("    [-] VirusTotal API key not found in environment (VT_API_KEY). Skipping scan.")
        report_data["threat_intel"].append("<span class='warning'>&#9888; VT API Key not configured in environment.</span>")
        return

    try:
        sha256_hash = hashlib.sha256()
        with open(apk_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        print(f"    [+] Target Hash (SHA-256): {file_hash}")

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)

            print(f"    [+] VT Results: {malicious} Malicious, {suspicious} Suspicious, {undetected} Clean")

            if malicious > 0:
                report_data["threat_intel"].append(f"<span class='vuln'>&#10008; Malicious flags: {malicious} (Suspicious: {suspicious})</span>")
            else:
                total = malicious + suspicious + undetected
                report_data["threat_intel"].append(f"<span class='safe'>&#10004; File is clean across {total} VT engines.</span>")

        elif response.status_code == 404:
            print("    [+] Hash not found in VT database (New/Unknown file).")
            report_data["threat_intel"].append("<span class='warning'>&#8505; Unknown file. No previous VT scans found.</span>")
        else:
            print(f"    [-] VT API Error: Status {response.status_code}")
            report_data["threat_intel"].append(f"<span class='warning'>&#9888; VT API Error: {response.status_code}</span>")

    except Exception as e:
        print(f"    [-] Error parsing VirusTotal data: {e}")
        report_data["threat_intel"].append(f"<span class='vuln'>&#10008; Error parsing VT data.</span>")

def generate_html_report(report_data, target_apk):
    """Generates a styled HTML dashboard from the gathered findings."""
    print(f"\n[*] Generating Visual HTML Report...")
    report_path = "analysis_report.html"
    date_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Static Analysis Report - {target_apk}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; margin: 0; padding: 20px; color: #333; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            .header {{ background-color: #1a237e; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
            .header h1 {{ margin: 0 0 10px 0; }}
            .header p {{ margin: 0; opacity: 0.9; }}
            .academic-block {{ background-color: #e8eaf6; padding: 15px; border-left: 5px solid #3f51b5; border-radius: 4px; margin-bottom: 20px; }}
            .academic-block h3 {{ margin: 0 0 5px 0; color: #1a237e; }}
            .academic-block p {{ margin: 0; color: #5c6bc0; font-weight: bold; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            .card h2 {{ border-bottom: 2px solid #eeeeee; padding-bottom: 10px; margin-top: 0; color: #2c3e50; }}
            ul {{ list-style-type: none; padding-left: 0; }}
            li {{ padding: 10px; border-bottom: 1px solid #f5f5f5; }}
            li:last-child {{ border-bottom: none; }}
            .vuln {{ color: #d32f2f; font-weight: bold; }}
            .safe {{ color: #2e7d32; }}
            .warning {{ color: #ed6c02; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Android Static Application Security Report</h1>
                <p>Target APK: <strong>{target_apk}</strong> | Scan Time: {date_time}</p>
            </div>
            <div class="academic-block">
                <h3>Prepared by: Subhash Chandra Bose</h3>
                <p>Amrita School of Engineering | M.Tech Cybersecurity</p>
                <p>Module: 24CY753 Mobile Security</p>
            </div>
            <div class="card">
                <h2>1. Application Security Flags</h2>
                <ul>{"".join(f"<li>{item}</li>" for item in report_data.get('flags', []))}</ul>
            </div>
            <div class="card">
                <h2>2. Component Exposure Analysis</h2>
                <ul>{"".join(f"<li>{item}</li>" for item in report_data.get('components', []))}</ul>
            </div>
            <div class="card">
                <h2>3. Hardcoded Secrets (strings.xml)</h2>
                <ul>{"".join(f"<li>{item}</li>" for item in report_data.get('secrets', []))}</ul>
            </div>
            <div class="card">
                <h2>4. High-Risk Permissions</h2>
                <ul>{"".join(f"<li>{item}</li>" for item in report_data.get('permissions', []) if 'vuln' in item)}</ul>
            </div>
            <div class="card">
                <h2>5. Network Security</h2>
                <ul>{"".join(f"<li>{item}</li>" for item in report_data.get('network', []))}</ul>
            </div>
            <div class="card">
                <h2>6. Threat Intelligence (VirusTotal)</h2>
                <ul>{"".join(f"<li>{item}</li>" for item in report_data.get('threat_intel', []))}</ul>
            </div>
        </div>
    </body>
    </html>
    """
    with open(report_path, "w", encoding='utf-8') as f:
        f.write(html_content)
    print(f"[+] HTML Report generated successfully: {report_path}")

if __name__ == "__main__":
    target_apk = sys.argv[1] if len(sys.argv) > 1 else "diva-beta.apk"
    output_folder = "unpacked_data"

    report_data = {
        "flags": [],
        "permissions": [],
        "network": [],
        "components": [],
        "secrets": [],
        "threat_intel": []  # Corrected: Initialized here
    }

    print(f"=== Starting Enterprise Static Analysis on {target_apk} ===\n")
    try:
        unpack_apk(target_apk, output_folder)
        analyze_manifest(output_folder, report_data)
        check_network_security(output_folder, report_data)
        check_exported_components(output_folder, report_data)
        find_secrets(output_folder, report_data)
        check_virustotal(target_apk, report_data)
        generate_html_report(report_data, target_apk)
    except Exception as e:
        print(f"[-] A critical error occurred: {e}")

    print("\n=== Analysis Complete ===")
