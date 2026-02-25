import ollama
import subprocess
import requests
import sys
import threading
import time

# Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def loading(stop_event, message):
    spinner = ['|', '/', '-', '\\']
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f'\r{message} {spinner[i % len(spinner)]}')
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write('\r' + ' ' * (len(message) + 2) + '\r')

def get_cves(service):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
    response = requests.get(url)
    data = response.json()
    
    cves = []
    for item in data["vulnerabilities"][:3]:
        cve = item["cve"]
        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]
        
        score = "N/A"
        if "cvssMetricV31" in cve["metrics"]:
            score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in cve["metrics"]:
            score = cve["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
        
        cves.append(f"{cve_id} (Score: {score}): {description}")
    
    return "\n".join(cves)

def parse_services(nmap_output):
    services = []
    for line in nmap_output.split('\n'):
        if 'open' in line:
            parts = line.split()
            if len(parts) >= 3:
                services.append(parts[2])
    return list(set(services))

# Scan selection
print(f"{CYAN}Select scan type:{RESET}")
print("1. -sV  - Version detection (identify what software is running on each port)")
print("2. -sS  - SYN scan (fast and stealthy, sends half-open connections, requires root)")
print("3. -A   - Aggressive scan (version detection + OS detection + scripts, noisy)")
print("4. -p-  - Full port scan (scans all 65535 ports instead of just common ones, slow)")
print("5. -sU  - UDP scan (scans UDP ports instead of TCP, requires root)")

choice = input(f"\n{CYAN}Enter choice (1-5): {RESET}")

scan_map = {
    "1": "-sV",
    "2": "-sS",
    "3": "-A",
    "4": "-p-",
    "5": "-sU"
}

scan_flag = scan_map.get(choice, "-sV")
target = input(f"{CYAN}Enter target: {RESET}")

print(f"\n{GREEN}Starting scan on {target} using {scan_flag}...{RESET}")

stop = threading.Event()
t = threading.Thread(target=loading, args=(stop, "Scanning"))
t.start()

nmap_result = subprocess.run(
    ["nmap", scan_flag, target],
    capture_output=True,
    text=True
)

stop.set()
t.join()

print(f"{GREEN}Scan complete.{RESET}\n")

services = parse_services(nmap_result.stdout)

all_cves = ""
for service in services:
    print(f"Looking up CVEs for {CYAN}{service}{RESET}...")
    cves = get_cves(service)
    if cves:
        all_cves += f"\n{service}:\n{cves}\n"

print()

stop2 = threading.Event()
t2 = threading.Thread(target=loading, args=(stop2, "AI analyzing results"))
t2.start()

response = ollama.chat(
    model="llama3.2:1b",
    messages=[
        {
            "role": "user",
            "content": f"""You are a cybersecurity analyst. 

STRICT RULES:
- ONLY use data provided below. Do not add anything you were not given.
- If you do not have enough data to fill a section, write "Insufficient data" for that section.
- Do NOT invent CVE IDs, scores, or service names.
- Do NOT add extra sections.

Respond ONLY in this format:

OPEN PORTS:
[+] <port number> - <service name> - <version if known>

KNOWN VULNERABILITIES:
[-] <CVE ID> - Score: <score> - <one sentence description>

POTENTIAL RISKS:
[-] <specific risk based on the services found>

RECOMMENDED NEXT STEPS:
[*] <specific action a penetration tester should take>

DATA TO ANALYZE:

Nmap results:
{nmap_result.stdout}

Known CVEs (use ONLY these, do not invent others):
{all_cves}"""
        }
    ]
)

stop2.set()
t2.join()

output = response["message"]["content"]

# Color coded output
colored = ""
for line in output.split('\n'):
    if line.startswith('[+]'):
        colored += GREEN + line + RESET + '\n'
    elif line.startswith('[-]'):
        colored += RED + line + RESET + '\n'
    elif line.startswith('[*]'):
        colored += YELLOW + line + RESET + '\n'
    elif line.isupper():
        colored += CYAN + line + RESET + '\n'
    else:
        colored += line + '\n'

print(colored)
