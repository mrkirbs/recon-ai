# recon-ai

A Python-based network reconnaissance tool that combines Nmap scanning, real CVE lookup from the NVD database, and local AI analysis using Ollama.

Built as a learning project to explore AI-assisted security tooling.

---

## What it does

1. **Scan selection** — Presents a menu of Nmap scan types with an explanation of what each one does so you can choose the right approach for your target
2. **Nmap scan** — Runs the selected scan against your target to discover open ports and identify what software and versions are running on each one
3. **CVE lookup** — For every service nmap finds, the tool automatically queries the NVD (National Vulnerability Database) API to pull real known CVEs including severity scores
4. **AI analysis** — Feeds the nmap results and CVE data into a local AI model running via Ollama. The AI analyzes everything and produces a structured report
5. **Color coded report** — Output is color coded for readability. Green for open ports, red for vulnerabilities and risks, yellow for recommended next steps

---

## Requirements

- Kali Linux
- Python 3
- Nmap
- Ollama with llama3.2:1b model pulled
- Python libraries: ollama, requests

---

## Setup
```bash
# Create a virtual environment to keep dependencies isolated
python3 -m venv recon-env

# Activate the virtual environment
source recon-env/bin/activate

# Install required Python libraries
pip install ollama requests

# Pull the AI model (this downloads about 1.3GB)
ollama pull llama3.2:1b
```

---

## Usage
```bash
python3 recon.py
```

You will be prompted to:
1. Select a scan type from the menu (each option is explained)
2. Enter your target IP or hostname

For practice use `scanme.nmap.org` — this is a legal public target provided by Nmap specifically for testing.

---

## Scan types explained

| Option | Flag | Description |
|--------|------|-------------|
| 1 | -sV | Version detection — identifies software running on each open port |
| 2 | -sS | SYN scan — fast and stealthy, sends half-open connections, requires root |
| 3 | -A  | Aggressive — version detection + OS detection + scripts, noisy |
| 4 | -p- | Full port scan — scans all 65535 ports instead of just common ones, slow |
| 5 | -sU | UDP scan — scans UDP ports instead of TCP, requires root |

---

## Example output
```
OPEN PORTS:
[+] 22/tcp - ssh - OpenSSH 6.6.1p1 Ubuntu

KNOWN VULNERABILITIES:
[-] CVE-2000-0525 - Score: 10.0 - OpenSSH does not properly drop privileges when UseLogin is enabled

POTENTIAL RISKS:
[-] SSH on port 22 allows remote access and is running an outdated version

RECOMMENDED NEXT STEPS:
[*] Investigate the SSH version for known exploits and check for weak credentials
```

---

## Notes on AI accuracy

The AI model used (llama3.2:1b) is a small local model. It can occasionally generate inaccurate information. Always verify CVEs and findings against the NVD directly at nvd.nist.gov. This tool is meant to assist analysis, not replace it.

---

## Disclaimer

This tool is for educational purposes only. Only use it on targets you have explicit permission to scan. Unauthorized scanning is illegal.

---

## What I learned

- How to chain CLI security tools with Python
- How to query the NVD API for real CVE data
- How to use local AI models via Ollama for security analysis
- Prompt engineering to reduce AI hallucinations
- Setting up Python virtual environments on Kali
- Using threads to show loading indicators while waiting for slow operations
