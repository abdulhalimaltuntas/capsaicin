<div align="center">
  <img src="https://raw.githubusercontent.com/abdulhalimaltuntas/capsaicin/main/.github/assets/logo.png" alt="Capsaicin Logo" width="200" onerror="this.src='https://via.placeholder.com/200?text=🌶️+Capsaicin';">
  
  # 🌶️ Capsaicin v2
  
  **Next-Generation Web Directory & Asset Discovery Engine**  
  *Built for Red Teamers, Bug Bounty Hunters, and DevSecOps*

  [![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![CI](https://img.shields.io/badge/CI-passing-brightgreen)](/.github/workflows/ci.yml)
  [![Maintainer](https://img.shields.io/badge/Maintainer-abdulhalimaltuntas-blue.svg)](https://github.com/abdulhalimaltuntas)
  
  [Features](#-key-features) •
  [Why Capsaicin?](#-why-capsaicin-differentiators) •
  [Installation](#-installation) •
  [Usage](#-usage-examples) •
  [CI/CD](#-cicd-integration)
</div>

---

## 📖 Overview

**Capsaicin** is not just another directory brute-forcer. It's a highly concurrent, context-aware web discovery framework engineered to bypass modern Web Application Firewalls (WAFs), evade rate limits, and filter out false positives dynamically. 

Developed by [@abdulhalimaltuntas](https://github.com/abdulhalimaltuntas), Capsaicin V2 integrates advanced evasion techniques like **JA3/JA4 TLS Fingerprint Spoofing**, **Stochastic Jitter Engines**, and **Shannon Entropy Analysis** to uncover hidden paths, leaked secrets, and misconfigurations with surgical precision.

---

## 🔥 Why Capsaicin? (Differentiators)

While traditional tools (like `ffuf`, `gobuster`, or `dirb`) simply send requests and read status codes, Capsaicin acts like a human and thinks like an analyst:

- **WAF Evasion (TLS Spoofing):** Uses the `utls` library to spoof TLS fingerprints (JA3/JA4). To network appliances (IDS/IPS), Capsaicin looks exactly like a standard Google Chrome or Apple Safari browser, overriding the default Go HTTP client signatures.
- **Human-Like Delay (Jitter Engine):** Employs Gaussian and Pareto mathematical distributions to simulate real human browsing. The `paranoid` mode introduces stochastic pauses, easily bypassing baseline AI/ML-based rate limiters.
- **Smart Auto-Calibration:** Dynamically profiles targets with catch-all (wildcard) directories before scanning. It measures page size, line counts, and words to create a baseline, effectively eliminating false positives associated with custom 404 pages.
- **Information Theory for Secrets:** Doesn't just use Regex to find secrets. It uses **Shannon Entropy** analysis to verify if the discovered text is truly cryptographically random (like a real API key) or just a false alarm.
- **Stateful Method Fuzzing:** When encountering a `405 Method Not Allowed`, Capsaicin automatically rotates HTTP methods (`POST`, `PUT`, `DELETE`, `PATCH`) to aggressively hunt for misconfigured API endpoints.
- **Header Injection for 403 Bypass:** Automatically attempts to bypass access controls using smart header manipulation (`X-Forwarded-For`, `X-Original-URL`, etc.) when it encounters `403 Forbidden` errors.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🎯 **Smart Calibration** | Automatic 404 baseline creation to eliminate false-positives dynamically. |
| 🛡️ **TLS & WAF Bypass** | JA3/JA4 fingerprint spoofing + Header Injection (`X-Forwarded-For` etc.) for 403/401 bypass. |
| 🔑 **Secret Hunter** | 15 built-in patterns (AWS, Stripe, GitHub, etc.) scored with **Shannon Entropy**. |
| 🤖 **WAF Recognition** | Detects over 16 WAFs (Cloudflare, Akamai, AWS Shield, Imperva) via headers & signatures. |
| 🌊 **Stochastic Jitter** | Gaussian and Pareto distribution delays to avoid syn-flood alarms. |
| 🚦 **Circuit Breaker** | Auto-backs off failing targets to prevent infrastructure overload. |
| 🌳 **Recursive Scan** | Configurable depth-limited directory traversal. |
| 📊 **Dual Reporting** | Export findings in Version 3.1 JSON and Interactive HTML. |
| 🔁 **Deduplication** | Automatic URL+Method dedup, keeping the highest-severity finding. |
| 🚀 **CI/CD Native** | `--fail-on` flag to fail pipelines automatically on high/critical findings. |

---

## ⚙️ Installation

### Option 1: Using Go (Recommended)
Make sure you have Go 1.21+ installed.
```bash
go install github.com/abdulhalimaltuntas/capsaicin/cmd/capsaicin@latest
```

### Option 2: Build From Source
```bash
git clone https://github.com/abdulhalimaltuntas/capsaicin.git
cd capsaicin
go build -o capsaicin ./cmd/capsaicin
sudo mv capsaicin /usr/local/bin/
```

---

## ⚙️ Configuration Options (CLI Flags)

Capsaicin offers extensive configuration through command-line parameters to tailor your discovery and testing precisely to your needs.

### 🎯 Core & Target Options
| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url` | - | Target URL to scan (supports `FUZZ` keyword for dynamic wordlist injection). |
| `-w, --wordlist` | - | Path to the wordlist (e.g. `path/to/wordlist:FUZZ`). |
| `-X, --method` | `GET` | HTTP method to use for requests. |
| `-d, --data` | - | POST body data for requests. |

### 🚀 Performance & Network
| Flag | Default | Description |
|------|---------|-------------|
| `-t, --threads` | `40` | Number of concurrent request workers. |
| `--rate-limit` | `0` | Maximum requests per second per host (`0` = unlimited). |
| `--timeout` | `10` | Request timeout duration in seconds. |
| `--retries` | `2` | Number of retry attempts for failed network requests. |
| `--h2` | `true` | Force HTTP/2 multiplexing for higher performance and stealth. |
| `--h3` | `false` | Enable experimental HTTP/3 (QUIC) transport. |

### 🧠 Evasion & WAF Bypass
| Flag | Default | Description |
|------|---------|-------------|
| `--tls-impersonate`| `random` | JA3/JA4 spoofing profile (`chrome`, `firefox`, `safari`, `edge`, `random`, `none`). |
| `--jitter` | `moderate` | Stochastic delay profile to avoid rate limiters (`aggressive`, `moderate`, `stealth`, `paranoid`). |
| `--header-rotation`| `false` | Auto-rotate `User-Agent` and `Sec-CH-UA` headers coherently. |
| `-H, --header` | - | Custom header entry to send with every request (`Name: Value`, repeatable). |
| `--safe-mode` | `false` | Disables all bypass attempts, method fuzzing, and intrusive checks. |

### 🎛️ Fuzzing & Discovery
| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `sniper` | Fuzzing mode for multiple payloads (`sniper`, `clusterbomb`, `pitchfork`, `dynamic`). |
| `--extensions` | - | File extensions to probe (comma-separated, e.g. `php,html,txt`). |
| `--depth` | `0` | Recursive scanning depth (`0` = disabled). |
| `--extract-paths` | `false` | On-the-fly JavaScript and HTML scraping for new endpoints. |
| `--extract-depth` | `2` | Maximum recursion depth for dynamically extracted paths. |
| `--auto-calibrate` | `false` | Enable Smart Anomaly Detection (DOM Hash + Length Clustering) for false positives. |
| `--recal-interval` | `500` | Requests between rolling recalibration probes during scanning. |

### 🕵️‍♂️ Filtering & Matching
| Flag | Default | Description |
|------|---------|-------------|
| `--match-code` | `200...405` | Comma-separated HTTP status codes to match. |
| `--filter-code` | - | HTTP status codes to filter (exclude) from results. |
| `--match-size` | - | Match exact response sizes. |
| `--filter-size` | - | Filter (exclude) response by exact size. |
| `--filter-words` | - | Filter (exclude) responses by exact word count. |
| `--match-regex` | - | Match a specific regular expression in the response body. |
| `--max-response-mb`| `10` | Maximum response body size to process in MB. |
| `--allow` / `--deny`| - | Allowed / Denied domain patterns for recursive scope control (repeatable). |

### 📊 Reporting & State Management
| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output` | - | Path to save the output file. |
| `--output-format`| `jsonl` | Output data format (`jsonl`, `json`, `html`, `csv`). |
| `--html` | - | Legacy HTML report output file (v1 compat). |
| `--fail-on` | - | Exit code 2 if severity threshold is met (`critical`, `high`, `medium`, `low`, `info`). |
| `--trigger-config` | - | YAML file pointing to exploit triggers and webhook actions. |
| `--resume` | - | Provide a session state file path to resume a previously stopped scan. |

### 🛡️ Proxy Management
| Flag | Default | Description |
|------|---------|-------------|
| `-x, --proxy` | - | Proxy URL (supports HTTP/SOCKS5). |
| `--proxy-file` | - | File containing a list of proxies (one per line). |
| `--proxy-strategy` | `random` | Proxy rotation strategy (`round_robin`, `random`, `failover`). |

### ⚙️ Utilities
| Flag | Default | Description |
|------|---------|-------------|
| `-v, --verbose` | `false` | Enable verbose output. |
| `--debug` | `false` | Enable internal debug logging for developer troubleshooting. |
| `--log-level` | `info` | Adjust the verbosity of logging (`debug`, `info`, `warn`, `error`). |
| `--dry-run` | `false` | Check the scan execution plan without actually making requests. |

---

## 🚀 Usage Examples

### 1. Basic Scan
Run a standard scan against a target using a specific wordlist:
```bash
capsaicin -u https://target.com -w wordlist.txt
```

### 2. Stealth & Evasion Mode (Paranoid)
Enable jitter delays, random user-agents, and bypass mechanisms to evade strict WAFs without triggering alarms:
```bash
capsaicin -u https://target.com -w wordlist.txt \
  --rate-limit 15 \
  -t 10
```

### 3. Deep API Discovery
Hunt for specific file extensions, enable recursive scanning, and fuzz HTTP methods on `405` responses:
```bash
capsaicin -u https://api.target.com -w wordlist.txt \
  -x php,json,yaml,env \
  --depth 3 \
  --retries 3 \
  -v
```

### 4. Authenticated Scans & Custom Headers
Pass custom headers and cookies for behind-login discovery:
```bash
capsaicin -u https://admin.target.com -w wordlist.txt \
  -H "Authorization: Bearer eyJhbGci..." \
  -H "Cookie: session=abc123_secure"
```

### 5. Pipeline Mode (Stdin)
Feed multiple targets directly from other tools (e.g., `subfinder`, `httpx`):
```bash
cat targets.txt | capsaicin -w wordlist.txt -t 100 -o results.json
```

### 6. Safe Mode (No Intrusive Checks)
Disable bypass header injections and method fuzzing for standard, non-intrusive compliance scans:
```bash
capsaicin -u https://target.com -w wordlist.txt --safe-mode
```

---

## 🚦 CI/CD Integration

Capsaicin is built for DevSecOps. You can gate your pipeline deployments based on the severity of discovered assets.

**Exit Codes:**
- `0` : Clean (No findings met the threshold)
- `1` : Error (Invalid config, network down)
- `2` : Alert (Findings met or exceeded the `--fail-on` threshold)

**GitHub Actions / GitLab Pipeline Example:**
```bash
# Fail the pipeline ONLY if CRITICAL vulnerabilities (e.g., exposed AWS keys) are found
capsaicin -u https://staging.com -w words.txt --fail-on critical -o output.json
```

---

## 🗂️ Risk Scoring & Severity

Capsaicin enriches every finding with contextual metadata, preventing alert fatigue:

| Severity | Example Triggers | Confidence |
|----------|-----------------|------------|
| 🔴 **Critical** | AWS/Stripe Keys, Priv Keys, DB Conn Strings | Confirmed |
| 🟠 **High** | JWT Tokens, Slack/Google APIs, 403 Bypass Success | Confirmed/Firm |
| 🟡 **Medium** | Generic API Keys (Entropy Verified), Method Fuzz Success | Firm |
| 🟢 **Low** | Directory Listing, 401/403 Access Denied | Tentative |
| ⚪ **Info** | Standard 200 OK Responses | Tentative |

---

## 🛠️ Architecture Overview

Capsaicin operates on a highly optimized concurrent core. Here is the high-level request flow:

```text
CLI Input → Config Validation → Engine.RunContext(ctx)
    ↓
Calibration (Auto Base-Lining per target) → Worker Pool
    ↓
Worker: makeRequest → Calibration Filter → Detection Pipeline
    ↓                                          ↓
405? → Method Fuzzing               Secret Detection (Shannon Entropy)
403? → Bypass Injector              WAF Detection (Header + Body Hash)
    ↓
Results Channel → Deduplication Engine → Reporter (JSON 3.1 / HTML)
```

---

## ⚠️ Disclaimer

**Capsaicin is developed strictly for authorized security testing and educational research purposes.**
- Always ensure you have explicit, written permission from the system owner before scanning.
- Do not use this tool against infrastructure you do not own or have authorization to test.
- The developer (`@abdulhalimaltuntas`) assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by this tool.

---

<div align="center">
  <i>"Don't just scan it, burn through the noise."</i> <br>
  <b>Developed by <a href="https://github.com/abdulhalimaltuntas">Abdulhalim Altuntaş</a></b><br>
  <sub>Licensed under the MIT License.</sub>
</div>