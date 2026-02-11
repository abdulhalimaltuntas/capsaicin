# Capsaicin v2.0 - Production-Grade Web Directory Scanner

A professional web directory fuzzer with advanced detection capabilities, designed for security testing and reconnaissance.

## Features

- **Smart Calibration**: Automatic baseline detection to reduce false positives
- **Secret Detection**: Built-in patterns for API keys, tokens, and credentials
- **WAF Detection**: Identifies common Web Application Firewalls
- **Method Fuzzing**: Automatically tests alternative HTTP methods on 405 responses
- **Bypass Attempts**: Active 403/401 bypass testing with header manipulation
- **Recursive Scanning**: Optional directory tree traversal
- **Rate Limiting**: Per-host request rate control
- **Circuit Breaker**: Automatic backoff for repeatedly failing targets
- **Retry Logic**: Exponential backoff with jitter for transient failures
- **Memory Protection**: Bounded response body reading (configurable limit)
- **Multiple Output Formats**: JSON and HTML reports

## Installation

```bash
go build -o capsaicin ./cmd/capsaicin
```

## Usage

### Basic Scan
```bash
capsaicin -u https://target.com -w wordlist.txt
```

### With Custom Headers (Authentication)
```bash
capsaicin -u https://api.target.com -w wordlist.txt \
  -H "Authorization: Bearer token123" \
  -H "Cookie: session=abc"
```

### Multi-Target Scan
```bash
cat targets.txt | capsaicin -w wordlist.txt -t 100
```

### Recursive Scanning with Rate Limiting
```bash
capsaicin -u https://target.com -w wordlist.txt \
  --depth 3 \
  --rate-limit 50 \
  -t 20
```

### Full Feature Example
```bash
capsaicin -u https://target.com -w wordlist.txt \
  -x php,html,txt \
  --depth 2 \
  --rate-limit 100 \
  --timeout 15 \
  --retries 3 \
  -o results.json \
  --html report.html
```

## Flags

### Required
- `-u string` - Target URL (or use STDIN for multiple targets)
- `-w string` - Path to wordlist file

### Optional
- `-t int` - Concurrent threads (default: 50)
- `-x string` - Extensions (comma-separated, e.g., php,html,txt)
- `-H string` - Custom headers (repeatable)
- `--timeout int` - Request timeout in seconds (default: 10)
- `--depth int` - Recursive scanning depth (0=disabled, default: 0)
- `--rate-limit int` - Max requests per second per host (0=unlimited, default: 0)
- `--retries int` - Retry attempts for failed requests (default: 2)
- `--max-response-mb int` - Max response body size in MB (default: 10)
- `-v` - Verbose mode (print every request)
- `-o string` - JSON output file
- `--html string` - HTML report file

## Operational Safety

### Authorization Requirements
**CRITICAL**: This tool must only be used against systems you own or have explicit written authorization to test.

Unauthorized scanning of web applications may:
- Violate computer fraud and abuse laws
- Trigger security alerts and incident response
- Result in civil and criminal penalties
- Cause service disruptions

### Rate Limiting Best Practices
Always use appropriate rate limiting to avoid overwhelming target systems:

```bash
capsaicin -u https://target.com -w wordlist.txt --rate-limit 50 -t 20
```

Recommended settings:
- **Production systems**: `--rate-limit 10-20` with `-t 5-10` threads
- **Testing environments**: `--rate-limit 50-100` with `-t 20-50` threads
- **Local/development**: `--rate-limit 0` (unlimited) with `-t 50-100` threads

### Target Scope Discipline
- Always verify target ownership before scanning
- Document authorization in writing
- Define scope boundaries clearly
- Exclude out-of-scope domains and IPs
- Monitor for unintended requests

### Responsible Disclosure
If you discover vulnerabilities:
1. Document findings securely
2. Report to the organization's security team
3. Allow reasonable time for remediation
4. Do not publicly disclose without coordination

## Architecture

```
capsaicin/
├── cmd/capsaicin/         # Main entry point
├── internal/
│   ├── config/            # Configuration and flag parsing
│   ├── scanner/           # Core scanning engine
│   │   ├── engine.go      # Orchestration and lifecycle
│   │   ├── worker.go      # Request workers
│   │   ├── task.go        # Task types
│   │   └── stats.go       # Atomic metrics tracking
│   ├── detection/         # Pattern matching
│   │   ├── secrets.go     # Secret detection
│   │   ├── waf.go         # WAF identification
│   │   └── calibration.go # Baseline calibration
│   ├── transport/         # HTTP client layer
│   │   └── client.go      # Rate limiting, retry, circuit breaker
│   ├── reporting/         # Output generation
│   │   ├── json.go        # JSON export
│   │   └── html.go        # HTML report
│   └── ui/                # CLI formatting
│       └── output.go      # Terminal output
```

## Testing

### Run All Tests
```bash
go test ./... -v
```

### Run with Race Detector
```bash
go test ./... -race
```

### Run Specific Package Tests
```bash
go test ./internal/detection -v
go test ./internal/transport -v
go test ./internal/scanner -v
```

### Coverage Report
```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Key Improvements in v2.0

### Critical Engineering Fixes
1. **Deterministic Channel Lifecycle**: Proper goroutine coordination prevents deadlocks
2. **Accurate Metrics**: All counters use atomic operations for race-free tracking
3. **Single Calibration**: Per-target baseline computed once and cached
4. **WAF Counter Fix**: WAF detections now properly increment stats

### Advanced Safeguards
1. **Rate Limiting**: Token bucket per-host with configurable limits
2. **Retry Logic**: Exponential backoff with jitter for failed requests
3. **Circuit Breaker**: Automatic cooldown for repeatedly failing targets
4. **Memory Protection**: Bounded response reading prevents memory exhaustion

### Maintainability
1. **Package Structure**: Clear separation of concerns
2. **No Comments**: Self-documenting code through naming and structure
3. **Comprehensive Tests**: Unit and integration test coverage
4. **Clean UI**: Minimal, professional output

## Known Limitations

1. **TLS Certificate Validation**: Default client validates certificates; use with caution on self-signed certs
2. **JavaScript Rendering**: Does not execute JavaScript; static content only
3. **Session Management**: No built-in session handling for multi-step authentication
4. **Custom Protocols**: HTTP/HTTPS only; no support for WebSocket, gRPC, etc.
5. **Large Wordlists**: Memory usage scales with wordlist size for recursive scans

## Contributing

This is a production-grade refactoring focused on stability and maintainability. Contributions should:
- Include comprehensive tests
- Follow the no-comments coding standard
- Maintain deterministic behavior
- Add operational safety considerations

## License

Use responsibly and legally. This tool is provided as-is for authorized security testing only.