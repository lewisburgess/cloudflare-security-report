# Cloudflare Security Audit Report

A PowerShell script that audits security settings across all Cloudflare zones and generates detailed CSV and HTML reports with RAG (Red/Amber/Green) status indicators.

## Features

- **Multi-zone auditing** — Scans all zones in your Cloudflare account (or specific zones)
- **Comprehensive coverage** — SSL/TLS, HSTS, security settings, bot management, DNS, caching, workers, rules
- **RAG status indicators** — Visual traffic-light system highlighting issues and recommendations
- **Interactive HTML report** — Filterable tables, tooltips, documentation links
- **Rule deduplication** — Eliminates duplicate entries for accurate reporting
- **Security.txt capture** — Full content export of security.txt configurations
- **Cross-zone comparison** — Filter rules by type to compare settings across domains

## Requirements

- **PowerShell 5.1+** (Windows) or **PowerShell Core 7+** (Windows/macOS/Linux)
- **Cloudflare API Token** with the following permissions:

| Permission | Access Level | Required For |
|------------|--------------|--------------|
| Zone | Read | Zone list and basic info |
| Zone Settings | Read | SSL, security, speed settings |
| DNS | Read | DNSSEC status |
| Page Rules | Read | Legacy page rules |
| Zone WAF | Read | Firewall rules |
| Dynamic Redirect | Read | Redirect rules |
| Config Rules | Read | Configuration rules |
| Workers Routes | Read | Worker route mappings |
| Firewall Services | Read | IP access rules, rate limits |
| Account Settings | Read | Account ID for dashboard links |

### Creating an API Token

1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use **Create Custom Token**
4. Add the permissions listed above
5. Set **Zone Resources** to "Include All Zones" (or specific zones)
6. Create and copy the token

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cloudflare-security-audit.git
cd cloudflare-security-audit

# Or download directly
curl -O https://raw.githubusercontent.com/yourusername/cloudflare-security-audit/main/Get-CloudflareSecurityReport.ps1
```

## Usage

### Basic Usage

```powershell
# Will prompt for API token if not configured
.\Get-CloudflareSecurityReport.ps1

# With API token
.\Get-CloudflareSecurityReport.ps1 -ApiToken "your_api_token_here"
```

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ApiToken` | String | No* | — | Cloudflare API token. *Required if not set via environment variable or script default |
| `-OutputPath` | String | No | Current directory | Directory where reports will be saved |
| `-IncludeRules` | Boolean | No | `$true` | Include detailed rules export (page rules, redirects, WAF, etc.) |
| `-Zones` | String[] | No | All zones | Array of specific zone names to audit |

### Examples

```powershell
# Audit all zones, save to specific directory
.\Get-CloudflareSecurityReport.ps1 -ApiToken "abc123" -OutputPath "C:\Reports\Cloudflare"

# Audit specific zones only
.\Get-CloudflareSecurityReport.ps1 -ApiToken "abc123" -Zones @("example.com", "example.org")

# Skip rules collection for faster execution
.\Get-CloudflareSecurityReport.ps1 -ApiToken "abc123" -IncludeRules $false

# Use environment variable for token
$env:CF_API_TOKEN = "your_api_token_here"
.\Get-CloudflareSecurityReport.ps1
```

## Configuration Methods

The script supports three methods for providing the API token (checked in this order):

### 1. Command Line Parameter (Highest Priority)

```powershell
.\Get-CloudflareSecurityReport.ps1 -ApiToken "your_token"
```

### 2. Environment Variable

```powershell
# Windows PowerShell
$env:CF_API_TOKEN = "your_token"
.\Get-CloudflareSecurityReport.ps1

# Linux/macOS
export CF_API_TOKEN="your_token"
pwsh ./Get-CloudflareSecurityReport.ps1
```

To persist the environment variable:

**Windows (User level):**
```powershell
[Environment]::SetEnvironmentVariable("CF_API_TOKEN", "your_token", "User")
```

**Linux/macOS (add to ~/.bashrc or ~/.zshrc):**
```bash
export CF_API_TOKEN="your_token"
```

### 3. Script Default (Edit the script)

Open the script and edit the configuration section near the top:

```powershell
#region Configuration - Edit these defaults if desired
$script:DefaultApiToken = "your_token_here"  # Paste your API token here
$script:DefaultOutputPath = "C:\Reports\Cloudflare"  # Default output directory
#endregion
```

### 4. Interactive Prompt (Fallback)

If no token is found via the above methods, the script will securely prompt for it:

```
No API token found. Please enter your Cloudflare API token.
API Token: ********
```

## Output Files

The script generates the following files (timestamped):

| File | Description |
|------|-------------|
| `CloudflareSecurityAudit_YYYY-MM-DD_HHMMSS.csv` | All zone settings in CSV format |
| `CloudflareRulesAudit_YYYY-MM-DD_HHMMSS.csv` | All rules (page rules, redirects, WAF, etc.) |
| `CloudflareWorkersAudit_YYYY-MM-DD_HHMMSS.csv` | Worker routes per zone |
| `CloudflareIPAccessRules_YYYY-MM-DD_HHMMSS.csv` | IP access rules (block/allow/challenge) |
| `CloudflareSecurityTxt_YYYY-MM-DD_HHMMSS.csv` | Security.txt content per zone |
| `CloudflareSecurityAudit_YYYY-MM-DD_HHMMSS.html` | Interactive HTML report |

## HTML Report Features

### Tabs

- **SSL/TLS & HSTS** — Encryption mode, TLS versions, HTTPS settings, HSTS configuration
- **Security** — Security level, browser check, email obfuscation, WAF, leaked credentials
- **Bots & AI** — Bot fight mode, AI Labyrinth, block AI bots
- **Speed & Protocols** — HTTP/2, HTTP/3, 0-RTT, Early Hints, Rocket Loader
- **Caching** — Minification, Polish, Mirage, cache TTL, development mode
- **DNS** — Zone status, DNSSEC
- **Workers** — Worker routes and scripts
- **IP Access** — IP access rules with filtering
- **Rules & Redirects** — All rules with filtering and full expression display
- **Security.txt** — Full content of security.txt per zone
- **Recommendations** — Prioritised action items

### Interactive Features

- **Filtering** — Filter rules and IP access by zone, type, and free-text search
- **Tooltips** — Hover over `(?)` for setting explanations
- **Documentation Links** — Click `ℹ️` to open Cloudflare documentation
- **Zone Links** — Click zone names to open Cloudflare dashboard

### RAG Status

| Status | Meaning | Examples |
|--------|---------|----------|
| 🟢 Green | Recommended setting | SSL: Full (Strict), Min TLS: 1.2, HSTS: On |
| 🟡 Amber | Acceptable but review | SSL: Full, Min TLS: 1.1, DNSSEC: Pending |
| 🔴 Red | Action needed | SSL: Flexible, Min TLS: 1.0, HSTS: Off, Dev Mode: On |

## Settings Audited

### SSL/TLS
- Encryption mode (Flexible/Full/Full Strict)
- Minimum TLS version
- TLS 1.3
- Always Use HTTPS
- Automatic HTTPS Rewrites
- Opportunistic Encryption
- Certificate Transparency Monitoring

### HSTS
- Enabled/Disabled
- Max-Age
- Include Subdomains
- Preload
- No-Sniff header

### Security
- Security Level
- Browser Integrity Check
- Email Obfuscation
- Hotlink Protection
- Challenge TTL
- WAF
- Replace Insecure JS
- Leaked Credentials Detection
- Security.txt

### Bot Management
- Bot Fight Mode
- AI Labyrinth
- Block AI Bots

### Speed & Performance
- HTTP/2, HTTP/3
- HTTP/2 to Origin
- 0-RTT Connection Resumption
- Early Hints
- Speed Brain
- Rocket Loader
- WebSockets

### Caching
- Minification (JS/CSS/HTML)
- Polish (image optimisation)
- Mirage
- Browser Cache TTL
- Cache Level
- Development Mode
- Argo Smart Routing

### DNS
- DNSSEC status

### Rules
- Page Rules
- Redirect Rules
- Origin Rules
- Transform Rules (URL Rewrite, Request/Response Header Modification)
- Firewall Rules
- Rate Limits
- IP Access Rules

## Troubleshooting

### "N/A" for Bot Management Settings

Bot management features require specific plan levels or API permissions. Ensure your token has `Bot Management: Read` permission if available on your plan.

### "No rules found"

Ensure your API token has all the required permissions listed above, particularly:
- Page Rules: Read
- Zone WAF: Read
- Dynamic Redirect: Read
- Config Rules: Read
- Firewall Services: Read

### API Token Verification Failed

- Check the token hasn't expired
- Verify the token has Zone: Read permission at minimum
- Ensure the token scope includes the zones you're trying to audit

### Slow Execution

For accounts with many zones, the script may take several minutes. Use `-Zones` parameter to audit specific zones:

```powershell
.\Get-CloudflareSecurityReport.ps1 -Zones @("critical-site.com")
```

## Contributing

Contributions welcome! Please feel free to submit issues or pull requests.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

Lewis Burgess

## Changelog
