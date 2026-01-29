<#
.SYNOPSIS
    Generates a comprehensive security settings report for all Cloudflare zones.

.DESCRIPTION
    Connects to the Cloudflare API and retrieves security, SSL/TLS, speed, DNS settings,
    workers, rules and redirects for all zones. Produces CSV and HTML reports with RAG status.

.PARAMETER ApiToken
    Cloudflare API Token with appropriate permissions.
    Create at: https://dash.cloudflare.com/profile/api-tokens
    Can also be set via $env:CF_API_TOKEN or edited in the script defaults.
    If not provided, the script will prompt for it.

.PARAMETER OutputPath
    Directory for output files. Defaults to current directory.

.PARAMETER IncludeRules
    Include detailed rules export (Page Rules, Redirects, WAF, etc). Default: $true

.PARAMETER Zones
    Optional array of specific zone names to audit. If not specified, audits all zones.
    Example: -Zones @("example.com", "example.org")

.EXAMPLE
    .\Get-CloudflareSecurityReport.ps1 -ApiToken "your_api_token_here"

.EXAMPLE
    .\Get-CloudflareSecurityReport.ps1 -ApiToken $env:CF_API_TOKEN -OutputPath "C:\Reports"

.EXAMPLE
    .\Get-CloudflareSecurityReport.ps1 -Zones @("mydomain.org.uk", "anotherdomain.org.uk")

.EXAMPLE
    .\Get-CloudflareSecurityReport.ps1
    # Will prompt for API token if not configured

.NOTES
    Author: Claude (for The Collegiate Trust)
    Version: 4.0
    
    Required API Token Permissions:
    - Zone: Read
    - Zone Settings: Read
    - DNS: Read
    - Page Rules: Read
    - Zone WAF: Read
    - Dynamic Redirect: Read
    - Config Rules: Read
    - Workers Routes: Read
    - Firewall Services: Read
    - Account Settings: Read (for account ID)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiToken = "",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory = $false)]
    [bool]$IncludeRules = $true,
    
    [Parameter(Mandatory = $false)]
    [string[]]$Zones = @()
)

#region Configuration - Edit these defaults if desired
$script:DefaultApiToken = ""  # Paste your API token here to avoid passing it each time
$script:DefaultOutputPath = ""  # e.g., "C:\Reports\Cloudflare"
#endregion

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Resolve API token with fallbacks and prompt
if ([string]::IsNullOrEmpty($ApiToken)) {
    if (-not [string]::IsNullOrEmpty($script:DefaultApiToken)) {
        $ApiToken = $script:DefaultApiToken
    }
    elseif (-not [string]::IsNullOrEmpty($env:CF_API_TOKEN)) {
        $ApiToken = $env:CF_API_TOKEN
    }
    else {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Cloudflare Security Audit" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        Write-Host "No API token found. Please enter your Cloudflare API token." -ForegroundColor Yellow
        Write-Host "Create one at: https://dash.cloudflare.com/profile/api-tokens" -ForegroundColor Gray
        Write-Host "Required permissions: Zone:Read, Zone Settings:Read, DNS:Read," -ForegroundColor Gray
        Write-Host "                      Page Rules:Read, Zone WAF:Read, Workers Routes:Read`n" -ForegroundColor Gray
        
        $secureToken = Read-Host -Prompt "API Token" -AsSecureString
        $ApiToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        )
        
        if ([string]::IsNullOrEmpty($ApiToken)) {
            Write-Error "No API token provided. Exiting."
            exit 1
        }
    }
}

# Resolve output path
if ([string]::IsNullOrEmpty($OutputPath)) {
    if (-not [string]::IsNullOrEmpty($script:DefaultOutputPath)) {
        $OutputPath = $script:DefaultOutputPath
    }
    else {
        $OutputPath = (Get-Location).Path
    }
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Cloudflare API base URL
$BaseUrl = "https://api.cloudflare.com/client/v4"

# Standard headers for API requests
$Headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type"  = "application/json"
}

# Store account ID for zone links
$script:AccountId = $null

#region Documentation Links
$script:DocLinks = @{
    "ssl_mode"              = "https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/"
    "min_tls"               = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/"
    "tls_1_3"               = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/tls-13/"
    "always_https"          = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/"
    "auto_https_rewrites"   = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/"
    "opportunistic_enc"     = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/opportunistic-encryption/"
    "cert_transparency"     = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/certificate-transparency-monitoring/"
    "hsts"                  = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/"
    "security_level"        = "https://developers.cloudflare.com/waf/tools/security-level/"
    "browser_check"         = "https://developers.cloudflare.com/waf/tools/browser-integrity-check/"
    "email_obfuscation"     = "https://developers.cloudflare.com/waf/tools/scrape-shield/email-address-obfuscation/"
    "hotlink_protection"    = "https://developers.cloudflare.com/waf/tools/scrape-shield/hotlink-protection/"
    "bot_fight_mode"        = "https://developers.cloudflare.com/bots/get-started/free/"
    "ai_labyrinth"          = "https://developers.cloudflare.com/bots/ai-labyrinth/"
    "block_ai_bots"         = "https://developers.cloudflare.com/bots/concepts/bot/#ai-bots"
    "replace_insecure_js"   = "https://developers.cloudflare.com/speed/optimization/content/auto-minify/"
    "leaked_creds"          = "https://developers.cloudflare.com/waf/detections/leaked-credentials/"
    "security_txt"          = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/security-txt/"
    "robots_txt"            = "https://developers.cloudflare.com/bots/concepts/bot/#verified-bots"
    "http2"                 = "https://developers.cloudflare.com/speed/optimization/protocol/http2/"
    "http3"                 = "https://developers.cloudflare.com/speed/optimization/protocol/http3/"
    "http2_origin"          = "https://developers.cloudflare.com/speed/optimization/protocol/http2-to-origin/"
    "zero_rtt"              = "https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/"
    "early_hints"           = "https://developers.cloudflare.com/speed/optimization/content/early-hints/"
    "speed_brain"           = "https://developers.cloudflare.com/speed/optimization/content/speed-brain/"
    "rocket_loader"         = "https://developers.cloudflare.com/speed/optimization/content/rocket-loader/"
    "minify"                = "https://developers.cloudflare.com/speed/optimization/content/auto-minify/"
    "polish"                = "https://developers.cloudflare.com/images/polish/"
    "mirage"                = "https://developers.cloudflare.com/speed/optimization/images/mirage/"
    "dnssec"                = "https://developers.cloudflare.com/dns/dnssec/"
    "workers"               = "https://developers.cloudflare.com/workers/"
    "waf"                   = "https://developers.cloudflare.com/waf/"
    "rate_limiting"         = "https://developers.cloudflare.com/waf/rate-limiting-rules/"
    "ip_access"             = "https://developers.cloudflare.com/waf/tools/ip-access-rules/"
    "cache_ttl"             = "https://developers.cloudflare.com/cache/how-to/edge-browser-cache-ttl/"
    "dev_mode"              = "https://developers.cloudflare.com/cache/reference/development-mode/"
    "argo"                  = "https://developers.cloudflare.com/argo-smart-routing/"
    "page_shield"           = "https://developers.cloudflare.com/page-shield/"
    "nosniff"               = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    "ip_access_rules"       = "https://developers.cloudflare.com/waf/tools/ip-access-rules/"
    "origin_rules"          = "https://developers.cloudflare.com/rules/origin-rules/"
    "transform_rules"       = "https://developers.cloudflare.com/rules/transform/"
    "url_rewrite"           = "https://developers.cloudflare.com/rules/transform/url-rewrite/"
    "request_header_mod"    = "https://developers.cloudflare.com/rules/transform/request-header-modification/"
    "response_header_mod"   = "https://developers.cloudflare.com/rules/transform/response-header-modification/"
}

$script:Tooltips = @{
    "ssl_mode"              = "How Cloudflare connects to your origin. 'Full (Strict)' is most secure, requiring valid SSL on origin."
    "min_tls"               = "Minimum TLS version accepted. 1.2 recommended; 1.0/1.1 are deprecated and insecure."
    "tls_1_3"               = "Latest TLS protocol with improved security and performance. 'zrt' means 0-RTT is enabled."
    "always_https"          = "Redirects all HTTP requests to HTTPS at the edge before reaching your origin."
    "auto_https_rewrites"   = "Automatically rewrites HTTP links in your HTML to HTTPS to avoid mixed content."
    "opportunistic_enc"     = "Allows browsers to use HTTP/2 with encryption on HTTP URLs."
    "cert_transparency"     = "Alerts you when certificates are issued for your domain."
    "hsts"                  = "HTTP Strict Transport Security - tells browsers to only use HTTPS."
    "hsts_max_age"          = "How long browsers remember to use HTTPS (in seconds). 31536000 = 1 year."
    "hsts_subdomains"       = "Whether HSTS applies to all subdomains."
    "hsts_preload"          = "Submit to browser preload lists for HSTS enforcement before first visit."
    "nosniff"               = "X-Content-Type-Options header preventing browsers from MIME-type sniffing."
    "security_level"        = "Challenge threshold for suspicious visitors. Higher = more challenges."
    "browser_check"         = "Blocks requests with invalid or missing User-Agent headers."
    "email_obfuscation"     = "Obfuscates email addresses on your site to prevent harvesting by bots."
    "hotlink_protection"    = "Prevents other sites from embedding your images/assets."
    "bot_fight_mode"        = "Challenges requests from known bot networks."
    "ai_labyrinth"          = "Wastes AI scraper resources by serving generated maze content."
    "block_ai_bots"         = "Blocks known AI training crawlers from indexing your content."
    "replace_insecure_js"   = "Automatically updates known vulnerable JavaScript libraries."
    "leaked_creds"          = "Detects login attempts using credentials from known data breaches."
    "security_txt"          = "Publishes security contact info at /.well-known/security.txt"
    "robots_txt"            = "Cloudflare-managed robots.txt for bot control."
    "http2"                 = "HTTP/2 multiplexing for faster parallel requests."
    "http3"                 = "HTTP/3 (QUIC) for improved performance on unreliable networks."
    "http2_origin"          = "Use HTTP/2 between Cloudflare and your origin server."
    "zero_rtt"              = "0-RTT Connection Resumption for faster TLS handshakes on repeat visits."
    "early_hints"           = "Sends 103 Early Hints to preload critical assets."
    "speed_brain"           = "AI-powered performance optimisation predicting user navigation."
    "rocket_loader"         = "Defers JavaScript loading to improve page render time."
    "minify"                = "Removes unnecessary characters from JS/CSS/HTML."
    "polish"                = "Optimises images (compression, WebP conversion)."
    "mirage"                = "Lazy-loads images and optimises for mobile."
    "dnssec"                = "Cryptographically signs DNS records to prevent spoofing."
    "workers"               = "Serverless functions running at the edge."
    "waf"                   = "Web Application Firewall - blocks common attacks."
    "rate_limiting"         = "Limits requests per IP to prevent abuse."
    "ip_access"             = "Allow/block specific IP addresses or ranges."
    "cache_ttl"             = "How long content is cached at the edge and in browsers."
    "dev_mode"              = "Bypasses cache for development - should be OFF in production."
    "argo"                  = "Smart routing for faster, more reliable connections."
    "page_shield"           = "Monitors for malicious scripts on your pages."
    "ip_access_rules"       = "Allow, block, or challenge requests from specific IPs, IP ranges, countries, or ASNs."
    "origin_rules"          = "Override origin server settings like hostname, port, or SNI for matching requests."
    "transform_rules"       = "Modify URLs or HTTP headers for requests and responses."
    "url_rewrite"           = "Rewrite URL path or query string before requests reach your origin."
    "request_header_mod"    = "Add, remove, or modify HTTP request headers before they reach your origin."
    "response_header_mod"   = "Add, remove, or modify HTTP response headers before they reach visitors."
}
#endregion

#region Helper Functions

function Invoke-CloudflareApi {
    param(
        [string]$Endpoint,
        [string]$Method = "Get"
    )
    
    try {
        $response = Invoke-RestMethod -Uri "$BaseUrl$Endpoint" -Headers $Headers -Method $Method -ErrorAction Stop
        return $response
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403) {
            return @{ result = $null; success = $false; error = "NO_PERMISSION" }
        }
        elseif ($statusCode -eq 404) {
            return @{ result = $null; success = $false; error = "NOT_FOUND" }
        }
        else {
            return @{ result = $null; success = $false; error = $_.Exception.Message }
        }
    }
}

function Get-SettingValue {
    param($Settings, [string]$SettingId)
    
    if ($null -eq $Settings) { return "N/A" }
    
    $setting = $Settings | Where-Object { $_.id -eq $SettingId }
    if ($setting) {
        if ($null -eq $setting.value) { return "N/A" }
        return $setting.value
    }
    return "N/A"
}

function Format-BooleanSetting {
    param($Value)
    
    if ($null -eq $Value) { return "N/A" }
    if ($Value -eq $true -or $Value -eq "on" -or $Value -eq "enabled") { return "on" }
    if ($Value -eq $false -or $Value -eq "off" -or $Value -eq "disabled") { return "off" }
    return $Value.ToString()
}

function Get-RagStatus {
    param(
        [string]$SettingName,
        [string]$Value
    )
    
    if ([string]::IsNullOrEmpty($Value) -or $Value -eq "N/A") { return "Unknown" }
    
    $valueLower = $Value.ToString().ToLower()
    
    $greenSettings = @{
        "ssl"                           = @("strict", "full_strict")
        "min_tls_version"               = @("1.2", "1.3")
        "tls_1_3"                       = @("on", "zrt")
        "always_use_https"              = @("on")
        "automatic_https_rewrites"      = @("on")
        "opportunistic_encryption"      = @("on")
        "hsts_enabled"                  = @("on")
        "security_level"                = @("medium", "high", "under_attack")
        "browser_check"                 = @("on")
        "email_obfuscation"             = @("on")
        "bot_fight_mode"                = @("on")
        "dnssec"                        = @("active")
        "http2"                         = @("on")
        "http3"                         = @("on")
        "0rtt"                          = @("on")
        "early_hints"                   = @("on")
        "development_mode"              = @("off")
    }
    
    $amberSettings = @{
        "ssl"                           = @("full")
        "security_level"                = @("low", "essentially_off")
        "min_tls_version"               = @("1.1")
        "dnssec"                        = @("pending")
    }
    
    if ($greenSettings.ContainsKey($SettingName)) {
        if ($greenSettings[$SettingName] -contains $valueLower) {
            return "Green"
        }
        elseif ($amberSettings.ContainsKey($SettingName) -and $amberSettings[$SettingName] -contains $valueLower) {
            return "Amber"
        }
        else {
            return "Red"
        }
    }
    return "Unknown"
}

function Get-RagClass {
    param([string]$Status)
    
    switch ($Status) {
        "Green" { return "status-green" }
        "Amber" { return "status-amber" }
        "Red" { return "status-red" }
        default { return "status-gray" }
    }
}

function Get-ZoneUrl {
    param([string]$ZoneName, [string]$ZoneId)
    
    if ($script:AccountId) {
        return "https://dash.cloudflare.com/$($script:AccountId)/$ZoneName"
    }
    return "https://dash.cloudflare.com/?search=$ZoneName"
}

function Get-RuleHash {
    param($Rule)
    # Create a unique hash for deduplication
    $hashString = "$($Rule.Zone)|$($Rule.RuleType)|$($Rule.Trigger)|$($Rule.Actions)"
    return $hashString.GetHashCode()
}

#endregion

#region Data Collection Functions

function Get-AccountId {
    Write-Host "Fetching account information..." -ForegroundColor Cyan
    $response = Invoke-CloudflareApi -Endpoint "/accounts?page=1&per_page=1"
    if ($response.result -and $response.result.Count -gt 0) {
        $script:AccountId = $response.result[0].id
        Write-Host "  Account ID: $($script:AccountId)" -ForegroundColor Green
    }
}

function Get-AllZones {
    param([string[]]$FilterZones)
    
    Write-Host "Fetching zones..." -ForegroundColor Cyan
    $zones = @()
    $page = 1
    $perPage = 50

    do {
        $response = Invoke-CloudflareApi -Endpoint "/zones?page=$page&per_page=$perPage"
        if ($response.result -and $response.error -ne "NO_PERMISSION") {
            $zones += $response.result
            $totalPages = [math]::Ceiling($response.result_info.total_count / $perPage)
            Write-Host "  Retrieved page $page of $totalPages ($($zones.Count) zones)" -ForegroundColor Gray
            $page++
        }
        else {
            break
        }
    } while ($page -le $totalPages)

    if ($FilterZones.Count -gt 0) {
        $zones = $zones | Where-Object { $FilterZones -contains $_.name }
        Write-Host "  Filtered to $($zones.Count) specified zones" -ForegroundColor Yellow
    }

    Write-Host "  Processing $($zones.Count) zones" -ForegroundColor Green
    return $zones
}

function Get-ZoneSettings {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/settings"
    if ($response.success -eq $false) { return $null }
    return $response.result
}

function Get-ZoneDnssec {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/dnssec"
    if ($response.success -eq $false) { return @{ status = "N/A" } }
    return $response.result
}

function Get-ZonePageRules {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/pagerules"
    if ($response.success -eq $false -or $null -eq $response.result) { return @() }
    return $response.result
}

function Get-ZoneRulesets {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/rulesets"
    if ($response.success -eq $false -or $null -eq $response.result) { return @() }
    return $response.result
}

function Get-RulesetByPhase {
    param([string]$ZoneId, [string]$Phase)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/rulesets/phases/$Phase/entrypoint"
    if ($response.success -eq $false -or $null -eq $response.result) { return $null }
    return $response.result
}

function Get-ZoneWorkerRoutes {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/workers/routes"
    if ($response.success -eq $false -or $null -eq $response.result) { return @() }
    return $response.result
}

function Get-ZoneFirewallRules {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/firewall/rules"
    if ($response.success -eq $false -or $null -eq $response.result) { return @() }
    return $response.result
}

function Get-ZoneRateLimits {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/rate_limits"
    if ($response.success -eq $false -or $null -eq $response.result) { return @() }
    return $response.result
}

function Get-ZoneIPAccessRules {
    param([string]$ZoneId)
    
    $allRules = @()
    $page = 1
    $perPage = 50
    
    do {
        $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/firewall/access_rules/rules?page=$page&per_page=$perPage"
        if ($response.success -eq $false -or $null -eq $response.result) { break }
        
        $allRules += $response.result
        $totalPages = if ($response.result_info) { [math]::Ceiling($response.result_info.total_count / $perPage) } else { 1 }
        $page++
    } while ($page -le $totalPages)
    
    return $allRules
}

function Get-ZoneSecurityTxt {
    param([string]$ZoneId)
    
    $response = Invoke-CloudflareApi -Endpoint "/zones/$ZoneId/security-center/securitytxt"
    if ($response.success -eq $false -or $null -eq $response.result) { return $null }
    return $response.result
}

#endregion

#region Main Execution

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Cloudflare Security Settings Audit" -ForegroundColor Cyan
Write-Host "  Comprehensive Report v4.0" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Verify API token
Write-Host "Verifying API token..." -ForegroundColor Cyan
try {
    $verify = Invoke-RestMethod -Uri "$BaseUrl/user/tokens/verify" -Headers $Headers -Method Get
    if ($verify.result.status -ne "active") {
        throw "API token is not active"
    }
    Write-Host "  API token verified successfully" -ForegroundColor Green
}
catch {
    Write-Error "API token verification failed: $_"
    exit 1
}

# Get account ID for zone links
Get-AccountId

# Get all zones
$zones = Get-AllZones -FilterZones $Zones

# Process each zone
$results = @()
$rulesData = @()
$workersData = @()
$ipAccessData = @()
$securityTxtData = @()
$seenRuleHashes = @{}

$zoneCount = 0
foreach ($zone in $zones) {
    $zoneCount++
    Write-Host "`n[$zoneCount/$($zones.Count)] Processing: $($zone.name)" -ForegroundColor Yellow
    
    # Get all settings
    Write-Host "  Fetching zone settings..." -ForegroundColor Gray
    $settings = Get-ZoneSettings -ZoneId $zone.id
    
    Write-Host "  Fetching DNSSEC status..." -ForegroundColor Gray
    $dnssec = Get-ZoneDnssec -ZoneId $zone.id
    
    Write-Host "  Fetching worker routes..." -ForegroundColor Gray
    $workerRoutes = Get-ZoneWorkerRoutes -ZoneId $zone.id
    
    Write-Host "  Fetching security.txt..." -ForegroundColor Gray
    $securityTxt = Get-ZoneSecurityTxt -ZoneId $zone.id
    
    if ($IncludeRules) {
        Write-Host "  Fetching page rules..." -ForegroundColor Gray
        $pageRules = Get-ZonePageRules -ZoneId $zone.id
        
        Write-Host "  Fetching firewall rules..." -ForegroundColor Gray
        $firewallRules = Get-ZoneFirewallRules -ZoneId $zone.id
        
        Write-Host "  Fetching rate limits..." -ForegroundColor Gray
        $rateLimits = Get-ZoneRateLimits -ZoneId $zone.id
        
        Write-Host "  Fetching IP access rules..." -ForegroundColor Gray
        $ipAccessRules = Get-ZoneIPAccessRules -ZoneId $zone.id
        
        Write-Host "  Fetching redirect rules..." -ForegroundColor Gray
        $redirectRuleset = Get-RulesetByPhase -ZoneId $zone.id -Phase "http_request_dynamic_redirect"
        
        Write-Host "  Fetching origin rules..." -ForegroundColor Gray
        $originRuleset = Get-RulesetByPhase -ZoneId $zone.id -Phase "http_request_origin"
        
        Write-Host "  Fetching transform rules..." -ForegroundColor Gray
        $urlRewriteRuleset = Get-RulesetByPhase -ZoneId $zone.id -Phase "http_request_transform"
        $reqHeaderRuleset = Get-RulesetByPhase -ZoneId $zone.id -Phase "http_request_late_transform"
        $respHeaderRuleset = Get-RulesetByPhase -ZoneId $zone.id -Phase "http_response_headers_transform"
    }
    
    if ($null -eq $settings) {
        Write-Warning "  Could not retrieve settings for $($zone.name)"
        continue
    }
    
    #region Extract Settings
    
    # SSL/TLS Settings
    $sslMode = Get-SettingValue -Settings $settings -SettingId "ssl"
    $minTls = Get-SettingValue -Settings $settings -SettingId "min_tls_version"
    $tls13 = Get-SettingValue -Settings $settings -SettingId "tls_1_3"
    $alwaysHttps = Get-SettingValue -Settings $settings -SettingId "always_use_https"
    $autoHttpsRewrites = Get-SettingValue -Settings $settings -SettingId "automatic_https_rewrites"
    $opportunisticEnc = Get-SettingValue -Settings $settings -SettingId "opportunistic_encryption"
    
    # Certificate Transparency
    $certTransparency = Get-SettingValue -Settings $settings -SettingId "certificate_transparency_monitoring"
    if ($certTransparency -is [PSCustomObject] -and $null -ne $certTransparency.enabled) {
        $certTransparency = if ($certTransparency.enabled) { "on" } else { "off" }
    }
    elseif ($certTransparency -is [bool]) {
        $certTransparency = if ($certTransparency) { "on" } else { "off" }
    }
    
    # HSTS
    $hstsEnabled = "off"
    $hstsMaxAge = "0"
    $hstsIncludeSubs = "off"
    $hstsPreload = "off"
    $hstsNoSniff = "off"
    
    $hstsSettings = Get-SettingValue -Settings $settings -SettingId "security_header"
    if ($hstsSettings -ne "N/A" -and $null -ne $hstsSettings) {
        if ($hstsSettings.strict_transport_security) {
            $hsts = $hstsSettings.strict_transport_security
            $hstsEnabled = if ($hsts.enabled -eq $true) { "on" } else { "off" }
            $hstsMaxAge = if ($null -ne $hsts.max_age) { $hsts.max_age.ToString() } else { "0" }
            $hstsIncludeSubs = if ($hsts.include_subdomains -eq $true) { "on" } else { "off" }
            $hstsPreload = if ($hsts.preload -eq $true) { "on" } else { "off" }
            $hstsNoSniff = if ($hsts.nosniff -eq $true) { "on" } else { "off" }
        }
    }
    
    # Security Settings
    $securityLevel = Get-SettingValue -Settings $settings -SettingId "security_level"
    $browserCheck = Get-SettingValue -Settings $settings -SettingId "browser_check"
    $emailObfuscation = Get-SettingValue -Settings $settings -SettingId "email_obfuscation"
    $hotlinkProtection = Get-SettingValue -Settings $settings -SettingId "hotlink_protection"
    $challengeTtl = Get-SettingValue -Settings $settings -SettingId "challenge_ttl"
    $waf = Get-SettingValue -Settings $settings -SettingId "waf"
    
    # Bot Management
    $botFightMode = "N/A"
    $aiLabyrinth = "N/A"
    $blockAiBots = "N/A"
    
    $botMgmtResponse = Invoke-CloudflareApi -Endpoint "/zones/$($zone.id)/bot_management"
    if ($botMgmtResponse.result -and $botMgmtResponse.error -ne "NO_PERMISSION") {
        $botMgmt = $botMgmtResponse.result
        if ($null -ne $botMgmt.fight_mode) { $botFightMode = Format-BooleanSetting $botMgmt.fight_mode }
        if ($null -ne $botMgmt.ai_bots_protection) { $aiLabyrinth = Format-BooleanSetting $botMgmt.ai_bots_protection }
        if ($null -ne $botMgmt.block_ai_scrapers) { $blockAiBots = Format-BooleanSetting $botMgmt.block_ai_scrapers }
        if ($null -ne $botMgmt.enable_js -and $botFightMode -eq "N/A") { $botFightMode = Format-BooleanSetting $botMgmt.enable_js }
    }
    
    # Advanced Security
    $replaceInsecureJs = Get-SettingValue -Settings $settings -SettingId "replace_insecure_js"
    
    # Leaked Credentials
    $leakedCredsEnabled = "N/A"
    $leakedCredsResponse = Invoke-CloudflareApi -Endpoint "/zones/$($zone.id)/leaked-credential-checks"
    if ($leakedCredsResponse.result -and $leakedCredsResponse.error -ne "NO_PERMISSION") {
        $leakedCredsEnabled = Format-BooleanSetting $leakedCredsResponse.result.enabled
    }
    
    # Security.txt - Collect full content
    $securityTxtEnabled = "N/A"
    $securityTxtContent = ""
    if ($securityTxt) {
        $securityTxtEnabled = if ($securityTxt.enabled) { "on" } else { "off" }
        if ($securityTxt.contents) {
            $securityTxtContent = $securityTxt.contents
        }
        
        $securityTxtData += [PSCustomObject]@{
            Zone    = $zone.name
            Enabled = $securityTxtEnabled
            Content = $securityTxtContent
        }
    }
    else {
        $securityTxtData += [PSCustomObject]@{
            Zone    = $zone.name
            Enabled = "N/A"
            Content = ""
        }
    }
    
    # Speed / Protocol Settings
    $http2 = Get-SettingValue -Settings $settings -SettingId "http2"
    $http3 = Get-SettingValue -Settings $settings -SettingId "http3"
    $http2Origin = Get-SettingValue -Settings $settings -SettingId "origin_h2_max_streams"
    if ($http2Origin -ne "N/A" -and $http2Origin -gt 0) { $http2Origin = "on" } else { $http2Origin = "off" }
    $zeroRtt = Get-SettingValue -Settings $settings -SettingId "0rtt"
    $earlyHints = Get-SettingValue -Settings $settings -SettingId "early_hints"
    $websockets = Get-SettingValue -Settings $settings -SettingId "websockets"
    $rocketLoader = Get-SettingValue -Settings $settings -SettingId "rocket_loader"
    
    # Speed Brain
    $speedBrain = Get-SettingValue -Settings $settings -SettingId "speed_brain"
    if ($speedBrain -eq "N/A") {
        $speedBrainResponse = Invoke-CloudflareApi -Endpoint "/zones/$($zone.id)/speed_api/settings"
        if ($speedBrainResponse.result -and $speedBrainResponse.error -ne "NO_PERMISSION") {
            $speedBrain = Format-BooleanSetting $speedBrainResponse.result.enabled
        }
    }
    
    # Minification
    $minifySettings = Get-SettingValue -Settings $settings -SettingId "minify"
    $minifyJs = "N/A"
    $minifyCss = "N/A"
    $minifyHtml = "N/A"
    if ($minifySettings -ne "N/A" -and $null -ne $minifySettings) {
        $minifyJs = if ($minifySettings.js) { "on" } else { "off" }
        $minifyCss = if ($minifySettings.css) { "on" } else { "off" }
        $minifyHtml = if ($minifySettings.html) { "on" } else { "off" }
    }
    
    # Image Optimization
    $polish = Get-SettingValue -Settings $settings -SettingId "polish"
    $mirage = Get-SettingValue -Settings $settings -SettingId "mirage"
    
    # Cache Settings
    $browserCacheTtl = Get-SettingValue -Settings $settings -SettingId "browser_cache_ttl"
    $developmentMode = Get-SettingValue -Settings $settings -SettingId "development_mode"
    $cacheLevel = Get-SettingValue -Settings $settings -SettingId "cache_level"
    
    # Argo
    $argoResponse = Invoke-CloudflareApi -Endpoint "/zones/$($zone.id)/argo/smart_routing"
    $argoSmartRouting = "N/A"
    if ($argoResponse.result -and $argoResponse.error -ne "NO_PERMISSION") {
        $argoSmartRouting = Format-BooleanSetting $argoResponse.result.value
    }
    
    # DNSSEC
    $dnssecStatus = if ($dnssec.status) { $dnssec.status } else { "N/A" }
    
    #endregion
    
    #region Process Workers
    
    foreach ($route in $workerRoutes) {
        $workersData += [PSCustomObject]@{
            Zone        = $zone.name
            Pattern     = $route.pattern
            Script      = if ($route.script) { $route.script } else { "N/A" }
            Enabled     = if ($null -eq $route.enabled -or $route.enabled -eq $true) { "enabled" } else { "disabled" }
        }
    }
    
    #endregion
    
    #region Process Rules (with deduplication)
    
    if ($IncludeRules) {
        # Helper function to add rule with deduplication
        function Add-UniqueRule {
            param($RuleObject)
            $hash = Get-RuleHash -Rule $RuleObject
            if (-not $seenRuleHashes.ContainsKey($hash)) {
                $seenRuleHashes[$hash] = $true
                $script:rulesData += $RuleObject
            }
        }
        
        # Page Rules
        foreach ($rule in $pageRules) {
            $ruleObj = [PSCustomObject]@{
                Zone        = $zone.name
                RuleType    = "Page Rule"
                RuleName    = "Page Rule #$($rule.priority)"
                Priority    = $rule.priority
                Status      = $rule.status
                Trigger     = ($rule.targets | ForEach-Object { $_.constraint.value }) -join ", "
                Actions     = ($rule.actions | ForEach-Object { "$($_.id): $($_.value)" }) -join "; "
            }
            Add-UniqueRule -RuleObject $ruleObj
        }
        
        # Firewall Rules
        foreach ($rule in $firewallRules) {
            $ruleObj = [PSCustomObject]@{
                Zone        = $zone.name
                RuleType    = "Firewall Rule"
                RuleName    = if ($rule.description) { $rule.description } else { "Firewall Rule" }
                Priority    = $rule.priority
                Status      = if ($rule.paused) { "paused" } else { "active" }
                Trigger     = $rule.filter.expression
                Actions     = $rule.action
            }
            Add-UniqueRule -RuleObject $ruleObj
        }
        
        # Rate Limits
        foreach ($rule in $rateLimits) {
            $ruleObj = [PSCustomObject]@{
                Zone        = $zone.name
                RuleType    = "Rate Limit"
                RuleName    = if ($rule.description) { $rule.description } else { "Rate Limit" }
                Priority    = "N/A"
                Status      = if ($rule.disabled) { "disabled" } else { "active" }
                Trigger     = $rule.match.request.url
                Actions     = "$($rule.action.mode) for $($rule.action.timeout)s when $($rule.threshold) requests in $($rule.period)s"
            }
            Add-UniqueRule -RuleObject $ruleObj
        }
        
        # IP Access Rules (also store in dedicated collection)
        foreach ($rule in $ipAccessRules) {
            $targetType = ""
            $targetAddr = ""
            if ($rule.configuration) {
                $targetType = $rule.configuration.target
                $targetAddr = $rule.configuration.value
            }
            
            $ipAccessData += [PSCustomObject]@{
                Zone        = $zone.name
                Mode        = $rule.mode
                TargetType  = $targetType
                Target      = $targetAddr
                Notes       = $rule.notes
                Status      = if ($rule.paused) { "paused" } else { "active" }
                Created     = if ($rule.created_on) { $rule.created_on.Substring(0, 10) } else { "N/A" }
                Modified    = if ($rule.modified_on) { $rule.modified_on.Substring(0, 10) } else { "N/A" }
            }
            
            $ruleObj = [PSCustomObject]@{
                Zone        = $zone.name
                RuleType    = "IP Access"
                RuleName    = if ($rule.notes) { $rule.notes } else { "$targetType`: $targetAddr" }
                Priority    = "N/A"
                Status      = if ($rule.paused) { "paused" } else { "active" }
                Trigger     = "$targetType`: $targetAddr"
                Actions     = $rule.mode
            }
            Add-UniqueRule -RuleObject $ruleObj
        }
        
        # Redirect Rules
        if ($redirectRuleset -and $redirectRuleset.rules) {
            foreach ($rule in $redirectRuleset.rules) {
                $target = ""
                $statusCode = ""
                if ($rule.action_parameters.from_value) {
                    $target = $rule.action_parameters.from_value.target_url.value
                    $statusCode = $rule.action_parameters.from_value.status_code
                }
                elseif ($rule.action_parameters.target_url) {
                    $target = $rule.action_parameters.target_url.value
                    $statusCode = $rule.action_parameters.status_code
                }
                
                $ruleObj = [PSCustomObject]@{
                    Zone        = $zone.name
                    RuleType    = "Redirect"
                    RuleName    = if ($rule.description) { $rule.description } else { "Redirect to $target" }
                    Priority    = if ($rule.position) { $rule.position } else { "N/A" }
                    Status      = if ($rule.enabled -eq $false) { "disabled" } else { "enabled" }
                    Trigger     = if ($rule.expression) { $rule.expression } else { "(all requests)" }
                    Actions     = "Redirect ($statusCode) to: $target"
                }
                Add-UniqueRule -RuleObject $ruleObj
            }
        }
        
        # Origin Rules
        if ($originRuleset -and $originRuleset.rules) {
            foreach ($rule in $originRuleset.rules) {
                $params = @()
                if ($rule.action_parameters) {
                    if ($rule.action_parameters.host_header) { $params += "Host Header: $($rule.action_parameters.host_header)" }
                    if ($rule.action_parameters.origin) {
                        if ($rule.action_parameters.origin.host) { $params += "Origin: $($rule.action_parameters.origin.host)" }
                        if ($rule.action_parameters.origin.port) { $params += "Port: $($rule.action_parameters.origin.port)" }
                    }
                    if ($rule.action_parameters.sni) {
                        if ($rule.action_parameters.sni.value) { $params += "SNI: $($rule.action_parameters.sni.value)" }
                    }
                }
                $actionDesc = if ($params.Count -gt 0) { $params -join "; " } else { $rule.action }
                
                $ruleObj = [PSCustomObject]@{
                    Zone        = $zone.name
                    RuleType    = "Origin"
                    RuleName    = if ($rule.description) { $rule.description } else { "Origin Rule" }
                    Priority    = if ($rule.position) { $rule.position } else { "N/A" }
                    Status      = if ($rule.enabled -eq $false) { "disabled" } else { "enabled" }
                    Trigger     = if ($rule.expression) { $rule.expression } else { "(all requests)" }
                    Actions     = $actionDesc
                }
                Add-UniqueRule -RuleObject $ruleObj
            }
        }
        
        # URL Rewrite Rules
        if ($urlRewriteRuleset -and $urlRewriteRuleset.rules) {
            foreach ($rule in $urlRewriteRuleset.rules) {
                $params = @()
                if ($rule.action_parameters.uri) {
                    if ($rule.action_parameters.uri.path.value) { $params += "Path: $($rule.action_parameters.uri.path.value)" }
                    elseif ($rule.action_parameters.uri.path.expression) { $params += "Path (dynamic): $($rule.action_parameters.uri.path.expression)" }
                    if ($rule.action_parameters.uri.query.value) { $params += "Query: $($rule.action_parameters.uri.query.value)" }
                    elseif ($rule.action_parameters.uri.query.expression) { $params += "Query (dynamic): $($rule.action_parameters.uri.query.expression)" }
                }
                $actionDesc = if ($params.Count -gt 0) { $params -join "; " } else { "URL Rewrite" }
                
                $ruleObj = [PSCustomObject]@{
                    Zone        = $zone.name
                    RuleType    = "URL Rewrite"
                    RuleName    = if ($rule.description) { $rule.description } else { "URL Rewrite" }
                    Priority    = if ($rule.position) { $rule.position } else { "N/A" }
                    Status      = if ($rule.enabled -eq $false) { "disabled" } else { "enabled" }
                    Trigger     = if ($rule.expression) { $rule.expression } else { "(all requests)" }
                    Actions     = $actionDesc
                }
                Add-UniqueRule -RuleObject $ruleObj
            }
        }
        
        # Request Header Modification Rules
        if ($reqHeaderRuleset -and $reqHeaderRuleset.rules) {
            foreach ($rule in $reqHeaderRuleset.rules) {
                $params = @()
                if ($rule.action_parameters.headers) {
                    foreach ($header in $rule.action_parameters.headers.PSObject.Properties) {
                        $op = $header.Value.operation
                        $val = if ($header.Value.value) { $header.Value.value } else { "(expression)" }
                        $params += "$op $($header.Name): $val"
                    }
                }
                $actionDesc = if ($params.Count -gt 0) { $params -join "; " } else { "Modify Request Headers" }
                
                $ruleObj = [PSCustomObject]@{
                    Zone        = $zone.name
                    RuleType    = "Request Header"
                    RuleName    = if ($rule.description) { $rule.description } else { "Request Header Mod" }
                    Priority    = if ($rule.position) { $rule.position } else { "N/A" }
                    Status      = if ($rule.enabled -eq $false) { "disabled" } else { "enabled" }
                    Trigger     = if ($rule.expression) { $rule.expression } else { "(all requests)" }
                    Actions     = $actionDesc
                }
                Add-UniqueRule -RuleObject $ruleObj
            }
        }
        
        # Response Header Modification Rules
        if ($respHeaderRuleset -and $respHeaderRuleset.rules) {
            foreach ($rule in $respHeaderRuleset.rules) {
                $params = @()
                if ($rule.action_parameters.headers) {
                    foreach ($header in $rule.action_parameters.headers.PSObject.Properties) {
                        $op = $header.Value.operation
                        $val = if ($header.Value.value) { $header.Value.value } else { "(expression)" }
                        $params += "$op $($header.Name): $val"
                    }
                }
                $actionDesc = if ($params.Count -gt 0) { $params -join "; " } else { "Modify Response Headers" }
                
                $ruleObj = [PSCustomObject]@{
                    Zone        = $zone.name
                    RuleType    = "Response Header"
                    RuleName    = if ($rule.description) { $rule.description } else { "Response Header Mod" }
                    Priority    = if ($rule.position) { $rule.position } else { "N/A" }
                    Status      = if ($rule.enabled -eq $false) { "disabled" } else { "enabled" }
                    Trigger     = if ($rule.expression) { $rule.expression } else { "(all requests)" }
                    Actions     = $actionDesc
                }
                Add-UniqueRule -RuleObject $ruleObj
            }
        }
    }
    
    #endregion
    
    # Build result object
    $result = [PSCustomObject]@{
        Zone                            = $zone.name
        ZoneId                          = $zone.id
        ZoneUrl                         = Get-ZoneUrl -ZoneName $zone.name -ZoneId $zone.id
        Status                          = $zone.status
        Plan                            = $zone.plan.name
        
        SSL_Mode                        = $sslMode
        SSL_Mode_RAG                    = Get-RagStatus -SettingName "ssl" -Value $sslMode
        Always_Use_HTTPS                = $alwaysHttps
        Always_HTTPS_RAG                = Get-RagStatus -SettingName "always_use_https" -Value $alwaysHttps
        Min_TLS_Version                 = $minTls
        Min_TLS_RAG                     = Get-RagStatus -SettingName "min_tls_version" -Value $minTls
        TLS_1_3                         = $tls13
        TLS_1_3_RAG                     = Get-RagStatus -SettingName "tls_1_3" -Value $tls13
        Opportunistic_Encryption        = $opportunisticEnc
        Auto_HTTPS_Rewrites             = $autoHttpsRewrites
        Certificate_Transparency        = $certTransparency
        
        HSTS_Enabled                    = $hstsEnabled
        HSTS_RAG                        = Get-RagStatus -SettingName "hsts_enabled" -Value $hstsEnabled
        HSTS_Max_Age                    = $hstsMaxAge
        HSTS_Include_Subdomains         = $hstsIncludeSubs
        HSTS_Preload                    = $hstsPreload
        HSTS_NoSniff                    = $hstsNoSniff
        
        Security_Level                  = $securityLevel
        Security_Level_RAG              = Get-RagStatus -SettingName "security_level" -Value $securityLevel
        Browser_Integrity_Check         = $browserCheck
        Browser_Check_RAG               = Get-RagStatus -SettingName "browser_check" -Value $browserCheck
        Email_Obfuscation               = $emailObfuscation
        Hotlink_Protection              = $hotlinkProtection
        Challenge_TTL                   = $challengeTtl
        WAF                             = $waf
        
        Bot_Fight_Mode                  = $botFightMode
        Bot_Fight_RAG                   = Get-RagStatus -SettingName "bot_fight_mode" -Value $botFightMode
        AI_Labyrinth                    = $aiLabyrinth
        Block_AI_Bots                   = $blockAiBots
        
        Replace_Insecure_JS             = $replaceInsecureJs
        Leaked_Credentials_Detection    = $leakedCredsEnabled
        Security_Txt_Enabled            = $securityTxtEnabled
        
        HTTP2                           = $http2
        HTTP2_RAG                       = Get-RagStatus -SettingName "http2" -Value $http2
        HTTP3                           = $http3
        HTTP3_RAG                       = Get-RagStatus -SettingName "http3" -Value $http3
        HTTP2_to_Origin                 = $http2Origin
        Zero_RTT                        = $zeroRtt
        Zero_RTT_RAG                    = Get-RagStatus -SettingName "0rtt" -Value $zeroRtt
        Early_Hints                     = $earlyHints
        Early_Hints_RAG                 = Get-RagStatus -SettingName "early_hints" -Value $earlyHints
        Speed_Brain                     = $speedBrain
        Rocket_Loader                   = $rocketLoader
        WebSockets                      = $websockets
        
        Minify_JS                       = $minifyJs
        Minify_CSS                      = $minifyCss
        Minify_HTML                     = $minifyHtml
        Polish                          = $polish
        Mirage                          = $mirage
        
        Browser_Cache_TTL               = $browserCacheTtl
        Cache_Level                     = $cacheLevel
        Development_Mode                = $developmentMode
        Dev_Mode_RAG                    = Get-RagStatus -SettingName "development_mode" -Value $developmentMode
        Argo_Smart_Routing              = $argoSmartRouting
        
        DNSSEC                          = $dnssecStatus
        DNSSEC_RAG                      = Get-RagStatus -SettingName "dnssec" -Value $dnssecStatus
        
        Workers_Count                   = ($workerRoutes | Measure-Object).Count
    }
    
    $results += $result
}

#endregion

#region Generate Reports

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$csvPath = Join-Path $OutputPath "CloudflareSecurityAudit_$timestamp.csv"
$rulesCsvPath = Join-Path $OutputPath "CloudflareRulesAudit_$timestamp.csv"
$workersCsvPath = Join-Path $OutputPath "CloudflareWorkersAudit_$timestamp.csv"
$ipAccessCsvPath = Join-Path $OutputPath "CloudflareIPAccessRules_$timestamp.csv"
$secTxtCsvPath = Join-Path $OutputPath "CloudflareSecurityTxt_$timestamp.csv"
$htmlPath = Join-Path $OutputPath "CloudflareSecurityAudit_$timestamp.html"

# Export CSVs
Write-Host "`nExporting CSV reports..." -ForegroundColor Cyan
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "  Settings:    $csvPath" -ForegroundColor Green

if ($IncludeRules -and $rulesData.Count -gt 0) {
    $rulesData | Export-Csv -Path $rulesCsvPath -NoTypeInformation
    Write-Host "  Rules:       $rulesCsvPath" -ForegroundColor Green
}

if ($workersData.Count -gt 0) {
    $workersData | Export-Csv -Path $workersCsvPath -NoTypeInformation
    Write-Host "  Workers:     $workersCsvPath" -ForegroundColor Green
}

if ($ipAccessData.Count -gt 0) {
    $ipAccessData | Export-Csv -Path $ipAccessCsvPath -NoTypeInformation
    Write-Host "  IP Access:   $ipAccessCsvPath" -ForegroundColor Green
}

if ($securityTxtData.Count -gt 0) {
    $securityTxtData | Export-Csv -Path $secTxtCsvPath -NoTypeInformation
    Write-Host "  Security.txt: $secTxtCsvPath" -ForegroundColor Green
}

# Calculate summary stats
$totalZones = $results.Count
$issueCount = ($results | ForEach-Object { 
    ($_.PSObject.Properties | Where-Object { $_.Value -eq "Red" }).Count 
} | Measure-Object -Sum).Sum

$warningCount = ($results | ForEach-Object { 
    ($_.PSObject.Properties | Where-Object { $_.Value -eq "Amber" }).Count 
} | Measure-Object -Sum).Sum

$zonesWithIssues = @($results | Where-Object { 
    $_.SSL_Mode_RAG -eq "Red" -or 
    $_.Min_TLS_RAG -eq "Red" -or 
    $_.Always_HTTPS_RAG -eq "Red" -or
    $_.HSTS_RAG -eq "Red" -or
    $_.DNSSEC_RAG -eq "Red" -or
    $_.Dev_Mode_RAG -eq "Red"
}).Count

# Get unique values for filters
$uniqueZones = ($results | Select-Object -ExpandProperty Zone -Unique | Sort-Object) -join '","'
$uniqueRuleTypes = ($rulesData | Select-Object -ExpandProperty RuleType -Unique | Sort-Object) -join '","'

# Generate HTML Report
Write-Host "Generating HTML report..." -ForegroundColor Cyan

# Helper function to create header with tooltip and link
function Get-HeaderHtml {
    param([string]$Title, [string]$TooltipKey)
    
    $tooltip = if ($script:Tooltips.ContainsKey($TooltipKey)) { $script:Tooltips[$TooltipKey] } else { "" }
    $docLink = if ($script:DocLinks.ContainsKey($TooltipKey)) { $script:DocLinks[$TooltipKey] } else { "" }
    
    if ($tooltip -or $docLink) {
        $infoIcon = if ($docLink) { "<a href=`"$docLink`" target=`"_blank`" class=`"info-link`" title=`"View documentation`">ℹ️</a>" } else { "" }
        return "$Title <span class=`"tooltip`" title=`"$tooltip`">(?)</span>$infoIcon"
    }
    return $Title
}

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare Security Audit - The Collegiate Trust</title>
    <style>
        :root {
            --green: #22c55e;
            --green-bg: #dcfce7;
            --amber: #f59e0b;
            --amber-bg: #fef3c7;
            --red: #ef4444;
            --red-bg: #fee2e2;
            --gray: #6b7280;
            --gray-bg: #f3f4f6;
            --primary: #1e3a5f;
            --primary-light: #2d5a87;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f9fafb;
            color: #1f2937;
            line-height: 1.5;
        }
        
        .container { max-width: 1900px; margin: 0 auto; padding: 20px; }
        
        header {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
            color: white;
            padding: 30px 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        header h1 { font-size: 28px; font-weight: 600; margin-bottom: 8px; }
        header p { opacity: 0.9; font-size: 14px; }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .summary-card h3 {
            font-size: 11px;
            color: #6b7280;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        
        .summary-card .number { font-size: 32px; font-weight: 700; }
        .summary-card.green .number { color: var(--green); }
        .summary-card.amber .number { color: var(--amber); }
        .summary-card.red .number { color: var(--red); }
        .summary-card.total .number { color: var(--primary); }
        
        .section {
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .table-scroll { overflow-x: auto; }
        
        table { width: 100%; border-collapse: collapse; font-size: 12px; }
        
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
        }
        
        /* Allow text wrapping in cells */
        td { 
            white-space: normal; 
            word-wrap: break-word;
            max-width: 400px;
        }
        
        td code {
            display: block;
            white-space: pre-wrap;
            word-break: break-all;
            background: #f3f4f6;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            max-height: 150px;
            overflow-y: auto;
        }
        
        th {
            background: #f9fafb;
            font-weight: 600;
            color: #374151;
            position: sticky;
            top: 0;
            font-size: 11px;
            letter-spacing: 0.3px;
            white-space: nowrap;
        }
        
        tr:hover { background: #fafafa; }
        
        .zone-name { font-weight: 600; color: var(--primary); }
        .zone-name a { color: var(--primary); text-decoration: none; }
        .zone-name a:hover { text-decoration: underline; }
        
        .status-green { background: var(--green-bg); color: #166534; padding: 3px 8px; border-radius: 9999px; font-weight: 500; font-size: 11px; }
        .status-amber { background: var(--amber-bg); color: #92400e; padding: 3px 8px; border-radius: 9999px; font-weight: 500; font-size: 11px; }
        .status-red { background: var(--red-bg); color: #991b1b; padding: 3px 8px; border-radius: 9999px; font-weight: 500; font-size: 11px; }
        .status-gray { background: var(--gray-bg); color: var(--gray); padding: 3px 8px; border-radius: 9999px; font-weight: 500; font-size: 11px; }
        
        .legend { display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; font-size: 13px; }
        .legend-item { display: flex; align-items: center; gap: 8px; }
        .legend-dot { width: 14px; height: 14px; border-radius: 4px; }
        .legend-dot.green { background: var(--green); }
        .legend-dot.amber { background: var(--amber); }
        .legend-dot.red { background: var(--red); }
        
        .tooltip { cursor: help; color: #9ca3af; font-size: 10px; margin-left: 4px; }
        .info-link { font-size: 10px; margin-left: 4px; text-decoration: none; opacity: 0.7; }
        .info-link:hover { opacity: 1; }
        
        .tabs { display: flex; gap: 4px; padding: 16px 24px; background: #f9fafb; border-bottom: 1px solid #e5e7eb; flex-wrap: wrap; }
        .tab {
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            background: transparent;
            border: none;
            color: #6b7280;
            transition: all 0.2s;
        }
        .tab.active { background: white; color: var(--primary); box-shadow: 0 1px 2px rgba(0,0,0,0.1); }
        .tab:hover { color: var(--primary); }
        
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .filters {
            padding: 16px 24px;
            background: #f9fafb;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-group { display: flex; align-items: center; gap: 8px; }
        .filter-group label { font-size: 13px; font-weight: 500; color: #374151; }
        .filter-group select, .filter-group input {
            padding: 6px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 13px;
            background: white;
        }
        
        .filter-group select:focus, .filter-group input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(30, 58, 95, 0.1);
        }
        
        .btn {
            padding: 6px 16px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn:hover { background: var(--primary-light); }
        .btn-secondary { background: #6b7280; }
        .btn-secondary:hover { background: #4b5563; }
        
        .api-permissions {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 8px;
            padding: 16px;
            margin: 16px;
            font-size: 13px;
        }
        .api-permissions h4 { color: #92400e; margin-bottom: 8px; }
        
        .security-txt-content {
            background: #1f2937;
            color: #f9fafb;
            padding: 16px;
            border-radius: 8px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }
        
        footer { text-align: center; padding: 20px; color: #6b7280; font-size: 13px; }
        
        @media print {
            body { background: white; }
            header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            .section { break-inside: avoid; }
            .tabs { display: none; }
            .tab-content { display: block !important; page-break-before: always; }
            .filters { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>☁️ Cloudflare Security Audit Report</h1>
            <p>Generated: $(Get-Date -Format "dddd, dd MMMM yyyy 'at' HH:mm:ss") | Zones Audited: $($results.Count) | The Collegiate Trust</p>
        </header>
        
        <div class="summary">
            <div class="summary-card total">
                <h3>Total Zones</h3>
                <div class="number">$totalZones</div>
            </div>
            <div class="summary-card red">
                <h3>Zones with Issues</h3>
                <div class="number">$zonesWithIssues</div>
            </div>
            <div class="summary-card red">
                <h3>Critical Issues</h3>
                <div class="number">$issueCount</div>
            </div>
            <div class="summary-card amber">
                <h3>Warnings</h3>
                <div class="number">$warningCount</div>
            </div>
            <div class="summary-card green">
                <h3>Rules</h3>
                <div class="number">$($rulesData.Count)</div>
            </div>
            <div class="summary-card green">
                <h3>Workers</h3>
                <div class="number">$($workersData.Count)</div>
            </div>
            <div class="summary-card green">
                <h3>IP Access</h3>
                <div class="number">$($ipAccessData.Count)</div>
            </div>
        </div>
        
        <div class="legend">
            <div class="legend-item"><div class="legend-dot green"></div> Recommended</div>
            <div class="legend-item"><div class="legend-dot amber"></div> Review</div>
            <div class="legend-item"><div class="legend-dot red"></div> Action needed</div>
            <div class="legend-item"><span style="color:#9ca3af">(?) Hover for info</span></div>
            <div class="legend-item"><span>ℹ️ Click for docs</span></div>
        </div>
        
        <div class="section">
            <div class="tabs">
                <button class="tab active" onclick="showTab('ssl')">SSL/TLS & HSTS</button>
                <button class="tab" onclick="showTab('security')">Security</button>
                <button class="tab" onclick="showTab('bots')">Bots & AI</button>
                <button class="tab" onclick="showTab('speed')">Speed & Protocols</button>
                <button class="tab" onclick="showTab('cache')">Caching</button>
                <button class="tab" onclick="showTab('dns')">DNS</button>
                <button class="tab" onclick="showTab('workers')">Workers</button>
                <button class="tab" onclick="showTab('ipaccess')">IP Access</button>
                <button class="tab" onclick="showTab('rules')">Rules & Redirects</button>
                <button class="tab" onclick="showTab('securitytxt')">Security.txt</button>
                <button class="tab" onclick="showTab('recommendations')">📋 Recommendations</button>
            </div>
            
            <!-- SSL/TLS Tab -->
            <div id="ssl" class="tab-content active">
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>Plan</th>
                                <th>$(Get-HeaderHtml 'SSL Mode' 'ssl_mode')</th>
                                <th>$(Get-HeaderHtml 'Min TLS' 'min_tls')</th>
                                <th>$(Get-HeaderHtml 'TLS 1.3' 'tls_1_3')</th>
                                <th>$(Get-HeaderHtml 'Always HTTPS' 'always_https')</th>
                                <th>$(Get-HeaderHtml 'Auto Rewrites' 'auto_https_rewrites')</th>
                                <th>$(Get-HeaderHtml 'Cert Transparency' 'cert_transparency')</th>
                                <th>$(Get-HeaderHtml 'HSTS' 'hsts')</th>
                                <th>Max-Age</th>
                                <th>Subdomains</th>
                                <th>Preload</th>
                                <th>$(Get-HeaderHtml 'NoSniff' 'nosniff')</th>
                            </tr>
                        </thead>
                        <tbody>
"@

foreach ($r in $results) {
    $htmlContent += @"
                            <tr>
                                <td class="zone-name"><a href="$($r.ZoneUrl)" target="_blank">$($r.Zone)</a></td>
                                <td>$($r.Plan)</td>
                                <td><span class="$(Get-RagClass $r.SSL_Mode_RAG)">$($r.SSL_Mode)</span></td>
                                <td><span class="$(Get-RagClass $r.Min_TLS_RAG)">$($r.Min_TLS_Version)</span></td>
                                <td><span class="$(Get-RagClass $r.TLS_1_3_RAG)">$($r.TLS_1_3)</span></td>
                                <td><span class="$(Get-RagClass $r.Always_HTTPS_RAG)">$($r.Always_Use_HTTPS)</span></td>
                                <td>$($r.Auto_HTTPS_Rewrites)</td>
                                <td>$($r.Certificate_Transparency)</td>
                                <td><span class="$(Get-RagClass $r.HSTS_RAG)">$($r.HSTS_Enabled)</span></td>
                                <td>$($r.HSTS_Max_Age)</td>
                                <td>$($r.HSTS_Include_Subdomains)</td>
                                <td>$($r.HSTS_Preload)</td>
                                <td>$($r.HSTS_NoSniff)</td>
                            </tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Security Tab -->
            <div id="security" class="tab-content">
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>$(Get-HeaderHtml 'Security Level' 'security_level')</th>
                                <th>$(Get-HeaderHtml 'Browser Check' 'browser_check')</th>
                                <th>$(Get-HeaderHtml 'Email Obfuscation' 'email_obfuscation')</th>
                                <th>$(Get-HeaderHtml 'Hotlink Protection' 'hotlink_protection')</th>
                                <th>Challenge TTL</th>
                                <th>$(Get-HeaderHtml 'WAF' 'waf')</th>
                                <th>Replace Insecure JS</th>
                                <th>$(Get-HeaderHtml 'Leaked Creds' 'leaked_creds')</th>
                            </tr>
                        </thead>
                        <tbody>
"@

foreach ($r in $results) {
    $htmlContent += @"
                            <tr>
                                <td class="zone-name"><a href="$($r.ZoneUrl)" target="_blank">$($r.Zone)</a></td>
                                <td><span class="$(Get-RagClass $r.Security_Level_RAG)">$($r.Security_Level)</span></td>
                                <td><span class="$(Get-RagClass $r.Browser_Check_RAG)">$($r.Browser_Integrity_Check)</span></td>
                                <td>$($r.Email_Obfuscation)</td>
                                <td>$($r.Hotlink_Protection)</td>
                                <td>$($r.Challenge_TTL)</td>
                                <td>$($r.WAF)</td>
                                <td>$($r.Replace_Insecure_JS)</td>
                                <td>$($r.Leaked_Credentials_Detection)</td>
                            </tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Bots Tab -->
            <div id="bots" class="tab-content">
                <div class="api-permissions">
                    <h4>ℹ️ Bot Management</h4>
                    <p>Some features require specific plan levels or API permissions. N/A may indicate missing permissions.</p>
                </div>
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>Plan</th>
                                <th>$(Get-HeaderHtml 'Bot Fight Mode' 'bot_fight_mode')</th>
                                <th>$(Get-HeaderHtml 'AI Labyrinth' 'ai_labyrinth')</th>
                                <th>$(Get-HeaderHtml 'Block AI Bots' 'block_ai_bots')</th>
                            </tr>
                        </thead>
                        <tbody>
"@

foreach ($r in $results) {
    $htmlContent += @"
                            <tr>
                                <td class="zone-name"><a href="$($r.ZoneUrl)" target="_blank">$($r.Zone)</a></td>
                                <td>$($r.Plan)</td>
                                <td><span class="$(Get-RagClass $r.Bot_Fight_RAG)">$($r.Bot_Fight_Mode)</span></td>
                                <td>$($r.AI_Labyrinth)</td>
                                <td>$($r.Block_AI_Bots)</td>
                            </tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Speed Tab -->
            <div id="speed" class="tab-content">
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>$(Get-HeaderHtml 'HTTP/2' 'http2')</th>
                                <th>$(Get-HeaderHtml 'HTTP/3' 'http3')</th>
                                <th>$(Get-HeaderHtml 'HTTP/2 Origin' 'http2_origin')</th>
                                <th>$(Get-HeaderHtml '0-RTT' 'zero_rtt')</th>
                                <th>$(Get-HeaderHtml 'Early Hints' 'early_hints')</th>
                                <th>$(Get-HeaderHtml 'Speed Brain' 'speed_brain')</th>
                                <th>$(Get-HeaderHtml 'Rocket Loader' 'rocket_loader')</th>
                                <th>WebSockets</th>
                            </tr>
                        </thead>
                        <tbody>
"@

foreach ($r in $results) {
    $htmlContent += @"
                            <tr>
                                <td class="zone-name"><a href="$($r.ZoneUrl)" target="_blank">$($r.Zone)</a></td>
                                <td><span class="$(Get-RagClass $r.HTTP2_RAG)">$($r.HTTP2)</span></td>
                                <td><span class="$(Get-RagClass $r.HTTP3_RAG)">$($r.HTTP3)</span></td>
                                <td>$($r.HTTP2_to_Origin)</td>
                                <td><span class="$(Get-RagClass $r.Zero_RTT_RAG)">$($r.Zero_RTT)</span></td>
                                <td><span class="$(Get-RagClass $r.Early_Hints_RAG)">$($r.Early_Hints)</span></td>
                                <td>$($r.Speed_Brain)</td>
                                <td>$($r.Rocket_Loader)</td>
                                <td>$($r.WebSockets)</td>
                            </tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Cache Tab -->
            <div id="cache" class="tab-content">
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>$(Get-HeaderHtml 'Minify JS' 'minify')</th>
                                <th>Minify CSS</th>
                                <th>Minify HTML</th>
                                <th>$(Get-HeaderHtml 'Polish' 'polish')</th>
                                <th>$(Get-HeaderHtml 'Mirage' 'mirage')</th>
                                <th>$(Get-HeaderHtml 'Browser TTL' 'cache_ttl')</th>
                                <th>Cache Level</th>
                                <th>$(Get-HeaderHtml 'Dev Mode' 'dev_mode')</th>
                                <th>$(Get-HeaderHtml 'Argo' 'argo')</th>
                            </tr>
                        </thead>
                        <tbody>
"@

foreach ($r in $results) {
    $htmlContent += @"
                            <tr>
                                <td class="zone-name"><a href="$($r.ZoneUrl)" target="_blank">$($r.Zone)</a></td>
                                <td>$($r.Minify_JS)</td>
                                <td>$($r.Minify_CSS)</td>
                                <td>$($r.Minify_HTML)</td>
                                <td>$($r.Polish)</td>
                                <td>$($r.Mirage)</td>
                                <td>$($r.Browser_Cache_TTL)</td>
                                <td>$($r.Cache_Level)</td>
                                <td><span class="$(Get-RagClass $r.Dev_Mode_RAG)">$($r.Development_Mode)</span></td>
                                <td>$($r.Argo_Smart_Routing)</td>
                            </tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- DNS Tab -->
            <div id="dns" class="tab-content">
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>Status</th>
                                <th>$(Get-HeaderHtml 'DNSSEC' 'dnssec')</th>
                            </tr>
                        </thead>
                        <tbody>
"@

foreach ($r in $results) {
    $htmlContent += @"
                            <tr>
                                <td class="zone-name"><a href="$($r.ZoneUrl)" target="_blank">$($r.Zone)</a></td>
                                <td>$($r.Status)</td>
                                <td><span class="$(Get-RagClass $r.DNSSEC_RAG)">$($r.DNSSEC)</span></td>
                            </tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Workers Tab -->
            <div id="workers" class="tab-content">
                <div class="table-scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>Route Pattern</th>
                                <th>Worker Script</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
"@

if ($workersData.Count -gt 0) {
    foreach ($w in $workersData) {
        $zoneResult = $results | Where-Object { $_.Zone -eq $w.Zone } | Select-Object -First 1
        $zoneUrl = if ($zoneResult) { $zoneResult.ZoneUrl } else { "#" }
        
        $htmlContent += @"
                            <tr>
                                <td class="zone-name"><a href="$zoneUrl" target="_blank">$($w.Zone)</a></td>
                                <td><code>$($w.Pattern)</code></td>
                                <td>$($w.Script)</td>
                                <td>$($w.Enabled)</td>
                            </tr>
"@
    }
}
else {
    $htmlContent += @"
                            <tr><td colspan="4" style="text-align:center;padding:40px;color:#6b7280;">No worker routes found.</td></tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- IP Access Tab -->
            <div id="ipaccess" class="tab-content">
                <div class="filters">
                    <div class="filter-group">
                        <label>Zone:</label>
                        <select id="ipZoneFilter" onchange="filterIPAccess()">
                            <option value="">All Zones</option>
"@

foreach ($zone in ($ipAccessData | Select-Object -ExpandProperty Zone -Unique | Sort-Object)) {
    $htmlContent += "                            <option value=`"$zone`">$zone</option>`n"
}

$htmlContent += @"
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Mode:</label>
                        <select id="ipModeFilter" onchange="filterIPAccess()">
                            <option value="">All Modes</option>
                            <option value="block">Block</option>
                            <option value="whitelist">Whitelist</option>
                            <option value="challenge">Challenge</option>
                            <option value="js_challenge">JS Challenge</option>
                            <option value="managed_challenge">Managed Challenge</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Target Type:</label>
                        <select id="ipTypeFilter" onchange="filterIPAccess()">
                            <option value="">All Types</option>
                            <option value="ip">IP</option>
                            <option value="ip_range">IP Range</option>
                            <option value="country">Country</option>
                            <option value="asn">ASN</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="ipSearchFilter" placeholder="Search target or notes..." onkeyup="filterIPAccess()">
                    </div>
                    <button class="btn btn-secondary" onclick="clearIPFilters()">Clear Filters</button>
                </div>
                <div class="table-scroll">
                    <table id="ipAccessTable">
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>Mode</th>
                                <th>Target Type</th>
                                <th>Target</th>
                                <th>Notes</th>
                                <th>Status</th>
                                <th>Created</th>
                            </tr>
                        </thead>
                        <tbody>
"@

if ($ipAccessData.Count -gt 0) {
    foreach ($ip in $ipAccessData) {
        $zoneResult = $results | Where-Object { $_.Zone -eq $ip.Zone } | Select-Object -First 1
        $zoneUrl = if ($zoneResult) { $zoneResult.ZoneUrl } else { "#" }
        
        $modeClass = switch ($ip.Mode) {
            "block" { "status-red" }
            "whitelist" { "status-green" }
            default { "status-amber" }
        }
        
        $notesEncoded = [System.Net.WebUtility]::HtmlEncode($ip.Notes)
        
        $htmlContent += @"
                            <tr data-zone="$($ip.Zone)" data-mode="$($ip.Mode)" data-type="$($ip.TargetType)" data-target="$($ip.Target)" data-notes="$notesEncoded">
                                <td class="zone-name"><a href="$zoneUrl" target="_blank">$($ip.Zone)</a></td>
                                <td><span class="$modeClass">$($ip.Mode)</span></td>
                                <td>$($ip.TargetType)</td>
                                <td><code>$($ip.Target)</code></td>
                                <td>$notesEncoded</td>
                                <td>$($ip.Status)</td>
                                <td>$($ip.Created)</td>
                            </tr>
"@
    }
}
else {
    $htmlContent += @"
                            <tr><td colspan="7" style="text-align:center;padding:40px;color:#6b7280;">No IP Access Rules found.</td></tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Rules Tab -->
            <div id="rules" class="tab-content">
                <div class="filters">
                    <div class="filter-group">
                        <label>Zone:</label>
                        <select id="ruleZoneFilter" onchange="filterRules()">
                            <option value="">All Zones</option>
"@

foreach ($zone in ($rulesData | Select-Object -ExpandProperty Zone -Unique | Sort-Object)) {
    $htmlContent += "                            <option value=`"$zone`">$zone</option>`n"
}

$htmlContent += @"
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Rule Type:</label>
                        <select id="ruleTypeFilter" onchange="filterRules()">
                            <option value="">All Types</option>
"@

foreach ($type in ($rulesData | Select-Object -ExpandProperty RuleType -Unique | Sort-Object)) {
    $htmlContent += "                            <option value=`"$type`">$type</option>`n"
}

$htmlContent += @"
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="ruleSearchFilter" placeholder="Search trigger or action..." onkeyup="filterRules()">
                    </div>
                    <button class="btn btn-secondary" onclick="clearRuleFilters()">Clear Filters</button>
                </div>
                <div class="table-scroll">
                    <table id="rulesTable">
                        <thead>
                            <tr>
                                <th>Zone</th>
                                <th>Type</th>
                                <th>Name</th>
                                <th>Status</th>
                                <th style="min-width:300px;">Trigger / Expression</th>
                                <th style="min-width:300px;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
"@

if ($rulesData.Count -gt 0) {
    foreach ($rule in $rulesData) {
        $zoneResult = $results | Where-Object { $_.Zone -eq $rule.Zone } | Select-Object -First 1
        $zoneUrl = if ($zoneResult) { $zoneResult.ZoneUrl } else { "#" }
        
        $triggerEncoded = [System.Net.WebUtility]::HtmlEncode($rule.Trigger)
        $actionsEncoded = [System.Net.WebUtility]::HtmlEncode($rule.Actions)
        $nameEncoded = [System.Net.WebUtility]::HtmlEncode($rule.RuleName)
        
        $htmlContent += @"
                            <tr data-zone="$($rule.Zone)" data-type="$($rule.RuleType)" data-trigger="$triggerEncoded" data-actions="$actionsEncoded">
                                <td class="zone-name"><a href="$zoneUrl" target="_blank">$($rule.Zone)</a></td>
                                <td><span class="status-gray">$($rule.RuleType)</span></td>
                                <td>$nameEncoded</td>
                                <td>$($rule.Status)</td>
                                <td><code>$triggerEncoded</code></td>
                                <td><code>$actionsEncoded</code></td>
                            </tr>
"@
    }
}
else {
    $htmlContent += @"
                            <tr><td colspan="6" style="text-align:center;padding:40px;color:#6b7280;">No rules found. Check API permissions.</td></tr>
"@
}

$htmlContent += @"
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Security.txt Tab -->
            <div id="securitytxt" class="tab-content">
                <div class="api-permissions">
                    <h4>ℹ️ $(Get-HeaderHtml 'Security.txt' 'security_txt')</h4>
                    <p>The security.txt file helps security researchers contact you responsibly when they find vulnerabilities.</p>
                </div>
"@

foreach ($stxt in $securityTxtData) {
    $zoneResult = $results | Where-Object { $_.Zone -eq $stxt.Zone } | Select-Object -First 1
    $zoneUrl = if ($zoneResult) { $zoneResult.ZoneUrl } else { "#" }
    
    $statusClass = if ($stxt.Enabled -eq "on") { "status-green" } else { "status-red" }
    $contentEncoded = [System.Net.WebUtility]::HtmlEncode($stxt.Content)
    
    $htmlContent += @"
                <div style="margin: 16px; padding: 16px; background: white; border: 1px solid #e5e7eb; border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <h3 style="font-size: 16px;"><a href="$zoneUrl" target="_blank" style="color: var(--primary);">$($stxt.Zone)</a></h3>
                        <span class="$statusClass">$($stxt.Enabled)</span>
                    </div>
"@
    
    if (-not [string]::IsNullOrEmpty($stxt.Content)) {
        $htmlContent += @"
                    <div class="security-txt-content">$contentEncoded</div>
"@
    }
    else {
        $htmlContent += @"
                    <p style="color: #6b7280; font-style: italic;">No security.txt content configured.</p>
"@
    }
    
    $htmlContent += @"
                </div>
"@
}

$htmlContent += @"
            </div>
            
            <!-- Recommendations Tab -->
            <div id="recommendations" class="tab-content">
                <div style="padding: 24px;">
                    <h2 style="margin-bottom: 20px; font-size: 20px;">📋 Recommended Actions</h2>
                    
                    <div style="display: grid; gap: 16px;">
                        <div style="background: var(--red-bg); border-left: 4px solid var(--red); padding: 16px; border-radius: 0 8px 8px 0;">
                            <h3 style="color: #991b1b; margin-bottom: 8px;">🔴 Critical Security</h3>
                            <ul style="padding-left: 20px; color: #7f1d1d;">
                                <li><strong>SSL Mode:</strong> Set to <code>Full (Strict)</code> for all production sites. <a href="$($script:DocLinks['ssl_mode'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Minimum TLS:</strong> Set to <code>1.2</code>. TLS 1.0/1.1 are deprecated. <a href="$($script:DocLinks['min_tls'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Always HTTPS:</strong> Enable on all zones. <a href="$($script:DocLinks['always_https'])" target="_blank">Docs ↗</a></li>
                                <li><strong>HSTS:</strong> Enable with max-age ≥ 15768000 (6 months). <a href="$($script:DocLinks['hsts'])" target="_blank">Docs ↗</a></li>
                            </ul>
                        </div>
                        
                        <div style="background: var(--amber-bg); border-left: 4px solid var(--amber); padding: 16px; border-radius: 0 8px 8px 0;">
                            <h3 style="color: #92400e; margin-bottom: 8px;">🟡 Important Security</h3>
                            <ul style="padding-left: 20px; color: #78350f;">
                                <li><strong>DNSSEC:</strong> Enable on all zones to prevent DNS spoofing. <a href="$($script:DocLinks['dnssec'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Bot Fight Mode:</strong> Enable to challenge bot traffic. <a href="$($script:DocLinks['bot_fight_mode'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Browser Integrity Check:</strong> Enable to block invalid User-Agents. <a href="$($script:DocLinks['browser_check'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Block AI Bots:</strong> Consider if you don't want AI crawlers. <a href="$($script:DocLinks['block_ai_bots'])" target="_blank">Docs ↗</a></li>
                            </ul>
                        </div>
                        
                        <div style="background: var(--green-bg); border-left: 4px solid var(--green); padding: 16px; border-radius: 0 8px 8px 0;">
                            <h3 style="color: #166534; margin-bottom: 8px;">🟢 Performance & Best Practice</h3>
                            <ul style="padding-left: 20px; color: #14532d;">
                                <li><strong>TLS 1.3:</strong> Enable for improved security and performance. <a href="$($script:DocLinks['tls_1_3'])" target="_blank">Docs ↗</a></li>
                                <li><strong>HTTP/2 & HTTP/3:</strong> Enable for better performance. <a href="$($script:DocLinks['http3'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Early Hints:</strong> Enable to preload assets. <a href="$($script:DocLinks['early_hints'])" target="_blank">Docs ↗</a></li>
                                <li><strong>0-RTT:</strong> Enable for faster TLS resumption. <a href="$($script:DocLinks['zero_rtt'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Development Mode:</strong> Ensure OFF in production. <a href="$($script:DocLinks['dev_mode'])" target="_blank">Docs ↗</a></li>
                            </ul>
                        </div>
                        
                        <div style="background: var(--gray-bg); border-left: 4px solid var(--gray); padding: 16px; border-radius: 0 8px 8px 0;">
                            <h3 style="color: #374151; margin-bottom: 8px;">📝 Documentation</h3>
                            <ul style="padding-left: 20px; color: #4b5563;">
                                <li><strong>Security.txt:</strong> Configure contact info for security researchers. <a href="$($script:DocLinks['security_txt'])" target="_blank">Docs ↗</a></li>
                                <li><strong>IP Access Rules:</strong> Document and review periodically. <a href="$($script:DocLinks['ip_access_rules'])" target="_blank">Docs ↗</a></li>
                                <li><strong>Workers:</strong> Audit worker routes and scripts. <a href="$($script:DocLinks['workers'])" target="_blank">Docs ↗</a></li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <footer>
            <p>The Collegiate Trust - IT Department | Cloudflare Security Audit v4.0</p>
            <p style="margin-top:8px;font-size:11px;">Hover over (?) for explanations • Click ℹ️ for documentation</p>
        </footer>
    </div>
    
    <script>
        function showTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }
        
        function filterRules() {
            const zone = document.getElementById('ruleZoneFilter').value.toLowerCase();
            const type = document.getElementById('ruleTypeFilter').value.toLowerCase();
            const search = document.getElementById('ruleSearchFilter').value.toLowerCase();
            
            document.querySelectorAll('#rulesTable tbody tr').forEach(row => {
                const rowZone = (row.dataset.zone || '').toLowerCase();
                const rowType = (row.dataset.type || '').toLowerCase();
                const rowTrigger = (row.dataset.trigger || '').toLowerCase();
                const rowActions = (row.dataset.actions || '').toLowerCase();
                
                const matchZone = !zone || rowZone === zone;
                const matchType = !type || rowType === type;
                const matchSearch = !search || rowTrigger.includes(search) || rowActions.includes(search);
                
                row.style.display = (matchZone && matchType && matchSearch) ? '' : 'none';
            });
        }
        
        function clearRuleFilters() {
            document.getElementById('ruleZoneFilter').value = '';
            document.getElementById('ruleTypeFilter').value = '';
            document.getElementById('ruleSearchFilter').value = '';
            filterRules();
        }
        
        function filterIPAccess() {
            const zone = document.getElementById('ipZoneFilter').value.toLowerCase();
            const mode = document.getElementById('ipModeFilter').value.toLowerCase();
            const type = document.getElementById('ipTypeFilter').value.toLowerCase();
            const search = document.getElementById('ipSearchFilter').value.toLowerCase();
            
            document.querySelectorAll('#ipAccessTable tbody tr').forEach(row => {
                const rowZone = (row.dataset.zone || '').toLowerCase();
                const rowMode = (row.dataset.mode || '').toLowerCase();
                const rowType = (row.dataset.type || '').toLowerCase();
                const rowTarget = (row.dataset.target || '').toLowerCase();
                const rowNotes = (row.dataset.notes || '').toLowerCase();
                
                const matchZone = !zone || rowZone === zone;
                const matchMode = !mode || rowMode === mode;
                const matchType = !type || rowType === type;
                const matchSearch = !search || rowTarget.includes(search) || rowNotes.includes(search);
                
                row.style.display = (matchZone && matchMode && matchType && matchSearch) ? '' : 'none';
            });
        }
        
        function clearIPFilters() {
            document.getElementById('ipZoneFilter').value = '';
            document.getElementById('ipModeFilter').value = '';
            document.getElementById('ipTypeFilter').value = '';
            document.getElementById('ipSearchFilter').value = '';
            filterIPAccess();
        }
    </script>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "  HTML:        $htmlPath" -ForegroundColor Green

#endregion

#region Summary Output

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Audit Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`n  Zones audited:       $totalZones"
Write-Host "  Zones with issues:   $zonesWithIssues" -ForegroundColor $(if ($zonesWithIssues -gt 0) { "Red" } else { "Green" })
Write-Host "  Critical issues:     $issueCount" -ForegroundColor $(if ($issueCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Warnings:            $warningCount" -ForegroundColor $(if ($warningCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Rules documented:    $($rulesData.Count)"
Write-Host "  Workers documented:  $($workersData.Count)"
Write-Host "  IP Access Rules:     $($ipAccessData.Count)"
Write-Host "`n  Reports saved to:"
Write-Host "    CSV (Settings):    $csvPath"
if ($IncludeRules -and $rulesData.Count -gt 0) {
    Write-Host "    CSV (Rules):       $rulesCsvPath"
}
if ($workersData.Count -gt 0) {
    Write-Host "    CSV (Workers):     $workersCsvPath"
}
if ($ipAccessData.Count -gt 0) {
    Write-Host "    CSV (IP Access):   $ipAccessCsvPath"
}
if ($securityTxtData.Count -gt 0) {
    Write-Host "    CSV (Security.txt): $secTxtCsvPath"
}
Write-Host "    HTML Report:       $htmlPath"
Write-Host ""

#endregion

# Return results for pipeline use
return @{
    Settings    = $results
    Rules       = $rulesData
    Workers     = $workersData
    IPAccess    = $ipAccessData
    SecurityTxt = $securityTxtData
}
