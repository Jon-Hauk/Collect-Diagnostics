<#
.SYNOPSIS
    Read-only Windows diagnostic collector for troubleshooting Windows 10/11 systems.

.DESCRIPTION
    Collects system, hardware, event log, network, service, startup, security, and process
    diagnostics into a timestamped Diag_<yyyyMMdd_HHmm> folder, generates a summary.md
    with automated issue flags, and compresses everything into a .zip archive.

    Strictly read-only: performs no registry writes, no service modifications, and no
    outbound network calls other than the explicit connectivity check (ping 8.8.8.8 and
    DNS resolution test) in the Network section.

.PARAMETER Redact
    Replaces usernames, hostname, domain, MAC addresses, and private/link-local IP
    addresses with stable anonymized tokens (USER_1, HOST_1, DOMAIN_1, MAC_1, IP_1, ...).

.PARAMETER OutputDirectory
    Directory where the Diag_<timestamp> folder and .zip archive are written.
    Defaults to the directory containing this script (or the current working directory).

.EXAMPLE
    .\Collect-Diagnostics.ps1

.EXAMPLE
    .\Collect-Diagnostics.ps1 -Redact
#>
[CmdletBinding()]
param(
    [switch]$Redact,
    [string]$OutputDirectory
)

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Returns $true if the current PowerShell process has Administrator privileges.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-IsAccessDeniedException {
    <#
    .SYNOPSIS
        Determines whether an ErrorRecord represents an elevation/access-denied error.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $ErrorRecord
    )

    if ($null -eq $ErrorRecord) {
        return $false
    }

    $ex = $ErrorRecord.Exception
    $category = $ErrorRecord.CategoryInfo.Category
    $msg = if ($ex) { $ex.Message } else { '' }

    if ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException]) {
        return $true
    }
    if ($category -eq [System.Management.Automation.ErrorCategory]::PermissionDenied) {
        return $true
    }
    if ($msg -match '(?i)access\s+is\s+denied|access\s+denied|unauthorized|requires\s+elevation|administrator\s+privilege') {
        return $true
    }

    return $false
}

function Get-LocalProfileUserNames {
    <#
    .SYNOPSIS
        Discovers local profile folder names under C:\Users for thorough redaction.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $excluded = @('Public', 'Default', 'All Users', 'Default User')
    $names = New-Object 'System.Collections.Generic.List[string]'

    try {
        if (Test-Path -LiteralPath 'C:\Users') {
            $dirs = Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue
            foreach ($dir in $dirs) {
                if ($excluded -notcontains $dir.Name -and -not [string]::IsNullOrWhiteSpace($dir.Name)) {
                    $names.Add($dir.Name)
                }
            }
        }
    }
    catch {
        # Best-effort only; ignore profile enumeration failures.
    }

    return $names.ToArray()
}

function Test-IsBuiltInPrincipal {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $true
    }

    $trimmed = $Name.Trim()
    $builtIn = @(
        'SYSTEM', 'LocalSystem', 'LocalService', 'NetworkService',
        'LOCAL SERVICE', 'NETWORK SERVICE', 'TrustedInstaller',
        'NT AUTHORITY', 'NT SERVICE', 'BUILTIN', 'IIS APPPOOL',
        'Window Manager', 'Font Driver Host',
        'INTERACTIVE', 'EVERYONE', 'Authenticated Users',
        'Users', 'Administrators', 'Creator Owner', 'Anonymous Logon',
        'N/A', 'Disabled', '<Disabled>', 'Author'
    )

    foreach ($b in $builtIn) {
        if ($trimmed -ieq $b) {
            return $true
        }
    }

    if ($trimmed -match '^(?i)(?:DWM|UMFD)-\d+$') {
        return $true
    }
    if ($trimmed -match '^(?i)S-1-\d+(?:-\d+)*$') {
        return $true
    }

    return $false
}

function Get-DiscoveredRedactionAccounts {
    <#
    .SYNOPSIS
        Discovers user and domain accounts from C:\Users, scheduled task principals, and service StartName entries.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    $users = New-Object 'System.Collections.Generic.HashSet[string]' $comparer
    $domains = New-Object 'System.Collections.Generic.HashSet[string]' $comparer

    $addAccountString = {
        param([string]$AccountRaw)
        if ([string]::IsNullOrWhiteSpace($AccountRaw)) {
            return
        }
        $acct = $AccountRaw.Trim()
        if (Test-IsBuiltInPrincipal -Name $acct) {
            return
        }

        if ($acct -match '^([^\\]+)\\(.+)$') {
            $dom = $matches[1].Trim()
            $usr = $matches[2].Trim()

            if (Test-IsBuiltInPrincipal -Name $dom) {
                return
            }

            if ($dom -ne '.' -and
                -not [string]::IsNullOrWhiteSpace($dom) -and
                $dom -ine 'WORKGROUP' -and
                ([string]::IsNullOrWhiteSpace($ComputerName) -or $dom -ine $ComputerName.Trim())) {
                [void]$domains.Add($dom)
            }

            if (-not (Test-IsBuiltInPrincipal -Name $usr)) {
                [void]$users.Add($usr)
            }
        }
        elseif ($acct -match '^([^@\s]+)@([^@\s]+)$') {
            $usr = $matches[1].Trim()
            $dom = $matches[2].Trim()
            if (-not (Test-IsBuiltInPrincipal -Name $usr)) {
                [void]$users.Add($usr)
            }
            if (-not [string]::IsNullOrWhiteSpace($dom) -and
                ([string]::IsNullOrWhiteSpace($ComputerName) -or $dom -ine $ComputerName.Trim())) {
                [void]$domains.Add($dom)
            }
        }
        else {
            [void]$users.Add($acct)
        }
    }

    # 1. Every folder name under C:\Users (except built-in shared/template folders)
    foreach ($profileName in (Get-LocalProfileUserNames)) {
        if (-not [string]::IsNullOrWhiteSpace($profileName)) {
            [void]$users.Add($profileName)
        }
    }

    # 2. Scheduled task principals (UserId)
    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        foreach ($t in $tasks) {
            $principalProp = $t.PSObject.Properties['Principal']
            if ($null -ne $principalProp -and $null -ne $principalProp.Value) {
                $uidProp = $principalProp.Value.PSObject.Properties['UserId']
                if ($null -ne $uidProp -and -not [string]::IsNullOrWhiteSpace([string]$uidProp.Value)) {
                    & $addAccountString ([string]$uidProp.Value)
                }
            }
        }
    }
    catch {
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $csvLines = @(& schtasks.exe /Query /FO CSV /V 2>$null)
            if ($LASTEXITCODE -eq 0 -and $csvLines.Count -gt 1) {
                $parsed = @($csvLines | ConvertFrom-Csv -ErrorAction Stop)
                foreach ($row in $parsed) {
                    $runAsProp = $row.PSObject.Properties['Run As User']
                    if ($null -ne $runAsProp -and -not [string]::IsNullOrWhiteSpace([string]$runAsProp.Value)) {
                        & $addAccountString ([string]$runAsProp.Value)
                    }
                }
            }
        }
        catch {
            # Best-effort only
        }
        finally {
            $ErrorActionPreference = $prevEap
        }
    }

    # 3. Service StartName accounts
    try {
        $svcs = @(Get-CimInstance -ClassName Win32_Service -Property StartName -ErrorAction Stop)
        foreach ($s in $svcs) {
            $snProp = $s.PSObject.Properties['StartName']
            if ($null -ne $snProp -and -not [string]::IsNullOrWhiteSpace([string]$snProp.Value)) {
                & $addAccountString ([string]$snProp.Value)
            }
        }
    }
    catch {
        try {
            $svcKeys = Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue
            foreach ($sk in $svcKeys) {
                $props = Get-ItemProperty -LiteralPath $sk.PSPath -Name 'ObjectName' -ErrorAction SilentlyContinue
                if ($null -ne $props -and $props.PSObject.Properties['ObjectName'] -and -not [string]::IsNullOrWhiteSpace([string]$props.ObjectName)) {
                    & $addAccountString ([string]$props.ObjectName)
                }
            }
        }
        catch {
            # Best-effort only
        }
    }

    return @{
        Users   = @($users)
        Domains = @($domains)
    }
}

function New-RedactionContext {
    <#
    .SYNOPSIS
        Creates a stateful, case-insensitive redaction context mapping sensitive values to stable tokens.
    #>
    [CmdletBinding()]
    param(
        [string]$UserName = $env:USERNAME,
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$Domain = $env:USERDOMAIN,
        [string]$DnsDomain = $env:USERDNSDOMAIN,
        [string[]]$AdditionalUsers = @(),
        [string[]]$AdditionalDomains = @()
    )

    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    $literalMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' $comparer
    $macMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' $comparer
    $ipMap = New-Object 'System.Collections.Generic.Dictionary[string,string]' $comparer
    $ip6Map = New-Object 'System.Collections.Generic.Dictionary[string,string]' $comparer

    $ctx = @{
        LiteralMap = $literalMap
        MacMap     = $macMap
        IpMap      = $ipMap
        Ip6Map     = $ip6Map
        Counters   = @{
            USER   = 0
            HOST   = 0
            DOMAIN = 0
            MAC    = 0
            IP     = 0
            IP6    = 0
        }
    }

    $registerLiteral = {
        param([string]$Value, [string]$Category)
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return
        }
        $trimmed = $Value.Trim()
        if ($trimmed.Length -lt 2) {
            return
        }
        if (-not $ctx.LiteralMap.ContainsKey($trimmed)) {
            $ctx.Counters[$Category]++
            $ctx.LiteralMap[$trimmed] = '{0}_{1}' -f $Category, $ctx.Counters[$Category]
        }
    }

    # Register ComputerName first so standalone workgroup machines map ComputerName -> HOST_1
    if (-not [string]::IsNullOrWhiteSpace($ComputerName)) {
        & $registerLiteral $ComputerName 'HOST'
    }

    if (-not [string]::IsNullOrWhiteSpace($UserName)) {
        & $registerLiteral $UserName 'USER'
    }

    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        $isSameAsHost = (-not [string]::IsNullOrWhiteSpace($ComputerName)) -and ($Domain.Trim() -ieq $ComputerName.Trim())
        $isWorkgroup = $Domain.Trim() -ieq 'WORKGROUP'
        if (-not $isSameAsHost -and -not $isWorkgroup) {
            & $registerLiteral $Domain 'DOMAIN'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($DnsDomain)) {
        $isSameAsHost = (-not [string]::IsNullOrWhiteSpace($ComputerName)) -and ($DnsDomain.Trim() -ieq $ComputerName.Trim())
        if (-not $isSameAsHost) {
            & $registerLiteral $DnsDomain 'DOMAIN'
        }
    }

    foreach ($extraUser in $AdditionalUsers) {
        if (-not [string]::IsNullOrWhiteSpace($extraUser)) {
            & $registerLiteral $extraUser 'USER'
        }
    }

    foreach ($extraDomain in $AdditionalDomains) {
        if (-not [string]::IsNullOrWhiteSpace($extraDomain)) {
            $isSameAsHost = (-not [string]::IsNullOrWhiteSpace($ComputerName)) -and ($extraDomain.Trim() -ieq $ComputerName.Trim())
            $isWorkgroup = $extraDomain.Trim() -ieq 'WORKGROUP'
            if (-not $isSameAsHost -and -not $isWorkgroup) {
                & $registerLiteral $extraDomain 'DOMAIN'
            }
        }
    }

    return $ctx
}

function Get-OrCreateToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Map,
        [Parameter(Mandatory = $true)]
        [hashtable]$Counters,
        [Parameter(Mandatory = $true)]
        [string]$Category,
        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    if ($Map.ContainsKey($Key)) {
        return $Map[$Key]
    }

    $Counters[$Category]++
    $token = '{0}_{1}' -f $Category, $Counters[$Category]
    $Map[$Key] = $token
    return $token
}

function Get-RedactionPatterns {
    <#
    .SYNOPSIS
        Returns shared regex patterns used for account discovery and redaction.
    #>
    [CmdletBinding()]
    param()

    return @{
        UserPathPattern = '(?i)(C:\\Users\\)([^\\/\r\n"''<>|]+)'
        UpnPattern      = '(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)(?![A-Za-z0-9._-])'
        DomUserPattern  = '(?<![A-Za-z0-9_:\\/.\-])(\.|[A-Za-z][A-Za-z0-9_.-]{1,63})\\([A-Za-z][A-Za-z0-9_.-]{1,63})(?![A-Za-z0-9_\\/:])'
    }
}

function Test-ShouldSkipDomainUserMatch {
    <#
    .SYNOPSIS
        Determines whether a DOMAIN\user regex match is a built-in principal, path segment, or non-account pair.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FullText,

        [Parameter(Mandatory = $true)]
        [int]$MatchIndex,

        [Parameter(Mandatory = $true)]
        [int]$MatchLength,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [string]$User,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Context
    )

    if ($Domain -match '^(?i)(?:DOMAIN|HOST)_\d+$' -and $User -match '^(?i)USER_\d+$') {
        return $true
    }

    $lineStart = $FullText.LastIndexOf("`n", [Math]::Max(0, $MatchIndex - 1))
    if ($lineStart -lt 0) { $lineStart = 0 } else { $lineStart++ }
    $beforeOnLine = $FullText.Substring($lineStart, $MatchIndex - $lineStart)

    $afterStart = $MatchIndex + $MatchLength
    $afterOnLine = ''
    if ($afterStart -lt $FullText.Length) {
        $lineEnd = $FullText.IndexOf("`n", $afterStart)
        if ($lineEnd -lt 0) { $lineEnd = $FullText.Length }
        $afterLen = $lineEnd - $afterStart
        if ($afterLen -gt 0) {
            $afterOnLine = $FullText.Substring($afterStart, $afterLen).TrimEnd("`r")
        }
    }

    if ($beforeOnLine -match '(?i)(?:NT|Window|Font Driver|IIS)\s+$') {
        return $true
    }
    # Never match inside a path segment preceded or followed by another backslash (e.g., \NVIDIA Corporation\Package Manager\ or C:\Program Files\App)
    if ($beforeOnLine -match '(?i)(?:^|[\s"''|;,<>])[A-Za-z]:\\[^\r\n"''|;,<>]*$' -and $beforeOnLine -notmatch '(?:\s{2,}|\.\w{2,4}\s+)$') {
        return $true
    }
    if ($beforeOnLine -match '(?:^|[\s"''|;,<>():])\\(?:[^\r\n"''|;,<>():\\]|\s(?!\s))*$') {
        return $true
    }
    if ($afterOnLine -match '^(?:[^\r\n"''|;,<>():\\]|\s(?!\s))*\\') {
        return $true
    }

    $nonDomainRoots = @(
        'SYSTEM', 'AUTHORITY', 'SERVICE', 'BUILTIN', 'APPPOOL', 'Manager', 'Host',
        'Windows', 'System32', 'SysWOW64', 'Microsoft', 'SOFTWARE', 'CurrentControlSet',
        'Policies', 'Classes', 'Users', 'ProgramData', 'PCI', 'USB', 'SCSI', 'IDE',
        'ACPI', 'SWD', 'STORAGE', 'ROOT', 'HID', 'DISPLAY', 'HDAUDIO', 'UMB', 'BTH',
        'NVME', 'UEFI', 'HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC', 'NVIDIA', 'AMD', 'INTEL',
        'WMI', 'CIM', 'COM', 'DCOM', 'RPC', 'HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS', 'DHCP',
        'SMB', 'RDP', 'TLS', 'SSL', 'GUID', 'CLSID', 'APPID', 'WORKGROUP'
    )

    if ($Domain -ne '.') {
        foreach ($skip in $nonDomainRoots) {
            if ($Domain -ieq $skip) {
                return $true
            }
        }
    }
    if (Test-IsBuiltInPrincipal -Name $User) {
        return $true
    }

    # Only tokenize DOMAIN\user when user is already a known account, domain is a known domain/host,
    # domain is '.' (local account), or domain is an ALL-CAPS NetBIOS domain name.
    $isKnownUser = ($User -match '^(?i)USER_\d+$') -or ($Context.LiteralMap.ContainsKey($User) -and $Context.LiteralMap[$User] -match '^USER_\d+$')
    $isKnownDomain = ($Domain -eq '.') -or ($Domain -match '^(?i)(?:DOMAIN|HOST)_\d+$') -or ($Context.LiteralMap.ContainsKey($Domain) -and $Context.LiteralMap[$Domain] -match '^(?:DOMAIN|HOST)_\d+$')
    $isNetBiosDomain = ($Domain -cmatch '^[A-Z][A-Z0-9_-]{1,14}$')

    if (-not ($isKnownUser -or $isKnownDomain -or $isNetBiosDomain)) {
        return $true
    }

    return $false
}

function Update-RedactionContextFromTexts {
    <#
    .SYNOPSIS
        Pass 1 discovery: scans collected section outputs to register all accounts and domains before redaction.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Texts,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Context
    )

    if ($null -eq $Texts -or $Texts.Count -eq 0) {
        return
    }

    $patterns = Get-RedactionPatterns
    $excludedProfiles = @('Public', 'Default', 'Default User', 'All Users')

    # Pass 1A: Discover C:\Users\<name> and user@domain across all texts first
    foreach ($text in $Texts) {
        if ([string]::IsNullOrEmpty($text)) {
            continue
        }

        foreach ($m in [regex]::Matches($text, $patterns.UserPathPattern)) {
            $profileName = $m.Groups[2].Value
            if ($profileName -match '^USER_\d+$') { continue }
            $isExcluded = $false
            foreach ($ex in $excludedProfiles) {
                if ($profileName -ieq $ex) { $isExcluded = $true; break }
            }
            if (-not $isExcluded -and -not [string]::IsNullOrWhiteSpace($profileName) -and $profileName.Length -ge 2) {
                [void](Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'USER' -Key $profileName)
            }
        }

        foreach ($m in [regex]::Matches($text, $patterns.UpnPattern)) {
            $u = $m.Groups[1].Value
            $d = $m.Groups[2].Value
            if ($u -notmatch '^(?i)USER_\d+$' -and $u.Length -ge 2) {
                [void](Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'USER' -Key $u)
            }
            if ($d -notmatch '^(?i)(?:DOMAIN|HOST)_\d+$' -and $d.Length -ge 2) {
                [void](Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'DOMAIN' -Key $d)
            }
        }
    }

    # Pass 1B: Discover DOMAIN\user and .\user across all texts using known accounts/domains
    foreach ($text in $Texts) {
        if ([string]::IsNullOrEmpty($text)) {
            continue
        }

        foreach ($m in [regex]::Matches($text, $patterns.DomUserPattern)) {
            $dom = $m.Groups[1].Value
            $usr = $m.Groups[2].Value
            if (Test-ShouldSkipDomainUserMatch -FullText $text -MatchIndex $m.Index -MatchLength $m.Length -Domain $dom -User $usr -Context $Context) {
                continue
            }
            if ($dom -ne '.' -and $dom -notmatch '^(?i)(?:DOMAIN|HOST)_\d+$' -and $dom.Length -ge 2) {
                [void](Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'DOMAIN' -Key $dom)
            }
            if ($usr -notmatch '^(?i)USER_\d+$' -and $usr.Length -ge 2) {
                [void](Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'USER' -Key $usr)
            }
        }
    }
}

function Protect-RedactedText {
    <#
    .SYNOPSIS
        Redacts usernames, hostnames, domains, MAC addresses, and private/link-local IPs using stable tokens.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Context
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return $Text
    }

    $result = $Text
    $patterns = Get-RedactionPatterns

    # 1. Replace MAC addresses first so hex segments never collide with short usernames/hostnames
    $macPattern = '(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])'
    $result = [regex]::Replace($result, $macPattern, {
        param($match)
        $normalized = $match.Value.Replace('-', ':').ToUpperInvariant()
        return (Get-OrCreateToken -Map $Context.MacMap -Counters $Context.Counters -Category 'MAC' -Key $normalized)
    })

    # 2. Replace private and link-local IPv4 addresses (RFC1918 + 169.254.0.0/16)
    # Strict 0-255 octet bounds prevent matching OS version strings like 10.0.26100.9818.
    $octet = '(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    $privateIpPattern = "(?<![\d.])(?:10\.$octet\.$octet\.$octet|172\.(?:1[6-9]|2\d|3[01])\.$octet\.$octet|192\.168\.$octet\.$octet|169\.254\.$octet\.$octet)(?![\d.])"
    $result = [regex]::Replace($result, $privateIpPattern, {
        param($match)
        return (Get-OrCreateToken -Map $Context.IpMap -Counters $Context.Counters -Category 'IP' -Key $match.Value)
    })

    # 3. Replace link-local (fe80::/10) and ULA (fc00::/7) IPv6 addresses
    $ip6Pattern = '(?<![0-9A-Fa-f:])(?:fe80|fc[0-9A-Fa-f]{2}|fd[0-9A-Fa-f]{2}):(?:[0-9A-Fa-f:]*[0-9A-Fa-f])(?:%[0-9A-Za-z_.-]+)?(?![0-9A-Fa-f:])'
    $result = [regex]::Replace($result, $ip6Pattern, {
        param($match)
        $normalized = $match.Value.ToLowerInvariant()
        return (Get-OrCreateToken -Map $Context.Ip6Map -Counters $Context.Counters -Category 'IP6' -Key $normalized)
    }, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    # 4. Replace known literal values (domains, hostnames, usernames), longest match first
    if ($Context.LiteralMap.Count -gt 0) {
        $sortedKeys = $Context.LiteralMap.Keys | Sort-Object -Property Length -Descending
        foreach ($key in $sortedKeys) {
            $token = $Context.LiteralMap[$key]
            $escaped = [regex]::Escape($key)
            $result = [regex]::Replace($result, $escaped, $token, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }

    $initialKeyCount = $Context.LiteralMap.Count

    # 5. Replace any remaining C:\Users\<username> profile path segments
    $excludedProfiles = @('Public', 'Default', 'Default User', 'All Users')
    $result = [regex]::Replace($result, $patterns.UserPathPattern, {
        param($match)
        $prefix = $match.Groups[1].Value
        $profileName = $match.Groups[2].Value
        if ($profileName -match '^USER_\d+$') {
            return $match.Value
        }
        foreach ($excluded in $excludedProfiles) {
            if ($profileName -ieq $excluded) {
                return $match.Value
            }
        }
        $token = Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'USER' -Key $profileName
        return ($prefix + $token)
    })

    # 6. Replace user@domain UPN / email patterns dynamically and keep tokens stable
    $result = [regex]::Replace($result, $patterns.UpnPattern, {
        param($match)
        $u = $match.Groups[1].Value
        $d = $match.Groups[2].Value
        $uToken = if ($u -match '^(?i)USER_\d+$') { $u } else { Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'USER' -Key $u }
        $dToken = if ($d -match '^(?i)(?:DOMAIN|HOST)_\d+$') { $d } else { Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'DOMAIN' -Key $d }
        return ($uToken + '@' + $dToken)
    })

    # 7. Replace DOMAIN\user and .\user patterns dynamically while preserving Windows built-in principals and paths
    $result = [regex]::Replace($result, $patterns.DomUserPattern, {
        param($match)
        $dom = $match.Groups[1].Value
        $usr = $match.Groups[2].Value

        if (Test-ShouldSkipDomainUserMatch -FullText $result -MatchIndex $match.Index -MatchLength $match.Length -Domain $dom -User $usr -Context $Context) {
            return $match.Value
        }

        $dToken = if ($dom -eq '.' -or $dom -match '^(?i)(?:DOMAIN|HOST)_\d+$') {
            $dom
        }
        else {
            Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'DOMAIN' -Key $dom
        }
        $uToken = if ($usr -match '^(?i)USER_\d+$') {
            $usr
        }
        else {
            Get-OrCreateToken -Map $Context.LiteralMap -Counters $Context.Counters -Category 'USER' -Key $usr
        }
        return ($dToken + '\' + $uToken)
    })

    # Re-apply any newly learned literal values across the current text so bare references match too
    if ($Context.LiteralMap.Count -gt $initialKeyCount) {
        $allKeys = $Context.LiteralMap.Keys | Sort-Object -Property Length -Descending
        foreach ($key in $allKeys) {
            if ($key.Length -lt 2) { continue }
            $token = $Context.LiteralMap[$key]
            $escaped = [regex]::Escape($key)
            $result = [regex]::Replace($result, $escaped, $token, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }

    return $result
}

function Get-SafePropertyValue {
    <#
    .SYNOPSIS
        Safely reads a property or dictionary key without triggering Set-StrictMode errors.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) {
            return $InputObject[$Name]
        }
        return $Default
    }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $prop) {
        return $prop.Value
    }
    return $Default
}

function Get-DiagnosticFlags {
    <#
    .SYNOPSIS
        Evaluates collected diagnostic metrics against issue thresholds and returns warning strings.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        $Metrics
    )

    $flags = New-Object 'System.Collections.Generic.List[string]'

    # Flag 1: Disk free < 15%
    $disks = Get-SafePropertyValue -InputObject $Metrics -Name 'Disks'
    if ($null -ne $disks) {
        foreach ($disk in $disks) {
            $freePct = Get-SafePropertyValue -InputObject $disk -Name 'FreePercent'
            $devId = Get-SafePropertyValue -InputObject $disk -Name 'DeviceID' -Default 'Unknown'
            if ($null -ne $freePct -and [double]$freePct -lt 15.0) {
                $flags.Add(('Low disk space on {0}: {1:N1}% free (threshold: < 15%)' -f $devId, [double]$freePct))
            }
        }
    }

    # Flag 2: Defender signature age > 3 days
    $sigAge = Get-SafePropertyValue -InputObject $Metrics -Name 'DefenderSignatureAgeDays'
    if ($null -ne $sigAge) {
        if ([double]$sigAge -gt 3.0) {
            $flags.Add(('Windows Defender signatures are {0} days old (threshold: > 3 days)' -f $sigAge))
        }
    }

    # Flag 3: Pending reboot
    $pendingReboot = Get-SafePropertyValue -InputObject $Metrics -Name 'PendingReboot' -Default $false
    if ($pendingReboot -eq $true) {
        $flags.Add('System has a pending reboot')
    }

    # Flag 4: Stopped automatic-start services
    $stoppedServices = Get-SafePropertyValue -InputObject $Metrics -Name 'StoppedAutoServices'
    if ($null -ne $stoppedServices) {
        $stopped = @($stoppedServices)
        if ($stopped.Count -gt 0) {
            $preview = ($stopped | Select-Object -First 5) -join ', '
            if ($stopped.Count -gt 5) {
                $preview = "$preview, ... (+$($stopped.Count - 5) more)"
            }
            $flags.Add(('{0} automatic-start service(s) are stopped: {1}' -f $stopped.Count, $preview))
        }
    }

    # Flag 5: > 50 errors/critical events from one source in last 7 days
    $eventSourceCounts = Get-SafePropertyValue -InputObject $Metrics -Name 'EventSourceCounts'
    if ($null -ne $eventSourceCounts) {
        foreach ($item in $eventSourceCounts) {
            $count = Get-SafePropertyValue -InputObject $item -Name 'Count'
            $source = Get-SafePropertyValue -InputObject $item -Name 'Source' -Default '(Unknown)'
            if ($null -ne $count -and [int]$count -gt 50) {
                $flags.Add(('High error volume from "{0}": {1} events in the last 7 days (threshold: > 50)' -f $source, $count))
            }
        }
    }

    return $flags.ToArray()
}

function Invoke-DiagnosticSection {
    <#
    .SYNOPSIS
        Executes a single diagnostic section inside try/catch, optionally redacts output, and writes its file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        [string]$FolderPath,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [switch]$Redact,

        [System.Collections.IDictionary]$RedactionContext,

        [switch]$DeferWrite
    )

    $filePath = Join-Path -Path $FolderPath -ChildPath $FileName
    $status = 'OK'
    $summary = ''
    $content = ''
    $metrics = @{}

    try {
        $result = & $ScriptBlock
        if ($null -eq $result) {
            throw "Section '$Name' returned no result."
        }

        $resStatus = Get-SafePropertyValue -InputObject $result -Name 'Status'
        if (-not [string]::IsNullOrWhiteSpace($resStatus)) {
            $status = [string]$resStatus
        }
        $resSummary = Get-SafePropertyValue -InputObject $result -Name 'Summary'
        if ($null -ne $resSummary) {
            $summary = [string]$resSummary
        }
        $resContent = Get-SafePropertyValue -InputObject $result -Name 'Content'
        if ($null -ne $resContent) {
            $content = [string]$resContent
        }
        $resMetrics = Get-SafePropertyValue -InputObject $result -Name 'Metrics'
        if ($null -ne $resMetrics) {
            $metrics = $resMetrics
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if (Test-IsAccessDeniedException -ErrorRecord $_) {
            $status = 'SKIPPED'
            $summary = 'SKIPPED: requires admin'
            $content = "SKIPPED: requires admin ($errMsg)"
        }
        else {
            $status = 'ERROR'
            $summary = "Failed: $errMsg"
            $content = "ERROR: Section '$Name' failed.`r`nMessage: $errMsg"
        }
    }

    if (-not $DeferWrite) {
        if ($Redact -and $null -ne $RedactionContext) {
            $content = Protect-RedactedText -Text $content -Context $RedactionContext
            $summary = Protect-RedactedText -Text $summary -Context $RedactionContext
        }

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($filePath, $content, $utf8NoBom)
    }

    return [pscustomobject]@{
        Name     = $Name
        FileName = $FileName
        FilePath = $filePath
        Status   = $status
        Summary  = $summary
        Content  = $content
        Metrics  = $metrics
    }
}

function Write-DiagnosticSections {
    <#
    .SYNOPSIS
        Pass 2 output writer: discovers accounts across all collected sections when -Redact is set,
        then applies redaction and writes each section file to disk.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Sections,

        [switch]$Redact,

        [System.Collections.IDictionary]$RedactionContext
    )

    if ($Redact -and $null -ne $RedactionContext) {
        $allTexts = New-Object 'System.Collections.Generic.List[string]'
        foreach ($sec in $Sections) {
            if (-not [string]::IsNullOrEmpty($sec.Content)) {
                $allTexts.Add([string]$sec.Content)
            }
            if (-not [string]::IsNullOrEmpty($sec.Summary)) {
                $allTexts.Add([string]$sec.Summary)
            }
        }
        Update-RedactionContextFromTexts -Texts $allTexts.ToArray() -Context $RedactionContext
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $finalSections = New-Object 'System.Collections.Generic.List[object]'

    foreach ($sec in $Sections) {
        $content = [string]$sec.Content
        $summary = [string]$sec.Summary

        if ($Redact -and $null -ne $RedactionContext) {
            $content = Protect-RedactedText -Text $content -Context $RedactionContext
            $summary = Protect-RedactedText -Text $summary -Context $RedactionContext
        }

        [System.IO.File]::WriteAllText($sec.FilePath, $content, $utf8NoBom)

        $finalSections.Add([pscustomobject]@{
            Name     = $sec.Name
            FileName = $sec.FileName
            FilePath = $sec.FilePath
            Status   = $sec.Status
            Summary  = $summary
            Content  = $content
            Metrics  = $sec.Metrics
        })
    }

    return $finalSections.ToArray()
}

function Get-SectionOS {
    [CmdletBinding()]
    param()

    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue

    $displayVersion = ''
    $ubr = ''
    $regBuild = ''
    $regProductName = ''
    $regInstallEpoch = $null
    if ($null -ne $cv) {
        if ($cv.PSObject.Properties['DisplayVersion'] -and $cv.DisplayVersion) {
            $displayVersion = [string]$cv.DisplayVersion
        }
        elseif ($cv.PSObject.Properties['ReleaseId'] -and $cv.ReleaseId) {
            $displayVersion = [string]$cv.ReleaseId
        }
        if ($cv.PSObject.Properties['UBR'] -and $null -ne $cv.UBR) {
            $ubr = [string]$cv.UBR
        }
        if ($cv.PSObject.Properties['CurrentBuildNumber'] -and $cv.CurrentBuildNumber) {
            $regBuild = [string]$cv.CurrentBuildNumber
        }
        if ($cv.PSObject.Properties['ProductName'] -and $cv.ProductName) {
            $regProductName = [string]$cv.ProductName
        }
        if ($cv.PSObject.Properties['InstallDate'] -and $null -ne $cv.InstallDate) {
            $regInstallEpoch = $cv.InstallDate
        }
    }

    $caption = ''
    $version = ''
    $buildNumber = ''
    $arch = ''
    $csName = ''
    $installDateStr = ''
    $lastBootStr = ''
    $uptime = $null

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = [string]$os.Caption
        $version = [string]$os.Version
        $buildNumber = [string]$os.BuildNumber
        $arch = [string]$os.OSArchitecture
        $csName = [string]$os.CSName
        $installDateStr = [string]$os.InstallDate
        $lastBoot = $os.LastBootUpTime
        $lastBootStr = $lastBoot.ToString('yyyy-MM-dd HH:mm:ss')
        $uptime = (Get-Date) - $lastBoot
    }
    catch {
        # Fallback to Registry + .NET when CIM/WMI is unavailable
        $buildNumber = if ($regBuild) { $regBuild } else { [string][Environment]::OSVersion.Version.Build }
        $caption = if ($regProductName) { $regProductName } else { 'Microsoft Windows' }
        $buildInt = 0
        if ([int]::TryParse($buildNumber, [ref]$buildInt) -and $buildInt -ge 22000 -and $caption -like 'Windows 10*') {
            $caption = $caption -replace '^Windows 10', 'Windows 11'
        }
        $version = '10.0.{0}' -f $buildNumber
        $arch = if ([Environment]::Is64BitOperatingSystem) { '64-bit' } else { '32-bit' }
        $csName = [Environment]::MachineName
        if ($null -ne $regInstallEpoch) {
            try {
                $installDateStr = [DateTimeOffset]::FromUnixTimeSeconds([int64]$regInstallEpoch).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
            catch {
                $installDateStr = 'Unavailable'
            }
        }
        else {
            $installDateStr = 'Unavailable'
        }
        $uptimeSeconds = [System.Diagnostics.Stopwatch]::GetTimestamp() / [System.Diagnostics.Stopwatch]::Frequency
        $uptime = [TimeSpan]::FromSeconds($uptimeSeconds)
        $lastBootStr = (Get-Date).Add(-$uptime).ToString('yyyy-MM-dd HH:mm:ss') + ' (approx)'
    }

    $fullBuild = if ($ubr) { "$buildNumber.$ubr" } else { "$buildNumber" }
    $uptimeText = '{0}d {1}h {2}m' -f [int][Math]::Floor($uptime.TotalDays), $uptime.Hours, $uptime.Minutes

    # Last 20 hotfixes (safe sorting when InstalledOn is null)
    $hotfixes = @()
    $hotfixNote = ''
    try {
        $hotfixes = @(
            Get-HotFix -ErrorAction Stop |
                Sort-Object -Property @{
                    Expression = {
                        try {
                            if ($_.InstalledOn) { [datetime]$_.InstalledOn } else { [datetime]::MinValue }
                        }
                        catch {
                            [datetime]::MinValue
                        }
                    }
                    Descending = $true
                } |
                Select-Object -First 20 -Property HotFixID, Description, InstalledBy, InstalledOn
        )
    }
    catch {
        $hotfixNote = "Unable to enumerate hotfixes: $($_.Exception.Message)"
    }

    # Pending reboot detection (strictly read-only)
    $rebootReasons = New-Object 'System.Collections.Generic.List[string]'
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $rebootReasons.Add('CBS RebootPending key exists')
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress') {
        $rebootReasons.Add('CBS RebootInProgress key exists')
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $rebootReasons.Add('Windows Update RebootRequired key exists')
    }
    try {
        $sm = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($null -ne $sm -and $null -ne $sm.PendingFileRenameOperations -and @($sm.PendingFileRenameOperations).Count -gt 0) {
            $rebootReasons.Add('Session Manager PendingFileRenameOperations non-empty')
        }
    }
    catch {
        # Ignore read errors on optional property
    }

    $pendingReboot = ($rebootReasons.Count -gt 0)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== OPERATING SYSTEM ===')
    [void]$sb.AppendLine(('Edition       : {0}' -f $caption))
    [void]$sb.AppendLine(('Version       : {0}' -f $version))
    [void]$sb.AppendLine(('DisplayVersion: {0}' -f $(if ($displayVersion) { $displayVersion } else { 'N/A' })))
    [void]$sb.AppendLine(('Build         : {0}' -f $fullBuild))
    [void]$sb.AppendLine(('Architecture  : {0}' -f $arch))
    [void]$sb.AppendLine(('Computer Name : {0}' -f $csName))
    [void]$sb.AppendLine(('Install Date  : {0}' -f $installDateStr))
    [void]$sb.AppendLine(('Last Boot     : {0}' -f $lastBootStr))
    [void]$sb.AppendLine(('Uptime        : {0}' -f $uptimeText))
    [void]$sb.AppendLine(('Pending Reboot: {0}' -f $pendingReboot))
    if ($pendingReboot) {
        [void]$sb.AppendLine(('Reboot Reasons: {0}' -f ($rebootReasons -join '; ')))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== LAST 20 HOTFIXES ===')
    if ($hotfixNote) {
        [void]$sb.AppendLine($hotfixNote)
    }
    elseif ($hotfixes.Count -eq 0) {
        [void]$sb.AppendLine('No hotfixes reported.')
    }
    else {
        $tableText = ($hotfixes | Format-Table -AutoSize | Out-String -Width 200).TrimEnd()
        [void]$sb.AppendLine($tableText)
    }

    $status = if ($pendingReboot) { 'WARN' } else { 'OK' }
    $summary = '{0} (Build {1}), Uptime {2}, PendingReboot: {3}' -f $caption, $fullBuild, $uptimeText, $pendingReboot

    return @{
        Status  = $status
        Summary = $summary
        Content = $sb.ToString()
        Metrics = @{
            PendingReboot = $pendingReboot
        }
    }
}

function Get-SectionHardware {
    [CmdletBinding()]
    param(
        [bool]$IsAdmin
    )

    $cpus = @()
    try {
        $cpus = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    }
    catch {
        $cpuReg = Get-ItemProperty -LiteralPath 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction SilentlyContinue
        $cpuNameReg = if ($cpuReg -and $cpuReg.PSObject.Properties['ProcessorNameString']) { [string]$cpuReg.ProcessorNameString } else { 'Unknown CPU' }
        $cpuMhzReg = if ($cpuReg -and $cpuReg.PSObject.Properties['~MHz']) { $cpuReg.'~MHz' } else { 'N/A' }
        $cpus = @(
            [pscustomobject]@{
                Name                      = $cpuNameReg
                NumberOfCores             = 'N/A (CIM unavailable)'
                NumberOfLogicalProcessors = [Environment]::ProcessorCount
                MaxClockSpeed             = $cpuMhzReg
                LoadPercentage            = 'N/A'
            }
        )
    }

    $totalRamGB = 0.0
    $freeRamGB = 0.0
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $totalRamGB = [Math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
        $freeRamGB = [Math]::Round((($os.FreePhysicalMemory * 1KB) / 1GB), 2)
    }
    catch {
        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        $ci = New-Object Microsoft.VisualBasic.Devices.ComputerInfo
        $totalRamGB = [Math]::Round(($ci.TotalPhysicalMemory / 1GB), 2)
        $freeRamGB = [Math]::Round(($ci.AvailablePhysicalMemory / 1GB), 2)
    }
    $usedRamGB = [Math]::Round(($totalRamGB - $freeRamGB), 2)
    $usedRamPct = if ($totalRamGB -gt 0) { [Math]::Round((($usedRamGB / $totalRamGB) * 100), 1) } else { 0.0 }

    $diskList = New-Object 'System.Collections.Generic.List[object]'
    try {
        $logicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
        foreach ($d in $logicalDisks) {
            $sizeGB = if ($d.Size) { [Math]::Round(($d.Size / 1GB), 2) } else { 0.0 }
            $freeGB = if ($d.FreeSpace) { [Math]::Round(($d.FreeSpace / 1GB), 2) } else { 0.0 }
            $freePct = if ($d.Size -and $d.Size -gt 0) { [Math]::Round((($d.FreeSpace / $d.Size) * 100), 1) } else { 0.0 }
            $diskList.Add([pscustomobject]@{
                DeviceID    = $d.DeviceID
                Label       = $d.VolumeName
                FileSystem  = $d.FileSystem
                SizeGB      = $sizeGB
                FreeGB      = $freeGB
                FreePercent = $freePct
            })
        }
    }
    catch {
        $drives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.IsReady })
        foreach ($drv in $drives) {
            $sizeGB = if ($drv.TotalSize -gt 0) { [Math]::Round(($drv.TotalSize / 1GB), 2) } else { 0.0 }
            $freeGB = if ($drv.AvailableFreeSpace -ge 0) { [Math]::Round(($drv.AvailableFreeSpace / 1GB), 2) } else { 0.0 }
            $freePct = if ($drv.TotalSize -gt 0) { [Math]::Round((($drv.AvailableFreeSpace / $drv.TotalSize) * 100), 1) } else { 0.0 }
            $diskList.Add([pscustomobject]@{
                DeviceID    = $drv.Name.TrimEnd('\')
                Label       = $drv.VolumeLabel
                FileSystem  = $drv.DriveFormat
                SizeGB      = $sizeGB
                FreeGB      = $freeGB
                FreePercent = $freePct
            })
        }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== CPU ===')
    foreach ($cpu in $cpus) {
        [void]$sb.AppendLine(('Name              : {0}' -f $cpu.Name))
        [void]$sb.AppendLine(('Cores / Logical   : {0} / {1}' -f $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors))
        [void]$sb.AppendLine(('Max Clock (MHz)   : {0}' -f $cpu.MaxClockSpeed))
        [void]$sb.AppendLine(('Current Load (%)  : {0}' -f $cpu.LoadPercentage))
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('=== MEMORY (RAM) ===')
    [void]$sb.AppendLine(('Total (GB)        : {0}' -f $totalRamGB))
    [void]$sb.AppendLine(('Used (GB)         : {0} ({1}%)' -f $usedRamGB, $usedRamPct))
    [void]$sb.AppendLine(('Free (GB)         : {0}' -f $freeRamGB))
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('=== LOGICAL DISKS (FIXED) ===')
    if ($diskList.Count -eq 0) {
        [void]$sb.AppendLine('No fixed logical disks found.')
    }
    else {
        [void]$sb.AppendLine(($diskList | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    }
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('=== PHYSICAL DISK HEALTH / SMART ===')
    $physicalDisksOK = $false
    try {
        $physDisks = @(Get-PhysicalDisk -ErrorAction Stop | Select-Object DeviceId, FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, @{ Name = 'SizeGB'; Expression = { [Math]::Round(($_.Size / 1GB), 2) } })
        if ($physDisks.Count -gt 0) {
            [void]$sb.AppendLine(($physDisks | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
            $physicalDisksOK = $true
        }
        else {
            [void]$sb.AppendLine('No physical disks returned by Get-PhysicalDisk.')
        }
    }
    catch {
        if (Test-IsAccessDeniedException -ErrorRecord $_) {
            [void]$sb.AppendLine('PhysicalDisk Health: SKIPPED: requires admin')
        }
        else {
            [void]$sb.AppendLine(('PhysicalDisk Health unavailable: {0}' -f $_.Exception.Message))
        }
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== SMART / STORAGE RELIABILITY COUNTERS ===')
    if (-not $IsAdmin) {
        [void]$sb.AppendLine('SKIPPED: requires admin')
    }
    else {
        $smartFound = $false
        if ($physicalDisksOK) {
            try {
                $relCounters = @(
                    Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
                        $pd = $_
                        try {
                            $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
                            [pscustomobject]@{
                                Disk                 = $pd.FriendlyName
                                TemperatureC         = $rc.Temperature
                                Wear                 = $rc.Wear
                                ReadErrorsTotal      = $rc.ReadErrorsTotal
                                WriteErrorsTotal     = $rc.WriteErrorsTotal
                                PowerOnHours         = $rc.PowerOnHours
                            }
                        }
                        catch {
                            [pscustomobject]@{
                                Disk                 = $pd.FriendlyName
                                TemperatureC         = $null
                                Wear                 = $null
                                ReadErrorsTotal      = $null
                                WriteErrorsTotal     = $null
                                PowerOnHours         = "Unavailable ($($_.Exception.Message))"
                            }
                        }
                    }
                )
                if ($relCounters.Count -gt 0) {
                    [void]$sb.AppendLine(($relCounters | Format-Table -AutoSize | Out-String -Width 220).TrimEnd())
                    $smartFound = $true
                }
            }
            catch {
                [void]$sb.AppendLine(('StorageReliabilityCounter unavailable: {0}' -f $_.Exception.Message))
            }
        }

        try {
            $wmiSmart = @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSStorageDriver_FailurePredictStatus' -ErrorAction Stop | Select-Object InstanceName, PredictFailure, Reason)
            if ($wmiSmart.Count -gt 0) {
                [void]$sb.AppendLine(($wmiSmart | Format-Table -AutoSize | Out-String -Width 220).TrimEnd())
                $smartFound = $true
            }
        }
        catch {
            if (-not $smartFound) {
                [void]$sb.AppendLine('WMI SMART (MSStorageDriver_FailurePredictStatus) not supported by storage controller.')
            }
        }
    }

    $lowDisk = $diskList | Where-Object { $_.FreePercent -lt 15.0 }
    $status = if (@($lowDisk).Count -gt 0) { 'WARN' } else { 'OK' }
    $cpuName = if ($cpus.Count -gt 0) { $cpus[0].Name.Trim() } else { 'Unknown CPU' }
    $diskSummary = ($diskList | ForEach-Object { '{0} {1}% free' -f $_.DeviceID, $_.FreePercent }) -join ', '
    $summary = '{0}; RAM {1}/{2} GB ({3}% used); Disks: {4}' -f $cpuName, $usedRamGB, $totalRamGB, $usedRamPct, $diskSummary

    return @{
        Status  = $status
        Summary = $summary
        Content = $sb.ToString()
        Metrics = @{
            Disks = $diskList.ToArray()
        }
    }
}

function Get-SectionEventLogs {
    [CmdletBinding()]
    param()

    $startTime = (Get-Date).AddDays(-7)
    $events = @()

    try {
        $events = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = @('System', 'Application')
                Level     = @(1, 2)
                StartTime = $startTime
            } -ErrorAction Stop
        )
    }
    catch {
        $fqid = $_.FullyQualifiedErrorId
        $msg = $_.Exception.Message
        if ($fqid -like 'NoMatchingEventsFound*' -or $msg -match '(?i)No events were found') {
            $events = @()
        }
        else {
            throw
        }
    }

    # Aggregate total count per provider for >50 threshold check
    $sourceCounts = @(
        $events |
            Group-Object -Property ProviderName |
            Sort-Object -Property Count -Descending |
            ForEach-Object {
                [pscustomobject]@{
                    Source = if ($_.Name) { $_.Name } else { '(Unknown)' }
                    Count  = $_.Count
                }
            }
    )

    # Top 25 by (LogName, ProviderName, Id)
    $top25 = @(
        $events |
            Group-Object -Property LogName, ProviderName, Id |
            Sort-Object -Property Count -Descending |
            Select-Object -First 25 |
            ForEach-Object {
                $sample = $_.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1
                $rawMsg = if ($sample -and $sample.Message) { [string]$sample.Message } else { '' }
                $cleanMsg = ($rawMsg -replace '[\r\n\t]+', ' ').Trim()
                if ($cleanMsg.Length -gt 240) {
                    $cleanMsg = $cleanMsg.Substring(0, 240) + '...'
                }
                $levelText = if ($sample -and $sample.LevelDisplayName) { $sample.LevelDisplayName } elseif ($sample.Level -eq 1) { 'Critical' } else { 'Error' }
                $latestTime = if ($sample -and $sample.TimeCreated) { $sample.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }

                [pscustomobject]@{
                    LogName       = $sample.LogName
                    ProviderName  = $sample.ProviderName
                    EventId       = $sample.Id
                    Level         = $levelText
                    Count         = $_.Count
                    LatestTime    = $latestTime
                    SampleMessage = $cleanMsg
                }
            }
    )

    if ($top25.Count -eq 0) {
        $csvContent = '"LogName","ProviderName","EventId","Level","Count","LatestTime","SampleMessage"'
    }
    else {
        $csvContent = ($top25 | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    }

    $highSources = @($sourceCounts | Where-Object { $_.Count -gt 50 })
    $status = if ($highSources.Count -gt 0) { 'WARN' } else { 'OK' }
    $summary = '{0} Error/Critical events in last 7 days across {1} source(s)' -f $events.Count, $sourceCounts.Count

    return @{
        Status  = $status
        Summary = $summary
        Content = $csvContent
        Metrics = @{
            EventSourceCounts = $sourceCounts
            TotalEvents       = $events.Count
        }
    }
}

function Get-SectionNetwork {
    [CmdletBinding()]
    param()

    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('=== NETWORK ADAPTERS ===')
    $adaptersUsedFallback = $false
    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress)
        if ($adapters.Count -eq 0) {
            [void]$sb.AppendLine('No network adapters returned.')
        }
        else {
            [void]$sb.AppendLine(($adapters | Format-Table -AutoSize | Out-String -Width 220).TrimEnd())
        }
    }
    catch {
        $adaptersUsedFallback = $true
        [void]$sb.AppendLine(('Get-NetAdapter unavailable ({0}); falling back to CIM.' -f $_.Exception.Message))
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== IP / GATEWAY / DNS CONFIGURATION ===')
    if (-not $adaptersUsedFallback) {
        try {
            $ipConfigs = @(
                Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
                    $ipv4 = ($_.IPv4Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', '
                    $ipv6 = ($_.IPv6Address | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', '
                    $gw = ($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', '
                    $dns = ($_.DNSServer | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses -join ', ' }) -join '; '
                    [pscustomobject]@{
                        Interface      = $_.InterfaceAlias
                        Description    = $_.InterfaceDescription
                        IPv4           = $ipv4
                        IPv6           = $ipv6
                        DefaultGateway = $gw
                        DNSServers     = $dns
                    }
                }
            )
            if ($ipConfigs.Count -eq 0) {
                [void]$sb.AppendLine('No IP configurations returned.')
            }
            else {
                [void]$sb.AppendLine(($ipConfigs | Format-List | Out-String -Width 220).TrimEnd())
            }
        }
        catch {
            $adaptersUsedFallback = $true
            [void]$sb.AppendLine(('Get-NetIPConfiguration unavailable ({0}); falling back to CIM.' -f $_.Exception.Message))
        }
    }

    if ($adaptersUsedFallback) {
        try {
            $cimNics = @(
                Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{
                        Description    = $_.Description
                        MACAddress     = $_.MACAddress
                        IPAddresses    = ($_.IPAddress -join ', ')
                        DefaultGateway = ($_.DefaultIPGateway -join ', ')
                        DNSServers     = ($_.DNSServerSearchOrder -join ', ')
                    }
                }
            )
            [void]$sb.AppendLine(($cimNics | Format-List | Out-String -Width 220).TrimEnd())
        }
        catch {
            $netNics = @(
                [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | ForEach-Object {
                    $ipProps = $_.GetIPProperties()
                    $macBytes = $_.GetPhysicalAddress().GetAddressBytes()
                    $macStr = if ($macBytes -and $macBytes.Length -gt 0) { ($macBytes | ForEach-Object { $_.ToString('X2') }) -join '-' } else { '' }
                    $ipv4 = ($ipProps.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | ForEach-Object { "$($_.Address.ToString())/$($_.PrefixLength)" }) -join ', '
                    $ipv6 = ($ipProps.UnicastAddresses | Where-Object { $_.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 } | ForEach-Object { "$($_.Address.ToString())/$($_.PrefixLength)" }) -join ', '
                    $gw = ($ipProps.GatewayAddresses | ForEach-Object { $_.Address.ToString() }) -join ', '
                    $dns = ($ipProps.DnsAddresses | ForEach-Object { $_.ToString() }) -join ', '
                    [pscustomobject]@{
                        Name           = $_.Name
                        Description    = $_.Description
                        Status         = [string]$_.OperationalStatus
                        SpeedMbps      = if ($_.Speed -gt 0) { [Math]::Round(($_.Speed / 1000000), 0) } else { 0 }
                        MACAddress     = $macStr
                        IPv4           = $ipv4
                        IPv6           = $ipv6
                        DefaultGateway = $gw
                        DNSServers     = $dns
                    }
                }
            )
            [void]$sb.AppendLine(($netNics | Format-List | Out-String -Width 220).TrimEnd())
        }
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== CONNECTIVITY TESTS (ONLY OUTBOUND CHECKS) ===')

    # Ping 8.8.8.8
    $pingSummary = 'Failed'
    try {
        $pingSender = New-Object System.Net.NetworkInformation.Ping
        try {
            $results = @()
            for ($i = 1; $i -le 2; $i++) {
                $reply = $pingSender.Send('8.8.8.8', 2000)
                $results += $reply
                [void]$sb.AppendLine(('Ping 8.8.8.8 #{0}  : Status={1}, RoundtripMs={2}' -f $i, $reply.Status, $reply.RoundtripTime))
            }
            $successCount = @($results | Where-Object { $_.Status -eq [System.Net.NetworkInformation.IPStatus]::Success }).Count
            $pingSummary = '{0}/2 succeeded' -f $successCount
        }
        finally {
            $pingSender.Dispose()
        }
    }
    catch {
        $pingErr = $_.Exception.Message
        if ($_.Exception.InnerException) {
            $pingErr = "$pingErr ($($_.Exception.InnerException.Message))"
        }
        $pingSummary = "Failed ($pingErr)"
        [void]$sb.AppendLine(('Ping 8.8.8.8     : {0}' -f $pingSummary))
    }

    # DNS resolve test
    $dnsSummary = 'Failed'
    try {
        $dnsResult = @(
            Resolve-DnsName -Name 'dns.google' -Type A -ErrorAction Stop | Where-Object {
                $_.PSObject.Properties['QueryType'] -and $_.QueryType -eq 'A' -and $_.PSObject.Properties['IPAddress']
            }
        )
        if ($dnsResult.Count -gt 0) {
            $ips = ($dnsResult | ForEach-Object { $_.IPAddress }) -join ', '
            $dnsSummary = "Resolved dns.google -> $ips"
            [void]$sb.AppendLine(('DNS Resolve Test : {0}' -f $dnsSummary))
        }
        else {
            $dnsSummary = 'No A records returned for dns.google'
            [void]$sb.AppendLine(('DNS Resolve Test : {0}' -f $dnsSummary))
        }
    }
    catch {
        $dnsSummary = "Failed ($($_.Exception.Message))"
        [void]$sb.AppendLine(('DNS Resolve Test : {0}' -f $dnsSummary))
    }

    $status = if ($pingSummary -like '0/2*' -or $pingSummary -like 'Failed*' -or $dnsSummary -like 'Failed*') { 'WARN' } else { 'OK' }
    $summary = 'Ping 8.8.8.8: {0}; DNS: {1}' -f $pingSummary, $dnsSummary

    return @{
        Status  = $status
        Summary = $summary
        Content = $sb.ToString()
        Metrics = @{}
    }
}

function Get-SectionServices {
    [CmdletBinding()]
    param()

    $stoppedAuto = @()
    try {
        $stoppedAuto = @(
            Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State!='Running'" -ErrorAction Stop |
                Sort-Object -Property DisplayName |
                Select-Object Name, DisplayName, State, StartMode, DelayedAutoStart, StartName, ExitCode
        )
    }
    catch {
        $stoppedAuto = @(
            Get-Service -ErrorAction Stop |
                Where-Object {
                    if ($_.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                        return $false
                    }
                    if ($_.PSObject.Properties['StartType']) {
                        return ($_.StartType -eq 'Automatic')
                    }
                    $svcReg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $_.ServiceName) -ErrorAction SilentlyContinue
                    return ($null -ne $svcReg -and $svcReg.PSObject.Properties['Start'] -and [int]$svcReg.Start -eq 2)
                } |
                Sort-Object -Property DisplayName |
                ForEach-Object {
                    $svcReg = Get-ItemProperty -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\{0}" -f $_.ServiceName) -ErrorAction SilentlyContinue
                    $delayed = $false
                    $startName = ''
                    if ($null -ne $svcReg) {
                        if ($svcReg.PSObject.Properties['DelayedAutostart'] -and [int]$svcReg.DelayedAutostart -eq 1) {
                            $delayed = $true
                        }
                        if ($svcReg.PSObject.Properties['ObjectName'] -and $svcReg.ObjectName) {
                            $startName = [string]$svcReg.ObjectName
                        }
                    }
                    [pscustomobject]@{
                        Name             = $_.ServiceName
                        DisplayName      = $_.DisplayName
                        State            = [string]$_.Status
                        StartMode        = 'Auto'
                        DelayedAutoStart = $delayed
                        StartName        = $startName
                        ExitCode         = ''
                    }
                }
        )
    }

    if ($stoppedAuto.Count -eq 0) {
        $csvContent = '"Name","DisplayName","State","StartMode","DelayedAutoStart","StartName","ExitCode"'
    }
    else {
        $csvContent = ($stoppedAuto | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    }

    $serviceNames = @($stoppedAuto | ForEach-Object { $_.Name })
    $status = if ($stoppedAuto.Count -gt 0) { 'WARN' } else { 'OK' }
    $summary = '{0} automatic-start service(s) currently stopped' -f $stoppedAuto.Count

    return @{
        Status  = $status
        Summary = $summary
        Content = $csvContent
        Metrics = @{
            StoppedAutoServices = $serviceNames
        }
    }
}

function Get-SectionStartup {
    [CmdletBinding()]
    param()

    $sb = New-Object System.Text.StringBuilder
    $regIgnored = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')

    [void]$sb.AppendLine('=== REGISTRY RUN / RUNONCE KEYS ===')
    $runPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    $regItems = New-Object 'System.Collections.Generic.List[object]'
    foreach ($regPath in $runPaths) {
        if (Test-Path -LiteralPath $regPath) {
            try {
                $props = Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop
                foreach ($p in $props.PSObject.Properties) {
                    if ($regIgnored -notcontains $p.Name) {
                        $regItems.Add([pscustomobject]@{
                            HivePath = $regPath
                            Name     = $p.Name
                            Command  = [string]$p.Value
                        })
                    }
                }
            }
            catch {
                $regItems.Add([pscustomobject]@{
                    HivePath = $regPath
                    Name     = '(Error)'
                    Command  = $_.Exception.Message
                })
            }
        }
    }

    if ($regItems.Count -eq 0) {
        [void]$sb.AppendLine('No Run/RunOnce entries found.')
    }
    else {
        [void]$sb.AppendLine(($regItems | Format-List | Out-String -Width 220).TrimEnd())
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== STARTUP FOLDERS ===')
    $startupFolders = @(
        [pscustomobject]@{ Scope = 'CurrentUser'; Path = [Environment]::GetFolderPath('Startup') },
        [pscustomobject]@{ Scope = 'AllUsers'; Path = [Environment]::GetFolderPath('CommonStartup') }
    )

    $folderItems = New-Object 'System.Collections.Generic.List[object]'
    foreach ($sf in $startupFolders) {
        if (-not [string]::IsNullOrWhiteSpace($sf.Path) -and (Test-Path -LiteralPath $sf.Path)) {
            $files = @(Get-ChildItem -LiteralPath $sf.Path -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })
            foreach ($f in $files) {
                $folderItems.Add([pscustomobject]@{
                    Scope        = $sf.Scope
                    FileName     = $f.Name
                    FullPath     = $f.FullName
                    LastModified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                })
            }
        }
    }

    if ($folderItems.Count -eq 0) {
        [void]$sb.AppendLine('No Startup folder items found.')
    }
    else {
        [void]$sb.AppendLine(($folderItems | Format-Table -AutoSize | Out-String -Width 220).TrimEnd())
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== NON-MICROSOFT SCHEDULED TASKS ===')
    $taskItems = New-Object 'System.Collections.Generic.List[object]'
    try {
        $tasks = @(
            Get-ScheduledTask -ErrorAction Stop | Where-Object {
                $pathNotMs = ($_.TaskPath -notlike '\Microsoft\*')
                $author = if ($_.Author) { [string]$_.Author } else { '' }
                $authorNotMs = ($author -notlike '*Microsoft*')
                $pathNotMs -and $authorNotMs
            }
        )
        foreach ($t in $tasks) {
            $actionText = ($t.Actions | ForEach-Object {
                $execProp = $_.PSObject.Properties['Execute']
                $argsProp = $_.PSObject.Properties['Arguments']
                if ($null -ne $execProp -and -not [string]::IsNullOrWhiteSpace([string]$execProp.Value)) {
                    $argVal = if ($null -ne $argsProp) { [string]$argsProp.Value } else { '' }
                    ("$($execProp.Value) $argVal").Trim()
                }
                else {
                    $_.ToString()
                }
            }) -join '; '
            $runAsVal = ''
            $principalProp = $t.PSObject.Properties['Principal']
            if ($null -ne $principalProp -and $null -ne $principalProp.Value) {
                $uidProp = $principalProp.Value.PSObject.Properties['UserId']
                if ($null -ne $uidProp -and $uidProp.Value) {
                    $runAsVal = [string]$uidProp.Value
                }
            }
            $taskItems.Add([pscustomobject]@{
                TaskName = $t.TaskName
                TaskPath = $t.TaskPath
                State    = [string]$t.State
                Author   = $t.Author
                RunAs    = $runAsVal
                Action   = $actionText
            })
        }

        if ($taskItems.Count -eq 0) {
            [void]$sb.AppendLine('No non-Microsoft scheduled tasks found.')
        }
        else {
            [void]$sb.AppendLine(($taskItems | Format-List | Out-String -Width 220).TrimEnd())
        }
    }
    catch {
        $schtasksOk = $false
        $prevEap = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $csvLines = @(& schtasks.exe /Query /FO CSV /V 2>$null)
            if ($LASTEXITCODE -eq 0 -and $csvLines.Count -gt 1) {
                $parsedTasks = @($csvLines | ConvertFrom-Csv -ErrorAction Stop)
                $seenTasks = New-Object 'System.Collections.Generic.HashSet[string]'
                foreach ($pt in $parsedTasks) {
                    $tnProp = $pt.PSObject.Properties['TaskName']
                    $authorProp = $pt.PSObject.Properties['Author']
                    $runAsProp = $pt.PSObject.Properties['Run As User']
                    $statusProp = $pt.PSObject.Properties['Status']
                    $actionProp = $pt.PSObject.Properties['Task To Run']
                    if ($null -eq $tnProp -or [string]::IsNullOrWhiteSpace([string]$tnProp.Value)) {
                        continue
                    }
                    $fullTaskName = [string]$tnProp.Value
                    $authorVal = if ($null -ne $authorProp -and $authorProp.Value) { [string]$authorProp.Value } else { '' }
                    $runAsVal = if ($null -ne $runAsProp -and $runAsProp.Value) { [string]$runAsProp.Value } else { '' }
                    if ($fullTaskName -like '\Microsoft\*' -or $authorVal -like '*Microsoft*') {
                        continue
                    }
                    if ($seenTasks.Add($fullTaskName)) {
                        $leafName = Split-Path -Path $fullTaskName -Leaf
                        $folderPath = Split-Path -Path $fullTaskName -Parent
                        if (-not $folderPath) { $folderPath = '\' }
                        $taskItems.Add([pscustomobject]@{
                            TaskName = $leafName
                            TaskPath = $folderPath
                            State    = if ($null -ne $statusProp) { [string]$statusProp.Value } else { '' }
                            Author   = $authorVal
                            RunAs    = $runAsVal
                            Action   = if ($null -ne $actionProp) { [string]$actionProp.Value } else { '' }
                        })
                    }
                }
                $schtasksOk = $true
            }
        }
        catch {
            $schtasksOk = $false
        }
        finally {
            $ErrorActionPreference = $prevEap
        }

        if ($schtasksOk) {
            if ($taskItems.Count -eq 0) {
                [void]$sb.AppendLine('No non-Microsoft scheduled tasks found.')
            }
            else {
                [void]$sb.AppendLine(($taskItems | Format-List | Out-String -Width 220).TrimEnd())
            }
        }
        elseif (Test-IsAccessDeniedException -ErrorRecord $_) {
            [void]$sb.AppendLine('Scheduled Tasks: SKIPPED: requires admin')
        }
        else {
            [void]$sb.AppendLine(('Scheduled Tasks unavailable: {0}' -f $_.Exception.Message))
        }
    }

    $summary = '{0} Run entries, {1} Startup folder items, {2} non-Microsoft scheduled tasks' -f $regItems.Count, $folderItems.Count, $taskItems.Count

    return @{
        Status  = 'OK'
        Summary = $summary
        Content = $sb.ToString()
        Metrics = @{}
    }
}

function Get-SectionSecurity {
    [CmdletBinding()]
    param(
        [bool]$IsAdmin
    )

    $sb = New-Object System.Text.StringBuilder
    $sigAgeDays = $null
    $defenderText = 'Unknown'

    [void]$sb.AppendLine('=== WINDOWS DEFENDER ===')
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $sigAgeDays = $mp.AntivirusSignatureAge
        $defenderText = "RTP=$($mp.RealTimeProtectionEnabled), SigAge=${sigAgeDays}d"
        [void]$sb.AppendLine(('AntivirusEnabled              : {0}' -f $mp.AntivirusEnabled))
        [void]$sb.AppendLine(('AMServiceEnabled              : {0}' -f $mp.AMServiceEnabled))
        [void]$sb.AppendLine(('RealTimeProtectionEnabled     : {0}' -f $mp.RealTimeProtectionEnabled))
        [void]$sb.AppendLine(('AntivirusSignatureVersion     : {0}' -f $mp.AntivirusSignatureVersion))
        [void]$sb.AppendLine(('AntivirusSignatureLastUpdated : {0}' -f $mp.AntivirusSignatureLastUpdated))
        [void]$sb.AppendLine(('AntivirusSignatureAge (days)  : {0}' -f $sigAgeDays))
    }
    catch {
        $defSigReg = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates' -ErrorAction SilentlyContinue
        $defRtpReg = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' -ErrorAction SilentlyContinue
        if ($null -ne $defSigReg) {
            $sigVer = if ($defSigReg.PSObject.Properties['AVSignatureVersion']) { [string]$defSigReg.AVSignatureVersion } else { 'Unknown' }
            $sigUpdatedStr = 'Unknown'
            if ($defSigReg.PSObject.Properties['SignaturesLastUpdated'] -and $defSigReg.SignaturesLastUpdated -is [byte[]] -and $defSigReg.SignaturesLastUpdated.Length -eq 8) {
                $ft = [BitConverter]::ToInt64($defSigReg.SignaturesLastUpdated, 0)
                if ($ft -gt 0) {
                    $sigDt = [datetime]::FromFileTimeUtc($ft).ToLocalTime()
                    $sigUpdatedStr = $sigDt.ToString('yyyy-MM-dd HH:mm:ss')
                    $sigAgeDays = [Math]::Max(0, [int][Math]::Floor(((Get-Date) - $sigDt).TotalDays))
                }
            }
            $rtpEnabled = 'Unknown'
            if ($null -ne $defRtpReg -and $defRtpReg.PSObject.Properties['DisableRealtimeMonitoring']) {
                $rtpEnabled = ([int]$defRtpReg.DisableRealtimeMonitoring -ne 1)
            }
            $ageDisplay = if ($null -ne $sigAgeDays) { "${sigAgeDays}d" } else { 'Unknown' }
            $defenderText = "RTP=$rtpEnabled, SigAge=$ageDisplay (Registry fallback)"
            [void]$sb.AppendLine(('Source                        : Registry fallback (Get-MpComputerStatus unavailable)'))
            [void]$sb.AppendLine(('RealTimeProtectionEnabled     : {0}' -f $rtpEnabled))
            [void]$sb.AppendLine(('AntivirusSignatureVersion     : {0}' -f $sigVer))
            [void]$sb.AppendLine(('AntivirusSignatureLastUpdated : {0}' -f $sigUpdatedStr))
            [void]$sb.AppendLine(('AntivirusSignatureAge (days)  : {0}' -f $(if ($null -ne $sigAgeDays) { $sigAgeDays } else { 'Unknown' })))
        }
        elseif (Test-IsAccessDeniedException -ErrorRecord $_) {
            $defenderText = 'SKIPPED: requires admin'
            [void]$sb.AppendLine('SKIPPED: requires admin')
        }
        else {
            $defenderText = "Unavailable ($($_.Exception.Message))"
            [void]$sb.AppendLine(('Defender status unavailable: {0}' -f $_.Exception.Message))
        }
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== WINDOWS FIREWALL PROFILES ===')
    $fwSummary = 'Unknown'
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        if ($profiles.Count -eq 0) {
            $fwSummary = 'No profiles'
            [void]$sb.AppendLine('No firewall profiles returned.')
        }
        else {
            $fwSummary = ($profiles | ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }) -join ', '
            [void]$sb.AppendLine(($profiles | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
        }
    }
    catch {
        $fwRegBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
        $fwMap = @(
            @{ Name = 'Domain';  Key = 'DomainProfile' },
            @{ Name = 'Private'; Key = 'StandardProfile' },
            @{ Name = 'Public';  Key = 'PublicProfile' }
        )
        $regProfiles = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $fwMap) {
            $pKey = Join-Path -Path $fwRegBase -ChildPath $item.Key
            if (Test-Path -LiteralPath $pKey) {
                $props = Get-ItemProperty -LiteralPath $pKey -ErrorAction SilentlyContinue
                $enabledVal = if ($null -ne $props -and $props.PSObject.Properties['EnableFirewall']) { ([int]$props.EnableFirewall -eq 1) } else { 'Unknown' }
                $regProfiles.Add([pscustomobject]@{
                    Name    = $item.Name
                    Enabled = $enabledVal
                    Source  = 'Registry fallback'
                })
            }
        }
        if ($regProfiles.Count -gt 0) {
            $fwSummary = ($regProfiles | ForEach-Object { '{0}={1}' -f $_.Name, $_.Enabled }) -join ', '
            [void]$sb.AppendLine(($regProfiles | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
        }
        elseif (Test-IsAccessDeniedException -ErrorRecord $_) {
            $fwSummary = 'SKIPPED: requires admin'
            [void]$sb.AppendLine('SKIPPED: requires admin')
        }
        else {
            $fwSummary = 'Unavailable'
            [void]$sb.AppendLine(('Firewall status unavailable: {0}' -f $_.Exception.Message))
        }
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== BITLOCKER STATUS ===')
    $blSummary = 'SKIPPED: requires admin'
    if (-not $IsAdmin) {
        [void]$sb.AppendLine('SKIPPED: requires admin')
    }
    else {
        try {
            $volumes = @(
                Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{
                        MountPoint           = $_.MountPoint
                        VolumeStatus         = [string]$_.VolumeStatus
                        ProtectionStatus     = [string]$_.ProtectionStatus
                        EncryptionPercentage = $_.EncryptionPercentage
                        KeyProtectors        = ($_.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ', '
                    }
                }
            )
            if ($volumes.Count -eq 0) {
                $blSummary = 'No BitLocker volumes'
                [void]$sb.AppendLine('No BitLocker volumes found.')
            }
            else {
                $blSummary = ($volumes | ForEach-Object { '{0}:{1}' -f $_.MountPoint, $_.ProtectionStatus }) -join ', '
                [void]$sb.AppendLine(($volumes | Format-Table -AutoSize | Out-String -Width 220).TrimEnd())
            }
        }
        catch {
            $blSummary = "Unavailable ($($_.Exception.Message))"
            [void]$sb.AppendLine(('BitLocker status unavailable: {0}' -f $_.Exception.Message))
        }
    }

    $status = if ($null -ne $sigAgeDays -and [double]$sigAgeDays -gt 3.0) { 'WARN' } else { 'OK' }
    $summary = 'Defender: {0}; Firewall: {1}; BitLocker: {2}' -f $defenderText, $fwSummary, $blSummary

    return @{
        Status  = $status
        Summary = $summary
        Content = $sb.ToString()
        Metrics = @{
            DefenderSignatureAgeDays = $sigAgeDays
        }
    }
}

function Get-SectionProcesses {
    [CmdletBinding()]
    param()

    $procs = @(
        Get-Process -ErrorAction Stop | ForEach-Object {
            $cpuVal = 0.0
            try {
                if ($null -ne $_.CPU) {
                    $cpuVal = [Math]::Round([double]$_.CPU, 2)
                }
            }
            catch {
                $cpuVal = 0.0
            }
            [pscustomobject]@{
                Name     = $_.ProcessName
                Id       = $_.Id
                CPU      = $cpuVal
                MemoryMB = [Math]::Round(($_.WorkingSet64 / 1MB), 2)
            }
        }
    )

    $topCpu = @($procs | Sort-Object -Property CPU -Descending | Select-Object -First 10)
    $topRam = @($procs | Sort-Object -Property MemoryMB -Descending | Select-Object -First 10)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('=== TOP 10 PROCESSES BY CPU (SECONDS) ===')
    [void]$sb.AppendLine(($topCpu | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== TOP 10 PROCESSES BY RAM (WORKING SET MB) ===')
    [void]$sb.AppendLine(($topRam | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())

    $topCpuName = if ($topCpu.Count -gt 0) { "$($topCpu[0].Name) ($($topCpu[0].CPU)s)" } else { 'N/A' }
    $topRamName = if ($topRam.Count -gt 0) { "$($topRam[0].Name) ($($topRam[0].MemoryMB) MB)" } else { 'N/A' }
    $summary = 'Total processes: {0}; Top CPU: {1}; Top RAM: {2}' -f $procs.Count, $topCpuName, $topRamName

    return @{
        Status  = 'OK'
        Summary = $summary
        Content = $sb.ToString()
        Metrics = @{}
    }
}

function Invoke-DiagnosticsCollection {
    <#
    .SYNOPSIS
        Orchestrates all 8 diagnostic sections, writes summary.md, and creates the output zip archive.
    #>
    [CmdletBinding()]
    param(
        [switch]$Redact,
        [string]$OutputDirectory
    )

    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
            $OutputDirectory = $PSScriptRoot
        }
        else {
            $OutputDirectory = (Get-Location).Path
        }
    }

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        [void](New-Item -Path $OutputDirectory -ItemType Directory -Force)
    }

    $resolvedOutDir = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $timestamp = (Get-Date).ToString('yyyyMMdd_HHmm')
    $folderName = "Diag_$timestamp"
    $diagFolder = Join-Path -Path $resolvedOutDir -ChildPath $folderName
    $zipPath = Join-Path -Path $resolvedOutDir -ChildPath "$folderName.zip"

    if (Test-Path -LiteralPath $diagFolder) {
        Remove-Item -LiteralPath $diagFolder -Recurse -Force
    }
    [void](New-Item -Path $diagFolder -ItemType Directory -Force)

    $isAdmin = Test-IsAdministrator

    $redactionContext = $null
    if ($Redact) {
        $discovered = Get-DiscoveredRedactionAccounts
        $redactionContext = New-RedactionContext -AdditionalUsers $discovered.Users -AdditionalDomains $discovered.Domains
    }

    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    try {
        $sectionDefs = @(
            @{ Name = 'OS';         File = '01_os.txt';         Block = { Get-SectionOS } },
            @{ Name = 'Hardware';   File = '02_hardware.txt';   Block = { Get-SectionHardware -IsAdmin $isAdmin } },
            @{ Name = 'Event Logs'; File = '03_event_logs.csv'; Block = { Get-SectionEventLogs } },
            @{ Name = 'Network';    File = '04_network.txt';    Block = { Get-SectionNetwork } },
            @{ Name = 'Services';   File = '05_services.csv';   Block = { Get-SectionServices } },
            @{ Name = 'Startup';    File = '06_startup.txt';    Block = { Get-SectionStartup } },
            @{ Name = 'Security';   File = '07_security.txt';   Block = { Get-SectionSecurity -IsAdmin $isAdmin } },
            @{ Name = 'Processes';  File = '08_processes.txt';  Block = { Get-SectionProcesses } }
        )

        $collected = New-Object 'System.Collections.Generic.List[object]'
        $aggregatedMetrics = @{
            Disks                    = @()
            DefenderSignatureAgeDays = $null
            PendingReboot            = $false
            StoppedAutoServices      = @()
            EventSourceCounts        = @()
        }

        # Pass 1: Collect all sections into memory
        foreach ($def in $sectionDefs) {
            $secResult = Invoke-DiagnosticSection `
                -Name $def.Name `
                -FileName $def.File `
                -FolderPath $diagFolder `
                -ScriptBlock $def.Block `
                -DeferWrite

            $collected.Add($secResult)

            $m = $secResult.Metrics
            if ($null -ne $m) {
                if ($m.ContainsKey('Disks')) { $aggregatedMetrics.Disks = $m.Disks }
                if ($m.ContainsKey('DefenderSignatureAgeDays')) { $aggregatedMetrics.DefenderSignatureAgeDays = $m.DefenderSignatureAgeDays }
                if ($m.ContainsKey('PendingReboot')) { $aggregatedMetrics.PendingReboot = $m.PendingReboot }
                if ($m.ContainsKey('StoppedAutoServices')) { $aggregatedMetrics.StoppedAutoServices = $m.StoppedAutoServices }
                if ($m.ContainsKey('EventSourceCounts')) { $aggregatedMetrics.EventSourceCounts = $m.EventSourceCounts }
            }
        }

        # Pass 2: Build complete token map across all section outputs, then redact and write files
        $results = @(
            Write-DiagnosticSections `
                -Sections $collected.ToArray() `
                -Redact:$Redact `
                -RedactionContext $redactionContext
        )

        $flags = @(Get-DiagnosticFlags -Metrics $aggregatedMetrics)

        # Build summary.md
        $hostDisplay = if ($Redact -and $null -ne $redactionContext) {
            Protect-RedactedText -Text $env:COMPUTERNAME -Context $redactionContext
        }
        else {
            $env:COMPUTERNAME
        }

        $sum = New-Object System.Text.StringBuilder
        [void]$sum.AppendLine('# Windows Diagnostic Summary')
        [void]$sum.AppendLine('')
        [void]$sum.AppendLine(('- **Collected**: {0}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')))
        [void]$sum.AppendLine(('- **Host**: {0}' -f $hostDisplay))
        [void]$sum.AppendLine(('- **Elevation**: {0}' -f $(if ($isAdmin) { 'Administrator' } else { 'Standard User' })))
        [void]$sum.AppendLine(('- **Redacted**: {0}' -f [bool]$Redact))
        [void]$sum.AppendLine('')
        [void]$sum.AppendLine('## Section Status')
        [void]$sum.AppendLine('')
        [void]$sum.AppendLine('| Section | File | Status | Summary |')
        [void]$sum.AppendLine('| --- | --- | --- | --- |')
        foreach ($r in $results) {
            $cleanSum = ($r.Summary -replace '[\r\n|]+', ' ').Trim()
            [void]$sum.AppendLine(('| {0} | `{1}` | {2} | {3} |' -f $r.Name, $r.FileName, $r.Status, $cleanSum))
        }
        [void]$sum.AppendLine('')
        [void]$sum.AppendLine('## Flagged Issues')
        [void]$sum.AppendLine('')
        if ($flags.Count -eq 0) {
            [void]$sum.AppendLine('- None detected.')
        }
        else {
            foreach ($flag in $flags) {
                $flagLine = if ($Redact -and $null -ne $redactionContext) {
                    Protect-RedactedText -Text $flag -Context $redactionContext
                }
                else {
                    $flag
                }
                [void]$sum.AppendLine(('- {0}' -f $flagLine))
            }
        }

        $summaryText = $sum.ToString()
        if ($Redact -and $null -ne $redactionContext) {
            $summaryText = Protect-RedactedText -Text $summaryText -Context $redactionContext
        }

        $summaryPath = Join-Path -Path $diagFolder -ChildPath 'summary.md'
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($summaryPath, $summaryText, $utf8NoBom)

        if (Test-Path -LiteralPath $zipPath) {
            Remove-Item -LiteralPath $zipPath -Force
        }
        Compress-Archive -Path $diagFolder -DestinationPath $zipPath -Force

        return [pscustomobject]@{
            FolderPath  = $diagFolder
            SummaryPath = $summaryPath
            ZipPath     = $zipPath
            IsAdmin     = $isAdmin
            Redacted    = [bool]$Redact
            Sections    = @($results)
            Flags       = $flags
        }
    }
    finally {
        $ProgressPreference = $prevProgress
    }
}

# Only execute automatically when invoked directly (not when dot-sourced for tests)
if ($MyInvocation.InvocationName -ne '.') {
    Set-StrictMode -Version Latest
    $runResult = Invoke-DiagnosticsCollection -Redact:$Redact -OutputDirectory $OutputDirectory
    Write-Output ("Diagnostics archive created: {0}" -f $runResult.ZipPath)
}
