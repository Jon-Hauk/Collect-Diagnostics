$ProgressPreference = 'SilentlyContinue'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = Join-Path -Path $here -ChildPath 'Collect-Diagnostics.ps1'

# Dot-source script under test without triggering collection
. $sut

Describe 'Collect-Diagnostics - Redaction' {
    It 'replaces username, hostname, and domain with stable tokens case-insensitively' {
        $ctx = New-RedactionContext -UserName 'AliceSmith' -ComputerName 'WORKSTATION-99' -Domain 'ACMECORP' -DnsDomain 'acme.local'
        $sample = "Host: workstation-99 | User: ALICESMITH | Domain: AcMeCoRp\alicesmith | FQDN: workstation-99.acme.local"

        $redacted = Protect-RedactedText -Text $sample -Context $ctx

        $redacted | Should Not Match '(?i)AliceSmith'
        $redacted | Should Not Match '(?i)WORKSTATION-99'
        $redacted | Should Not Match '(?i)ACMECORP'
        $redacted | Should Not Match '(?i)acme\.local'
        $redacted | Should Match 'HOST_1'
        $redacted | Should Match 'USER_1'
        $redacted | Should Match 'DOMAIN_1'
        $redacted | Should Match 'DOMAIN_2'
    }

    It 'maps ComputerName to HOST_1 when Domain matches ComputerName on workgroup machines' {
        $ctx = New-RedactionContext -UserName 'jdoe' -ComputerName 'DESKTOP-XYZ' -Domain 'DESKTOP-XYZ' -DnsDomain ''
        $redacted = Protect-RedactedText -Text 'DESKTOP-XYZ\jdoe logged on DESKTOP-XYZ' -Context $ctx

        $redacted | Should Be 'HOST_1\USER_1 logged on HOST_1'
    }

    It 'replaces MAC addresses and private/link-local IPv4 addresses with stable incrementing tokens' {
        $ctx = New-RedactionContext -UserName 'bob' -ComputerName 'PC1' -Domain 'WORKGROUP'
        $text1 = 'NIC1 MAC aa-bb-cc-dd-ee-ff IP 192.168.1.50 GW 10.0.0.1 DNS 8.8.8.8'
        $text2 = 'NIC1 again AA:BB:CC:DD:EE:FF IP 192.168.1.50 NIC2 11:22:33:44:55:66 IP 172.16.5.20 LinkLocal 169.254.10.20 Loopback 127.0.0.1'

        $r1 = Protect-RedactedText -Text $text1 -Context $ctx
        $r2 = Protect-RedactedText -Text $text2 -Context $ctx

        $r1 | Should Be 'NIC1 MAC MAC_1 IP IP_1 GW IP_2 DNS 8.8.8.8'
        $r2 | Should Be 'NIC1 again MAC_1 IP IP_1 NIC2 MAC_2 IP IP_3 LinkLocal IP_4 Loopback 127.0.0.1'
    }

    It 'does not treat Windows OS build/version strings like 10.0.26100.9818 as private IPs' {
        $ctx = New-RedactionContext -UserName 'bob' -ComputerName 'PC1' -Domain 'WORKGROUP'
        $text = 'Windows Version 10.0.26100.9818 Build 26100, Private IP 10.0.26.100'

        $redacted = Protect-RedactedText -Text $text -Context $ctx

        $redacted | Should Match '10\.0\.26100\.9818'
        $redacted | Should Match 'Private IP IP_1'
    }

    It 'redacts C:\Users\<name> paths while preserving Public and Default system profiles' {
        $ctx = New-RedactionContext -UserName 'primaryuser' -ComputerName 'PC1' -Domain 'WORKGROUP'
        $text = 'C:\Users\primaryuser\Desktop\app.exe; C:\Users\anotheruser\AppData\Local; C:\Users\Public\Documents; C:\Users\Default\NTUSER.DAT'

        $redacted = Protect-RedactedText -Text $text -Context $ctx

        $redacted | Should Not Match '(?i)primaryuser'
        $redacted | Should Not Match '(?i)anotheruser'
        $redacted | Should Match 'C:\\Users\\USER_1\\Desktop'
        $redacted | Should Match 'C:\\Users\\USER_2\\AppData'
        $redacted | Should Match 'C:\\Users\\Public\\Documents'
        $redacted | Should Match 'C:\\Users\\Default\\NTUSER\.DAT'
    }

    It 'redacts link-local and ULA IPv6 addresses' {
        $ctx = New-RedactionContext -UserName 'bob' -ComputerName 'PC1' -Domain 'WORKGROUP'
        $text = 'IPv6 fe80::1ff:fe23:4567:890a%12 and ULA fd12:3456:789a::1'

        $redacted = Protect-RedactedText -Text $text -Context $ctx

        $redacted | Should Not Match 'fe80::'
        $redacted | Should Not Match 'fd12:'
        $redacted | Should Match 'IP6_1'
        $redacted | Should Match 'IP6_2'
    }

    It 'redacts second profile name, DOMAIN\svc_account, and user@domain with stable tokens across sections' {
        $ctx = New-RedactionContext -UserName 'primaryuser' -ComputerName 'PC1' -Domain 'WORKGROUP' -AdditionalUsers @('OtherLocalProfile')
        $secStartup = 'Task RunAs: ACMECORP\svc_account | Profile owner: OtherLocalProfile | Contact: ops.admin@contoso.local'
        $secServices = 'Service StartName: ACMECORP\svc_account | Bare ref: svc_account | Backup: ops.admin@contoso.local | Other: otherlocalprofile'

        $out1 = Protect-RedactedText -Text $secStartup -Context $ctx
        $out2 = Protect-RedactedText -Text $secServices -Context $ctx

        $out1 | Should Not Match '(?i)OtherLocalProfile'
        $out1 | Should Not Match '(?i)svc_account'
        $out1 | Should Not Match '(?i)ACMECORP'
        $out1 | Should Not Match '(?i)ops\.admin'
        $out1 | Should Not Match '(?i)contoso\.local'

        $out2 | Should Not Match '(?i)OtherLocalProfile'
        $out2 | Should Not Match '(?i)svc_account'
        $out2 | Should Not Match '(?i)ACMECORP'
        $out2 | Should Not Match '(?i)ops\.admin'
        $out2 | Should Not Match '(?i)contoso\.local'

        $out1 | Should Match 'USER_2'
        $out1 | Should Match 'DOMAIN_2\\USER_4'
        $out1 | Should Match 'USER_3@DOMAIN_1'
        $out2 | Should Match 'DOMAIN_2\\USER_4'
        $out2 | Should Match 'Bare ref: USER_4'
        $out2 | Should Match 'USER_3@DOMAIN_1'
        $out2 | Should Match 'Other: USER_2'
    }

    It 'preserves built-in Windows principals and standard system/program file paths' {
        $ctx = New-RedactionContext -UserName 'bob' -ComputerName 'PC1' -Domain 'WORKGROUP'
        $text = 'StartName: NT AUTHORITY\SYSTEM, NT AUTHORITY\LOCAL SERVICE, NT SERVICE\W32Time, BUILTIN\Administrators | Path: "C:\Program Files\VendorApp" | C:\Windows\System32\svchost.exe  CONTOSO\deploy_svc'

        $redacted = Protect-RedactedText -Text $text -Context $ctx

        $redacted | Should Match 'NT AUTHORITY\\SYSTEM'
        $redacted | Should Match 'NT AUTHORITY\\LOCAL SERVICE'
        $redacted | Should Match 'NT SERVICE\\W32Time'
        $redacted | Should Match 'BUILTIN\\Administrators'
        $redacted | Should Match 'C:\\Program Files\\VendorApp'
        $redacted | Should Match 'C:\\Windows\\System32\\svchost\.exe'
        $redacted | Should Not Match '(?i)CONTOSO'
        $redacted | Should Not Match '(?i)deploy_svc'
        $redacted | Should Match 'DOMAIN_1\\USER_2'
    }

    It 'performs two-pass redaction so a name appearing bare in section 2 and as DOMAIN\name in section 6 is tokenized in both' {
        $outDir = Join-Path -Path $TestDrive -ChildPath 'two-pass'
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null

        # Deliberately NOT pre-seeding svc_deploy_bot or CORPDOM in New-RedactionContext
        $ctx = New-RedactionContext -UserName 'primaryuser' -ComputerName 'PC1' -Domain 'WORKGROUP'

        $sec2 = Invoke-DiagnosticSection `
            -Name 'Hardware' `
            -FileName '02_hardware.txt' `
            -FolderPath $outDir `
            -DeferWrite `
            -ScriptBlock {
                return @{
                    Status  = 'OK'
                    Summary = 'Hardware owner svc_deploy_bot'
                    Content = 'Assigned operator: svc_deploy_bot'
                }
            }

        $sec6 = Invoke-DiagnosticSection `
            -Name 'Startup' `
            -FileName '06_startup.txt' `
            -FolderPath $outDir `
            -DeferWrite `
            -ScriptBlock {
                return @{
                    Status  = 'OK'
                    Summary = '1 task for CORPDOM\svc_deploy_bot'
                    Content = 'Task RunAs: CORPDOM\svc_deploy_bot'
                }
            }

        $final = @(Write-DiagnosticSections -Sections @($sec2, $sec6) -Redact -RedactionContext $ctx)

        $hwText = Get-Content -LiteralPath (Join-Path -Path $outDir -ChildPath '02_hardware.txt') -Raw
        $stText = Get-Content -LiteralPath (Join-Path -Path $outDir -ChildPath '06_startup.txt') -Raw

        $hwText | Should Not Match '(?i)svc_deploy_bot'
        $stText | Should Not Match '(?i)svc_deploy_bot'
        $stText | Should Not Match '(?i)CORPDOM'
        $final[0].Summary | Should Not Match '(?i)svc_deploy_bot'
        $final[1].Summary | Should Not Match '(?i)svc_deploy_bot'

        $hwText | Should Match 'Assigned operator: USER_2'
        $stText | Should Match 'Task RunAs: DOMAIN_1\\USER_2'
        $final[0].Summary | Should Match 'Hardware owner USER_2'
        $final[1].Summary | Should Match '1 task for DOMAIN_1\\USER_2'
    }

    It 'preserves scheduled task path "\NVIDIA Corporation\Package Manager\" while still tokenizing ACMECORP\svc_account' {
        $ctx = New-RedactionContext -UserName 'bob' -ComputerName 'PC1' -Domain 'WORKGROUP'
        $text = 'TaskPath : \NVIDIA Corporation\Package Manager\ | RunAs : ACMECORP\svc_account'

        $redacted = Protect-RedactedText -Text $text -Context $ctx

        $redacted | Should Match '\\NVIDIA Corporation\\Package Manager\\'
        $redacted | Should Not Match '(?i)ACMECORP'
        $redacted | Should Not Match '(?i)svc_account'
        $redacted | Should Match 'DOMAIN_1\\USER_2'
    }

    It 'only replaces known names at word boundaries, never inside other words' {
        $ctx = New-RedactionContext -UserName 'jon' -ComputerName 'PC-1' -Domain 'PC-1' -DnsDomain ''
        $sample = 'Lib: jongo.dll | Net: banjonet | Path: C:\Users\jon\file.txt | Owner: jon | Backup: jon_backup | Tool: jonathanTool'

        $redacted = Protect-RedactedText -Text $sample -Context $ctx

        $redacted | Should Match 'jongo\.dll'
        $redacted | Should Match 'banjonet'
        $redacted | Should Match 'jonathanTool'
        $redacted | Should Match 'Owner: USER_1'
        $redacted | Should Match 'USER_1_backup'
        $redacted | Should Not Match '\\jon\\'
    }
}

Describe 'Collect-Diagnostics - Flag Thresholds' {
    It 'returns zero flags when all metrics are healthy or right on non-failing boundaries' {
        $metrics = @{
            Disks                    = @(
                [pscustomobject]@{ DeviceID = 'C:'; FreePercent = 15.0 }
                [pscustomobject]@{ DeviceID = 'D:'; FreePercent = 65.4 }
            )
            DefenderSignatureAgeDays = 3
            PendingReboot            = $false
            StoppedAutoServices      = @()
            EventSourceCounts        = @(
                [pscustomobject]@{ Source = 'Service Control Manager'; Count = 50 }
            )
        }

        $flags = @(Get-DiagnosticFlags -Metrics $metrics)
        $flags.Count | Should Be 0
    }

    It 'flags disk free percentage strictly below 15%' {
        $metrics = @{
            Disks = @(
                [pscustomobject]@{ DeviceID = 'C:'; FreePercent = 14.9 }
                [pscustomobject]@{ DeviceID = 'D:'; FreePercent = 15.0 }
            )
        }

        $flags = @(Get-DiagnosticFlags -Metrics $metrics)
        $flags.Count | Should Be 1
        $flags[0] | Should Match 'C:'
        $flags[0] | Should Match '14\.9%'
    }

    It 'flags Defender signature age strictly above 3 days' {
        $flagged = @(Get-DiagnosticFlags -Metrics @{ DefenderSignatureAgeDays = 4 })
        $notFlagged = @(Get-DiagnosticFlags -Metrics @{ DefenderSignatureAgeDays = 3 })
        $nullAge = @(Get-DiagnosticFlags -Metrics @{ DefenderSignatureAgeDays = $null })

        $flagged.Count | Should Be 1
        $flagged[0] | Should Match '4 days old'
        $notFlagged.Count | Should Be 0
        $nullAge.Count | Should Be 0
    }

    It 'flags pending reboot when true' {
        $flagged = @(Get-DiagnosticFlags -Metrics @{ PendingReboot = $true })
        $notFlagged = @(Get-DiagnosticFlags -Metrics @{ PendingReboot = $false })

        $flagged.Count | Should Be 1
        $flagged[0] | Should Match 'pending reboot'
        $notFlagged.Count | Should Be 0
    }

    It 'flags stopped automatic-start services when count > 0' {
        $flagged = @(Get-DiagnosticFlags -Metrics @{ StoppedAutoServices = @('wuauserv', 'BITS') })
        $notFlagged = @(Get-DiagnosticFlags -Metrics @{ StoppedAutoServices = @() })

        $flagged.Count | Should Be 1
        $flagged[0] | Should Match '2 automatic-start service'
        $flagged[0] | Should Match 'wuauserv'
        $notFlagged.Count | Should Be 0
    }

    It 'flags event sources with strictly more than 50 errors' {
        $metrics = @{
            EventSourceCounts = @(
                [pscustomobject]@{ Source = 'AppError'; Count = 50 }
                [pscustomobject]@{ Source = 'Disk'; Count = 51 }
            )
        }

        $flags = @(Get-DiagnosticFlags -Metrics $metrics)
        $flags.Count | Should Be 1
        $flags[0] | Should Match 'Disk'
        $flags[0] | Should Match '51 events'
    }
}

Describe 'Collect-Diagnostics - Section-Failure Isolation & Elevation Handling' {
    It 'isolates a failing section and lets subsequent sections succeed without throwing' {
        $outDir = Join-Path -Path $TestDrive -ChildPath 'isolation'
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null

        $res1 = $null
        $res2 = $null

        {
            $script:res1 = Invoke-DiagnosticSection `
                -Name 'BrokenSection' `
                -FileName '01_broken.txt' `
                -FolderPath $outDir `
                -ScriptBlock { throw 'Simulated section boom' }

            $script:res2 = Invoke-DiagnosticSection `
                -Name 'HealthySection' `
                -FileName '02_healthy.txt' `
                -FolderPath $outDir `
                -ScriptBlock {
                    return @{
                        Status  = 'OK'
                        Summary = 'All good'
                        Content = 'Healthy output line'
                    }
                }
        } | Should Not Throw

        $script:res1.Status | Should Be 'ERROR'
        $script:res1.Summary | Should Match 'Simulated section boom'
        (Join-Path -Path $outDir -ChildPath '01_broken.txt') | Should Exist
        (Get-Content -LiteralPath (Join-Path -Path $outDir -ChildPath '01_broken.txt') -Raw) | Should Match 'Simulated section boom'

        $script:res2.Status | Should Be 'OK'
        $script:res2.Summary | Should Be 'All good'
        (Join-Path -Path $outDir -ChildPath '02_healthy.txt') | Should Exist
    }

    It 'records SKIPPED: requires admin when an UnauthorizedAccessException is thrown' {
        $outDir = Join-Path -Path $TestDrive -ChildPath 'skip-admin'
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null

        $res = Invoke-DiagnosticSection `
            -Name 'AdminOnlySection' `
            -FileName 'admin.txt' `
            -FolderPath $outDir `
            -ScriptBlock { throw (New-Object System.UnauthorizedAccessException('Access is denied')) }

        $res.Status | Should Be 'SKIPPED'
        $res.Summary | Should Be 'SKIPPED: requires admin'
        (Get-Content -LiteralPath (Join-Path -Path $outDir -ChildPath 'admin.txt') -Raw) | Should Match 'SKIPPED: requires admin'
    }

    It 'applies redaction to both section file content and summary when -Redact is set' {
        $outDir = Join-Path -Path $TestDrive -ChildPath 'redact-section'
        New-Item -Path $outDir -ItemType Directory -Force | Out-Null
        $ctx = New-RedactionContext -UserName 'SecretUser' -ComputerName 'SECRET-HOST' -Domain 'WORKGROUP'

        $res = Invoke-DiagnosticSection `
            -Name 'Sample' `
            -FileName 'sample.txt' `
            -FolderPath $outDir `
            -Redact `
            -RedactionContext $ctx `
            -ScriptBlock {
                return @{
                    Status  = 'OK'
                    Summary = 'Host SECRET-HOST user SecretUser'
                    Content = 'Path C:\Users\SecretUser\log.txt IP 192.168.10.5'
                }
            }

        $fileText = Get-Content -LiteralPath (Join-Path -Path $outDir -ChildPath 'sample.txt') -Raw
        $res.Summary | Should Not Match '(?i)SecretUser'
        $res.Summary | Should Not Match '(?i)SECRET-HOST'
        $fileText | Should Not Match '(?i)SecretUser'
        $fileText | Should Match 'USER_1'
        $fileText | Should Match 'IP_1'
    }

    It 'logs SKIPPED: requires admin for BitLocker and SMART reliability counters when not elevated' {
        $hw = Get-SectionHardware -IsAdmin $false
        $sec = Get-SectionSecurity -IsAdmin $false

        $hw.Content | Should Match 'SKIPPED: requires admin'
        $sec.Content | Should Match 'SKIPPED: requires admin'
    }
}
