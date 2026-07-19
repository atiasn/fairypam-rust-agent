param(
    [ValidateSet('Authority', 'Run', 'WrongSession')]
    [string]$Mode = 'Run',
    [string]$SourceCommit = '',
    [string]$BuildId = '',
    [string]$Nonce = '',
    [string]$RunnerSha256 = '',
    [string]$ProdAgentPath = '',
    [string]$ProdAgentSha256 = '',
    [string]$AgentCtlPath = '',
    [string]$AgentCtlSha256 = '',
    [string]$ProdEnvironmentPath = '',
    [string]$ProdEnvironmentSha256 = '',
    [string]$BuildReceiptPath = '',
    [string]$BuildReceiptSha256 = '',
    [string]$ReceiptPath = '',
    [string]$AuthorityRoot = '',
    [string]$StateRoot = '',
    [ValidateRange(10, 300)]
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$AgentRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Write-JsonFile([string]$Path, $Payload) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $temporary = "$Path.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Payload | ConvertTo-Json -Depth 12))
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
    if ([IO.File]::Exists($Path)) {
        [IO.File]::Replace($temporary, $Path, $null)
    } else {
        [IO.File]::Move($temporary, $Path)
    }
}

function Read-JsonFile([string]$Path) {
    $json = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false, $true))
    return $json | ConvertFrom-Json
}

function Assert-Identity([string]$ExpectedSourceCommit, [string]$ExpectedBuildId, [string]$ExpectedNonce) {
    if ($ExpectedSourceCommit -cnotmatch '^[0-9a-f]{40}$' -or
        $ExpectedBuildId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,95}$' -or
        $ExpectedNonce -cnotmatch '^[0-9a-f]{64}$') {
        throw 'source_commit, build_id, or nonce is invalid'
    }
}

function Assert-ProtectedPath([string]$Path, [string]$Field) {
    $full = [IO.Path]::GetFullPath($Path)
    $programDataRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramData 'FairyPam'))
    if ($full -ine $programDataRoot -and
        -not $full.StartsWith("$programDataRoot\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Field must be stored below protected ProgramData\FairyPam"
    }
    $trustedWriters = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writeRights = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $cursor = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    while ($cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Field path may not traverse a reparse point"
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -cnotin $trustedWriters) {
            throw "$Field ancestor owner is not a protected authority: $($cursor.FullName)"
        }
        foreach ($rule in $acl.Access) {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                $sid -cnotin $trustedWriters -and ($rule.FileSystemRights -band $writeRights)) {
                throw "$Field ACL grants a low-authority principal mutable access: $($cursor.FullName)"
            }
        }
        if ($cursor.FullName -ieq $programDataRoot) {
            if (-not $acl.AreAccessRulesProtected) {
                throw "$Field protected authority inherits an uncontrolled ACL"
            }
            break
        }
        $cursor = $cursor.Parent
    }
    if (-not $cursor) { throw "$Field ancestor chain did not reach ProgramData\FairyPam" }
    return $full
}

function Assert-ProtectedFile([string]$Path, [string]$Field) {
    $full = Assert-ProtectedPath $Path $Field
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw "$Field must be a regular file" }
    return $full
}

function Get-VerifiedFile([string]$Path, [string]$ExpectedSha256, [string]$Field) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $ExpectedSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Field path/hash contract is invalid"
    }
    $full = Assert-ProtectedFile $Path $Field
    $sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash.ToLowerInvariant()
    if ($sha256 -cne $ExpectedSha256) { throw "$Field SHA256 mismatch" }
    return $full
}

function Get-VerifiedDirectory([string]$Path, [string]$Field) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw "$Field must be absolute" }
    $full = Assert-ProtectedPath $Path $Field
    if (-not (Get-Item -LiteralPath $full -Force).PSIsContainer) { throw "$Field must be a directory" }
    return $full
}

function Copy-ProtectedFileSnapshot(
    [string]$Source,
    [string]$Destination,
    [string]$ExpectedSha256,
    [string]$Field
) {
    $verified = Get-VerifiedFile $Source $ExpectedSha256 $Field
    Copy-Item -LiteralPath $verified -Destination $Destination -Force
    return Get-VerifiedFile $Destination $ExpectedSha256 "${Field}_snapshot"
}

function Copy-ProtectedDirectorySnapshot([string]$Source, [string]$Destination, [string]$Field) {
    $verified = Get-VerifiedDirectory $Source $Field
    foreach ($item in @(Get-ChildItem -LiteralPath $verified -Force -Recurse)) {
        Assert-ProtectedPath $item.FullName "${Field}_entry" | Out-Null
    }
    Copy-Item -LiteralPath $verified -Destination $Destination -Force -Recurse
    return Get-VerifiedDirectory $Destination "${Field}_snapshot"
}

function Get-VerifiedBuildReceipt(
    [string]$Path,
    [string]$ExpectedSha256,
    [string]$ExpectedSourceCommit,
    [string]$ExpectedBuildId,
    [string]$ExpectedProdSha256,
    [string]$ExpectedAgentCtlSha256,
    [string]$ExpectedEnvironmentSha256
) {
    $verified = Get-VerifiedFile $Path $ExpectedSha256 'build_receipt'
    Assert-ProtectedFile $verified 'build_receipt'
    $value = Read-JsonFile $verified
    if ([int]$value.schema_version -ne 1 -or
        [string]$value.source_commit -cne $ExpectedSourceCommit -or
        [string]$value.build_id -cne $ExpectedBuildId -or
        [string]$value.production_agent_sha256 -cne $ExpectedProdSha256 -or
        [string]$value.development_agent_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$value.agentctl_sha256 -cne $ExpectedAgentCtlSha256 -or
        [string]$value.production_environment_sha256 -cne $ExpectedEnvironmentSha256) {
        throw 'clean-build receipt identity is not exact'
    }
    return $value
}

function Get-VerifiedProductionEnvironment(
    [string]$Path,
    [string]$ExpectedSha256,
    [string]$ExpectedSourceCommit,
    [string]$ExpectedBuildId,
    [string]$ExpectedAgentPath,
    [string]$ExpectedAgentSha256,
    [string]$SnapshotRoot
) {
    $verified = Get-VerifiedFile $Path $ExpectedSha256 'prod_environment'
    Assert-ProtectedFile $verified 'prod_environment'
    $value = Read-JsonFile $verified
    if ([int]$value.schema_version -ne 1 -or
        [string]$value.source_commit -cne $ExpectedSourceCommit -or
        [string]$value.build_id -cne $ExpectedBuildId -or
        [string]$value.agent_sha256 -cne $ExpectedAgentSha256 -or
        [string]$value.profile_root_public_key_hex -cnotmatch '^[0-9a-fA-F]{64}$' -or
        [string]$value.pipe_name -cnotmatch '^\\\\\.\\pipe\\FairyPam\.Agent\.prod\.v1\.' -or
        [string]$value.task_name -cnotmatch '^\\[^\\]+(\\[^\\]+)*$' -or
        [string]::IsNullOrWhiteSpace([string]$value.task_user_id) -or
        [string]::IsNullOrWhiteSpace([string]$value.task_logon_type) -or
        [string]::IsNullOrWhiteSpace([string]$value.task_run_level)) {
        throw 'production environment identity is not exact'
    }
    foreach ($field in @('control_endpoint', 'frame_endpoint')) {
        $uri = $null
        $text = [string]$value.$field
        if (-not [Uri]::TryCreate($text, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -cne 'https') {
            throw "production environment $field must be HTTPS"
        }
    }
    foreach ($field in @('hub_server_name', 'agent_id')) {
        if ([string]::IsNullOrWhiteSpace([string]$value.$field)) {
            throw "production environment $field is missing"
        }
    }
    foreach ($entry in @(
        @('ca_pem', 'ca_pem_sha256'),
        @('agent_cert_pem', 'agent_cert_pem_sha256'),
        @('agent_key_pem', 'agent_key_pem_sha256')
    )) {
        $value.($entry[0]) = Copy-ProtectedFileSnapshot `
            ([string]$value.($entry[0])) `
            (Join-Path $SnapshotRoot ([string]$entry[0])) `
            ([string]$value.($entry[1])) `
            ([string]$entry[0])
    }
    $value.profile_dir = Copy-ProtectedDirectorySnapshot `
        ([string]$value.profile_dir) `
        (Join-Path $SnapshotRoot 'production-profiles') `
        'profile_dir'
    $value.state_dir = Get-VerifiedDirectory ([string]$value.state_dir) 'production_state_dir'
    $value.task_working_directory = Get-VerifiedDirectory ([string]$value.task_working_directory) 'production_task_working_directory'
    $taskName = ([string]$value.task_name).Substring(([string]$value.task_name).LastIndexOf('\') + 1)
    $taskPath = ([string]$value.task_name).Substring(0, ([string]$value.task_name).LastIndexOf('\') + 1)
    $tasks = @(Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue)
    if ($tasks.Count -ne 1 -or @($tasks[0].Actions).Count -ne 1 -or
        [string]$tasks[0].Actions[0].Execute -ine [IO.Path]::GetFullPath($ExpectedAgentPath) -or
        [string]$tasks[0].Actions[0].Arguments -cne [string]$value.task_arguments -or
        [string]$tasks[0].Actions[0].WorkingDirectory -ine [string]$value.task_working_directory -or
        [string]$tasks[0].Principal.UserId -ine [string]$value.task_user_id -or
        [string]$tasks[0].Principal.LogonType -cne [string]$value.task_logon_type -or
        [string]$tasks[0].Principal.RunLevel -cne [string]$value.task_run_level) {
        throw 'registered production Task action, principal, or working directory was tampered'
    }
    return $value
}

function Get-CanonicalDevProvision(
    [string]$ExpectedBuildId,
    [string]$ExpectedAgentSha256,
    [string]$SnapshotRoot,
    [switch]$ValidateOnly
) {
    $devRoot = Join-Path $env:ProgramData 'FairyPam\Dev'
    $matches = @()
    foreach ($path in @(Get-ChildItem -LiteralPath $devRoot -Directory -ErrorAction SilentlyContinue)) {
        $manifestPath = Join-Path $path.FullName 'dev-provision.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { continue }
        try {
            $manifestSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Assert-ProtectedFile $manifestPath 'dev_provision_manifest')).Hash.ToLowerInvariant()
            $manifestSnapshot = $manifestPath
            if (-not $ValidateOnly) {
                $candidateSnapshot = Join-Path $SnapshotRoot "dev-provision-$($path.Name).json"
                $manifestSnapshot = Copy-ProtectedFileSnapshot $manifestPath $candidateSnapshot $manifestSha256 'dev_provision_manifest'
            }
            $manifest = Read-JsonFile $manifestSnapshot
            if ([string]$manifest.build_id -ceq $ExpectedBuildId) {
                $matches += [pscustomobject]@{
                    root = $path.FullName
                    manifest = $manifest
                    manifest_path = $manifestSnapshot
                    manifest_sha256 = $manifestSha256
                }
            }
        } catch { }
    }
    if ($matches.Count -ne 1) { throw 'exactly one canonical protected DevProvisionManifest is required' }
    $root = [IO.Path]::GetFullPath([string]$matches[0].root)
    $manifest = $matches[0].manifest
    try { $userSid = [Security.Principal.SecurityIdentifier]::new([string]$manifest.developer_sid).Value } catch { throw 'canonical developer SID is invalid' }
    if ($userSid -ceq 'S-1-5-18') { throw 'canonical developer principal may not be SYSTEM' }
    $slot = [IO.Path]::GetFullPath((Join-Path $root 'slot'))
    $state = [IO.Path]::GetFullPath((Join-Path $root 'state'))
    $agent = [IO.Path]::GetFullPath((Join-Path $slot 'fairypam-agent.exe'))
    if ([int]$manifest.schema_version -ne 1 -or
        [string]$manifest.developer_sid_hash -cnotmatch '^[0-9a-f]{64}$' -or
        (Split-Path -Leaf $root) -cne ([string]$manifest.developer_sid_hash).Substring(0, 24) -or
        [IO.Path]::GetFullPath([string]$manifest.slot_dir) -ine $slot -or
        [IO.Path]::GetFullPath([string]$manifest.state_dir) -ine $state -or
        [string]$manifest.agent_sha256 -cne $ExpectedAgentSha256 -or
        [string]$manifest.pipe_name -cnotmatch '^\\\\\.\\pipe\\FairyPam\.Agent\.dev\.v1\.' -or
        [string]$manifest.task_name -cnotmatch '^\\FairyPam\\Dev\\[0-9a-f]{24}$') {
        throw 'canonical DevProvisionManifest identity is invalid'
    }
    Get-VerifiedDirectory $root 'dev_provision_root' | Out-Null
    Get-VerifiedDirectory $slot 'dev_slot_dir' | Out-Null
    Get-VerifiedDirectory $state 'dev_state_dir' | Out-Null
    Get-VerifiedFile $agent $ExpectedAgentSha256 'canonical_dev_agent' | Out-Null

    if ($ValidateOnly) {
        return [pscustomobject]@{
            manifest = $manifest
            agent = $agent
            slot = $slot
            state = $state
            user_sid = $userSid
        }
    }

    $taskName = ([string]$manifest.task_name).Substring(([string]$manifest.task_name).LastIndexOf('\') + 1)
    $taskPath = ([string]$manifest.task_name).Substring(0, ([string]$manifest.task_name).LastIndexOf('\') + 1)
    $tasks = @(Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue)
    if ($tasks.Count -ne 1 -or @($tasks[0].Actions).Count -ne 1 -or
        [string]$tasks[0].Actions[0].Execute -ine $agent -or
        -not [string]::IsNullOrEmpty([string]$tasks[0].Actions[0].Arguments) -or
        [string]$tasks[0].Actions[0].WorkingDirectory -ine $slot -or
        [string]$tasks[0].Principal.UserId -ine $userSid -or
        [string]$tasks[0].Principal.LogonType -cne 'Interactive' -or
        [string]$tasks[0].Principal.RunLevel -cne 'Highest') {
        throw 'registered canonical Dev Task action, principal, or slot identity was tampered'
    }
    $devSnapshot = Join-Path $SnapshotRoot 'development'
    New-Item -ItemType Directory -Force -Path $devSnapshot | Out-Null
    $snapshotAgent = Copy-ProtectedFileSnapshot $agent (Join-Path $devSnapshot 'fairypam-agent.exe') $ExpectedAgentSha256 'canonical_dev_agent'
    $runtimePath = [IO.Path]::GetFullPath([string]$manifest.runtime_config_path)
    $runtimeSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Assert-ProtectedFile $runtimePath 'dev_runtime_config')).Hash.ToLowerInvariant()
    $snapshotRuntime = Copy-ProtectedFileSnapshot $runtimePath (Join-Path $devSnapshot 'runtime-config.json') $runtimeSha256 'dev_runtime_config'
    $snapshotCa = Copy-ProtectedFileSnapshot ([string]$manifest.ca_path) (Join-Path $devSnapshot 'dev-ca.pem') ((Get-FileHash -Algorithm SHA256 -LiteralPath (Assert-ProtectedFile ([string]$manifest.ca_path) 'dev_ca')).Hash.ToLowerInvariant()) 'dev_ca'
    $snapshotCertificate = Copy-ProtectedFileSnapshot ([string]$manifest.certificate_path) (Join-Path $devSnapshot 'dev-agent-cert.pem') ((Get-FileHash -Algorithm SHA256 -LiteralPath (Assert-ProtectedFile ([string]$manifest.certificate_path) 'dev_certificate')).Hash.ToLowerInvariant()) 'dev_certificate'
    $snapshotPrivateKey = Copy-ProtectedFileSnapshot ([string]$manifest.private_key_path) (Join-Path $devSnapshot 'dev-agent-key.pem') ((Get-FileHash -Algorithm SHA256 -LiteralPath (Assert-ProtectedFile ([string]$manifest.private_key_path) 'dev_private_key')).Hash.ToLowerInvariant()) 'dev_private_key'
    $snapshotProfiles = Copy-ProtectedDirectorySnapshot ([string]$manifest.profile_dir) (Join-Path $devSnapshot 'profiles') 'dev_profiles'
    return [pscustomobject]@{
        manifest = $manifest
        manifest_path = [string]$matches[0].manifest_path
        manifest_sha256 = [string]$matches[0].manifest_sha256
        # ponytail: the registered task must execute the verified canonical slot, never a copied lookalike.
        agent = $agent
        slot = $slot
        state = $state
        user_sid = $userSid
        runtime_config = $snapshotRuntime
        runtime_config_sha256 = $runtimeSha256
        ca = $snapshotCa
        certificate = $snapshotCertificate
        private_key = $snapshotPrivateKey
        profiles = $snapshotProfiles
    }
}

function Get-ProcessIdentity($Process, [string]$ExpectedPath, [string]$ExpectedSha256) {
    $Process.Refresh()
    $actualPath = [IO.Path]::GetFullPath($Process.Path)
    if ($actualPath -ine [IO.Path]::GetFullPath($ExpectedPath)) {
        throw 'started process binary identity changed before ownership transfer'
    }
    Get-VerifiedFile $actualPath $ExpectedSha256 'started_process' | Out-Null
    return [ordered]@{
        pid = [int]$Process.Id
        started_at_unix_ms = ([DateTimeOffset]$Process.StartTime).ToUniversalTime().ToUnixTimeMilliseconds()
        path = [IO.Path]::GetFullPath($ExpectedPath)
        sha256 = $ExpectedSha256
    }
}

function Stop-ExactProcess($Identity) {
    $process = Get-Process -Id ([int]$Identity.pid) -ErrorAction SilentlyContinue
    if (-not $process) { return }
    $actualPath = [IO.Path]::GetFullPath($process.Path)
    $actualStartedAt = ([DateTimeOffset]$process.StartTime).ToUniversalTime().ToUnixTimeMilliseconds()
    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $actualPath).Hash.ToLowerInvariant()
    if ($actualPath -ine [string]$Identity.path -or
        $actualStartedAt -ne [long]$Identity.started_at_unix_ms -or
        $actualSha256 -cne [string]$Identity.sha256) {
        throw "refusing to stop reused or unowned pid $($Identity.pid)"
    }
    Stop-Process -Id $process.Id -Force -ErrorAction Stop
    Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
    if (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
        throw "owned pid $($Identity.pid) did not exit"
    }
}

function Write-OwnedState([string]$Path, [string]$ExpectedNonce, [Collections.ArrayList]$Owned) {
    Write-JsonFile $Path ([ordered]@{
        schema_version = 1
        nonce = $ExpectedNonce
        processes = @($Owned)
    })
}

function Take-ProcessOwnership(
    $Process,
    [string]$ExpectedPath,
    [string]$ExpectedSha256,
    [Collections.ArrayList]$Owned,
    [string]$StatePath,
    [string]$ExpectedNonce
) {
    $identity = $null
    try {
        $identity = Get-ProcessIdentity $Process $ExpectedPath $ExpectedSha256
        [void]$Owned.Add($identity)
    } catch {
        try { Stop-Process -Id $Process.Id -Force -ErrorAction Stop } catch { }
        throw
    }
    try {
        Write-OwnedState $StatePath $ExpectedNonce $Owned
        $intentPath = Join-Path (Split-Path -Parent $StatePath) 'recovery-intent.json'
        $intent = Read-JsonFile $intentPath
        $intent.stage = 'running'
        $intent.processes = @($intent.processes) + @($identity)
        Write-JsonFile $intentPath $intent
        return $identity
    } catch {
        $stateError = $_.Exception.Message
        $stopError = $null
        try { Stop-ExactProcess $identity } catch { $stopError = $_.Exception.Message }
        try {
            Write-JsonFile (Join-Path (Split-Path -Parent $StatePath) 'ownership-recovery.json') ([ordered]@{
                schema_version = 1
                nonce = $ExpectedNonce
                process = $identity
                state_error = $stateError
                stop_error = $stopError
            })
        } catch { }
        if ($stopError) { throw "state persistence failed and owned process stop failed: $stateError; $stopError" }
        throw
    }
}

function Stop-OwnedProcesses([Collections.ArrayList]$Owned) {
    $errors = @()
    foreach ($identity in @($Owned)) {
        try { Stop-ExactProcess $identity } catch { $errors += $_.Exception.Message }
    }
    if ($errors.Count -ne 0) { throw ($errors -join '; ') }
}

function Assert-NoExactProcess([string[]]$Paths) {
    $expected = @($Paths | ForEach-Object { [IO.Path]::GetFullPath($_) })
    $running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -and ([IO.Path]::GetFullPath($_.Path) -iin $expected) } catch { $false }
    })
    if ($running.Count -ne 0) { throw 'a supplied Agent binary is already running; refusing unowned cleanup' }
}

function Invoke-Cli([string]$Executable, [string[]]$Arguments, [string]$Prefix) {
    if ($script:TrustedAgentCtlSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'trusted agentctl identity is unavailable'
    }
    Get-VerifiedFile $Executable $script:TrustedAgentCtlSha256 'agentctl' | Out-Null
    $stdout = "$Prefix.out"
    $stderr = "$Prefix.err"
    Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath $stdout, $stderr
    $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $payload = $null
    $category = ''
    if ($process.ExitCode -eq 0) {
        $payload = Read-JsonFile $stdout
    } elseif (Test-Path -LiteralPath $stderr) {
        try { $category = [string](Read-JsonFile $stderr).error.category } catch { $category = 'unparseable' }
    }
    return [pscustomobject]@{ exit_code = [int]$process.ExitCode; payload = $payload; error_category = $category }
}

function Wait-CliSuccess([string]$Executable, [string[]]$Arguments, [string]$Prefix, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $result = Invoke-Cli $Executable $Arguments $Prefix
        if ($result.exit_code -eq 0) { return $result.payload }
        if ($result.error_category -cne 'agent_unavailable') {
            throw "local CLI failed with unexpected category $($result.error_category): $($Arguments -join ' ')"
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw "local CLI timed out waiting for agent_unavailable to clear: $($Arguments -join ' ')"
}

function Assert-CliFailure(
    [string]$Executable,
    [string[]]$Arguments,
    [string]$Prefix,
    [string[]]$ExpectedCategories
) {
    $result = Invoke-Cli $Executable $Arguments $Prefix
    if ($result.exit_code -eq 0 -or $result.error_category -cnotin $ExpectedCategories) {
        throw "local CLI failure category was not exact: $($result.error_category); expected $($ExpectedCategories -join ',')"
    }
    return $result
}

function Wait-NewExactProcess(
    [string]$Path,
    [int[]]$BeforePids,
    [int]$Seconds
) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $matches = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $Path -and $_.Id -notin $BeforePids } catch { $false }
        })
        if ($matches.Count -eq 1) { return $matches[0] }
        if ($matches.Count -gt 1) { throw 'canonical Dev Task started multiple indistinguishable processes' }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw 'canonical Dev Task did not start its registered binary in time'
}

function Invoke-WrongSession([string]$Root) {
    $request = Read-JsonFile (Join-Path $Root 'request.json')
    Assert-Identity ([string]$request.source_commit) ([string]$request.build_id) ([string]$request.nonce)
    Get-VerifiedFile $PSCommandPath ([string]$request.runner_sha256) 'runner' | Out-Null
    $agentCtl = Get-VerifiedFile ([string]$request.agentctl.path) ([string]$request.agentctl.sha256) 'agentctl'
    $script:TrustedAgentCtlSha256 = [string]$request.agentctl.sha256
    if ([uint32]$request.production_process_id -eq 0) { throw 'wrong-session target process is missing' }
    $probePrefix = Join-Path $env:TEMP "fairypam-wrong-session-$([string]$request.nonce)"
    Assert-CliFailure $agentCtl @(
        'dev', 'diagnostics-as-process', '--target-pid', [string]$request.production_process_id
    ) $probePrefix @('server_identity_rejected') | Out-Null
}

function Wait-JsonResult([string]$Path, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        if (Test-Path -LiteralPath $Path) {
            try { return Read-JsonFile $Path } catch { }
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw "timed out waiting for gate result: $Path"
}

function Assert-TaskExecute([string]$Execute, [string]$Sha256) {
    Get-VerifiedFile $Execute $Sha256 'scheduled_task_execute' | Out-Null
}

function Assert-TaskDefinition($Task) {
    Assert-TaskExecute ([string]$Task.execute) ([string]$Task.execute_sha256)
    $registered = @(Get-ScheduledTask -TaskName ([string]$Task.name) -TaskPath '\' -ErrorAction SilentlyContinue)
    if ($registered.Count -ne 1 -or @($registered[0].Actions).Count -ne 1) { throw "registered nonce Task is absent or ambiguous: $($Task.name)" }
    $action = $registered[0].Actions[0]
    if ([string]$action.Execute -ine [string]$Task.execute -or [string]$action.Arguments -cne [string]$Task.arguments -or [string]$action.WorkingDirectory -ine [string]$Task.working_directory) { throw "registered nonce Task action, principal, or working directory was tampered: $($Task.name)" }
    if ([string]$registered[0].Principal.UserId -ine [string]$Task.user_id -or [string]$registered[0].Principal.LogonType -cne [string]$Task.logon_type -or [string]$registered[0].Principal.RunLevel -cne [string]$Task.run_level) { throw "registered nonce Task action, principal, or working directory was tampered: $($Task.name)" }
    return $registered[0]
}

function Start-ExactTask($Task, [int]$Seconds) {
    Assert-TaskDefinition $Task | Out-Null
    if ($Task.launch_script_path) { Get-VerifiedFile ([string]$Task.launch_script_path) ([string]$Task.launch_script_sha256) 'scheduled_task_launch_script' | Out-Null }
    $path = [string]$Task.owned_process_path
    if ($path) { Assert-NoExactProcess @($path) }
    $before = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { try { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq $path } catch { $false } } | ForEach-Object { [int]$_.Id })
    Start-ScheduledTask -TaskName ([string]$Task.name) -TaskPath '\'
    if ($path) { return Wait-NewExactProcess $path $before $Seconds }
}

function Invoke-ExactProbeTask($Task, [int]$Seconds) {
    Assert-TaskDefinition $Task | Out-Null
    $before = Get-ScheduledTaskInfo -TaskName ([string]$Task.name) -TaskPath '\'
    Start-ScheduledTask -TaskName ([string]$Task.name) -TaskPath '\'
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $registered = Assert-TaskDefinition $Task
        $info = Get-ScheduledTaskInfo -TaskName ([string]$Task.name) -TaskPath '\'
        if ([DateTime]$info.LastRunTime -gt [DateTime]$before.LastRunTime -and [string]$registered.State -cne 'Running') {
            if ([int]$info.LastTaskResult -ne 0) { throw "exact principal probe failed: $($Task.name) result=$($info.LastTaskResult)" }
            return
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    throw "exact principal probe timed out: $($Task.name)"
}

function Stop-ExactTaskAndAssertNoOwnedProcess($Task) {
    Assert-TaskDefinition $Task | Out-Null
    Stop-ScheduledTask -TaskName ([string]$Task.name) -TaskPath '\' -ErrorAction SilentlyContinue
    if ($Task.owned_process_path) {
        $deadline = (Get-Date).AddSeconds(10)
        do { try { Assert-NoExactProcess @([string]$Task.owned_process_path); return } catch { Start-Sleep -Milliseconds 100 } } while ((Get-Date) -lt $deadline)
        Assert-NoExactProcess @([string]$Task.owned_process_path)
    }
}

function ConvertTo-PowerShellSingleQuotedLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

function Write-ProductionLaunchScript([string]$Path, [string]$AgentPath, $Environment) {
    $values = [ordered]@{
        FAIRYPAM_CONTROL_ENDPOINT = [string]$Environment.control_endpoint
        FAIRYPAM_FRAME_ENDPOINT = [string]$Environment.frame_endpoint
        FAIRYPAM_HUB_SERVER_NAME = [string]$Environment.hub_server_name
        FAIRYPAM_AGENT_ID = [string]$Environment.agent_id
        FAIRYPAM_CA_PEM = [string]$Environment.ca_pem
        FAIRYPAM_AGENT_CERT_PEM = [string]$Environment.agent_cert_pem
        FAIRYPAM_AGENT_KEY_PEM = [string]$Environment.agent_key_pem
        FAIRYPAM_PROFILE_DIR = [string]$Environment.profile_dir
        FAIRYPAM_PROFILE_ROOT_PUBLIC_KEY_HEX = [string]$Environment.profile_root_public_key_hex
    }
    $lines = @("`$ErrorActionPreference = 'Stop'")
    foreach ($entry in $values.GetEnumerator()) {
        $lines += "`$env:$($entry.Key) = $(ConvertTo-PowerShellSingleQuotedLiteral ([string]$entry.Value))"
    }
    $lines += "& $(ConvertTo-PowerShellSingleQuotedLiteral $AgentPath) '--local-control-safe'"
    $lines += 'exit $LASTEXITCODE'
    [IO.File]::WriteAllText($Path, (($lines -join [Environment]::NewLine) + [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
    Assert-ProtectedFile $Path 'production_launch_script' | Out-Null
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Remove-ExactTask(
    [string]$Name,
    [string]$ExpectedExecute,
    [string]$ExpectedExecuteSha256,
    [string]$ExpectedArguments,
    [string]$ExpectedWorkingDirectory,
    [string]$ExpectedUserId,
    [string]$ExpectedLogonType,
    [string]$ExpectedRunLevel,
    [string]$ExpectedOwnedProcessPath = ''
) {
    Get-VerifiedFile $ExpectedExecute $ExpectedExecuteSha256 'scheduled_task_execute' | Out-Null
    $tasks = @(Get-ScheduledTask -TaskName $Name -TaskPath '\' -ErrorAction SilentlyContinue)
    if ($tasks.Count -eq 0) { return }
    if ($tasks.Count -ne 1 -or @($tasks[0].Actions).Count -ne 1 -or
        [string]$tasks[0].Actions[0].Execute -ine $ExpectedExecute -or
        [string]$tasks[0].Actions[0].Arguments -cne $ExpectedArguments -or
        [string]$tasks[0].Actions[0].WorkingDirectory -ine $ExpectedWorkingDirectory -or
        [string]$tasks[0].Principal.UserId -ine $ExpectedUserId -or
        [string]$tasks[0].Principal.LogonType -cne $ExpectedLogonType -or
        [string]$tasks[0].Principal.RunLevel -cne $ExpectedRunLevel) {
        throw "refusing to remove replaced or unowned task $Name"
    }
    Stop-ScheduledTask -TaskName $Name -TaskPath '\' -ErrorAction SilentlyContinue
    if ($ExpectedOwnedProcessPath) { Assert-NoExactProcess @($ExpectedOwnedProcessPath) }
    Unregister-ScheduledTask -TaskName $Name -TaskPath '\' -Confirm:$false -ErrorAction Stop
}

function Remove-IntentTask($Task) {
    if ($Task.launch_script_path) { Get-VerifiedFile ([string]$Task.launch_script_path) ([string]$Task.launch_script_sha256) 'scheduled_task_launch_script' | Out-Null }
    $registered = @(Get-ScheduledTask -TaskName ([string]$Task.name) -TaskPath '\' -ErrorAction SilentlyContinue)
    if ($registered.Count -eq 0) {
        if ($Task.owned_process_path) { Assert-NoExactProcess @([string]$Task.owned_process_path) }
        return
    }
    if ($Task.owned_process_path) { Stop-ExactTaskAndAssertNoOwnedProcess $Task }
    Remove-ExactTask ([string]$Task.name) ([string]$Task.execute) ([string]$Task.execute_sha256) ([string]$Task.arguments) ([string]$Task.working_directory) ([string]$Task.user_id) ([string]$Task.logon_type) ([string]$Task.run_level) ([string]$Task.owned_process_path)
}

function Write-RecoveryIntent([string]$Root, $Intent) {
    # Write-JsonFile flushes the temporary file before its atomic replacement.
    Write-JsonFile (Join-Path $Root 'recovery-intent.json') $Intent
}

function Recover-ProtectedIntent([string]$Root) {
    $intentPath = Join-Path $Root 'recovery-intent.json'
    if (-not (Test-Path -LiteralPath $intentPath -PathType Leaf)) {
        throw 'existing nonce state has no protected recovery intent'
    }
    $intent = Read-JsonFile $intentPath
    if ([int]$intent.schema_version -ne 1 -or [string]::IsNullOrWhiteSpace([string]$intent.nonce)) {
        throw 'protected recovery intent is invalid'
    }
    $errors = @()
    foreach ($task in @($intent.tasks)) {
        try {
            Remove-IntentTask $task
        } catch { $errors += $_.Exception.Message }
    }
    foreach ($identity in @($intent.processes)) {
        try { Stop-ExactProcess $identity } catch { $errors += $_.Exception.Message }
    }
    if ($errors.Count -ne 0) {
        Write-JsonFile (Join-Path $Root 'recovery-mismatch.json') ([ordered]@{
            schema_version = 1
            nonce = [string]$intent.nonce
            stage = [string]$intent.stage
            errors = $errors
        })
        throw ('protected recovery retained mismatch evidence: ' + ($errors -join '; '))
    }
    Remove-Item -Recurse -Force -LiteralPath $Root
}

function Invoke-OrdinaryGate(
    [string]$Root,
    $Request,
    $Environment,
    $Dev,
    $DevTask,
    $ProdTaskOne,
    $ProdTaskTwo,
    $DevProbeTask,
    $ProdProbeTask,
    $DevUnavailableTask,
    $ProdUnavailableTask,
    $WrongTask
) {
    $statePath = Join-Path $Root 'execute-state.json'
    $owned = [Collections.ArrayList]::new()
    Write-OwnedState $statePath ([string]$Request.nonce) $owned
    $integrity = (& "$env:SystemRoot\System32\whoami.exe" /groups /fo csv /nh | Out-String)
    if ($LASTEXITCODE -ne 0 -or $integrity -notmatch 'S-1-16-16384') {
        throw 'fixed authority gate did not receive a System mandatory integrity token'
    }
    $prodAgent = Get-VerifiedFile ([string]$Request.prod_agent.path) ([string]$Request.prod_agent.sha256) 'prod_agent'
    $agentCtl = Get-VerifiedFile ([string]$Request.agentctl.path) ([string]$Request.agentctl.sha256) 'agentctl'
    Assert-NoExactProcess @($prodAgent, [string]$Dev.agent)
    $cleanupErrors = @()
    try {
        $env:FAIRYPAM_CONTROL_ENDPOINT = [string]$Environment.control_endpoint
        $env:FAIRYPAM_FRAME_ENDPOINT = [string]$Environment.frame_endpoint
        $env:FAIRYPAM_HUB_SERVER_NAME = [string]$Environment.hub_server_name
        $env:FAIRYPAM_AGENT_ID = [string]$Environment.agent_id
        $env:FAIRYPAM_CA_PEM = [string]$Environment.ca_pem
        $env:FAIRYPAM_AGENT_CERT_PEM = [string]$Environment.agent_cert_pem
        $env:FAIRYPAM_AGENT_KEY_PEM = [string]$Environment.agent_key_pem
        $env:FAIRYPAM_PROFILE_DIR = [string]$Environment.profile_dir
        $env:FAIRYPAM_PROFILE_ROOT_PUBLIC_KEY_HEX = [string]$Environment.profile_root_public_key_hex

        $prod = Start-ExactTask $ProdTaskOne ([int]$Request.timeout_seconds)
        $prodIdentity = Take-ProcessOwnership $prod $prodAgent ([string]$Request.prod_agent.sha256) $owned $statePath ([string]$Request.nonce)
        Invoke-ExactProbeTask $ProdProbeTask ([int]$Request.timeout_seconds)

        $beforeDev = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and [IO.Path]::GetFullPath($_.Path) -ieq [string]$Dev.agent } catch { $false }
        } | ForEach-Object { [int]$_.Id })
        $devProcess = Start-ExactTask $DevTask ([int]$Request.timeout_seconds)
        $devIdentity = Take-ProcessOwnership $devProcess ([string]$Dev.agent) ([string]$Dev.manifest.agent_sha256) $owned $statePath ([string]$Request.nonce)
        Invoke-ExactProbeTask $DevProbeTask ([int]$Request.timeout_seconds)

        Stop-ExactTaskAndAssertNoOwnedProcess $ProdTaskOne
        Invoke-ExactProbeTask $ProdUnavailableTask 5
        Invoke-ExactProbeTask $DevProbeTask 5

        $prod = Start-ExactTask $ProdTaskTwo ([int]$Request.timeout_seconds)
        $prodIdentity = Take-ProcessOwnership $prod $prodAgent ([string]$Request.prod_agent.sha256) $owned $statePath ([string]$Request.nonce)
        Invoke-ExactProbeTask $ProdProbeTask ([int]$Request.timeout_seconds)
        Stop-ExactTaskAndAssertNoOwnedProcess $DevTask
        Invoke-ExactProbeTask $DevUnavailableTask 5
        Invoke-ExactProbeTask $ProdProbeTask 5

        $Request['production_process_id'] = [int]$prodIdentity.pid
        Write-JsonFile (Join-Path $Root 'request.json') $Request
        Invoke-ExactProbeTask $WrongTask ([int]$Request.timeout_seconds)
        Invoke-ExactProbeTask $ProdProbeTask 5
    } finally {
        try { Stop-OwnedProcesses $owned } catch { $cleanupErrors += $_.Exception.Message }
        if ($cleanupErrors.Count -ne 0) {
            Write-JsonFile (Join-Path $Root 'cleanup-failure.json') ([ordered]@{
                nonce = [string]$Request.nonce
                errors = $cleanupErrors
                owned_processes = @($owned)
            })
            throw ($cleanupErrors -join '; ')
        }
    }
    Invoke-ExactProbeTask $ProdUnavailableTask 5
    Invoke-ExactProbeTask $DevUnavailableTask 5
}

function Invoke-Gate {
    Assert-Identity $SourceCommit $BuildId $Nonce
    Get-VerifiedFile $PSCommandPath $RunnerSha256 'runner' | Out-Null
    $prodAgent = Get-VerifiedFile $ProdAgentPath $ProdAgentSha256 'prod_agent'
    $agentCtl = Get-VerifiedFile $AgentCtlPath $AgentCtlSha256 'agentctl'
    $script:TrustedAgentCtlSha256 = $AgentCtlSha256
    $buildReceipt = Get-VerifiedBuildReceipt $BuildReceiptPath $BuildReceiptSha256 $SourceCommit $BuildId $ProdAgentSha256 $AgentCtlSha256 $ProdEnvironmentSha256
    # Validate the canonical Dev binary before creating state, reading a Task, or starting a process.
    Get-CanonicalDevProvision $BuildId ([string]$buildReceipt.development_agent_sha256) '' -ValidateOnly | Out-Null
    if (-not [IO.Path]::IsPathRooted($ReceiptPath)) { throw 'receipt path must be absolute' }
    if ([string]::IsNullOrWhiteSpace($AuthorityRoot)) { throw 'authority root is required' }
    $trustedAuthorityRoot = Get-VerifiedDirectory $AuthorityRoot 'local_control_authority_root'
    $trustedReceiptPath = [IO.Path]::GetFullPath($ReceiptPath)
    if (-not $trustedReceiptPath.StartsWith("$trustedAuthorityRoot\", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'receipt path must remain below the fixed protected authority root'
    }
    $expectedStateRoot = [IO.Path]::GetFullPath((Join-Path $trustedAuthorityRoot $Nonce))
    if (Test-Path -LiteralPath $expectedStateRoot) {
        Recover-ProtectedIntent $expectedStateRoot
    }
    New-Item -ItemType Directory -Path $expectedStateRoot | Out-Null
    Assert-ProtectedPath $expectedStateRoot 'gate_state_root' | Out-Null
    $environment = Get-VerifiedProductionEnvironment $ProdEnvironmentPath $ProdEnvironmentSha256 $SourceCommit $BuildId $prodAgent $ProdAgentSha256 $expectedStateRoot
    $dev = Get-CanonicalDevProvision $BuildId ([string]$buildReceipt.development_agent_sha256) $expectedStateRoot
    if ($prodAgent -ieq [string]$dev.agent -or
        $ProdAgentSha256 -ceq [string]$dev.manifest.agent_sha256 -or
        [string]$environment.pipe_name -ceq [string]$dev.manifest.pipe_name -or
        [string]$environment.task_name -ceq [string]$dev.manifest.task_name -or
        [IO.Path]::GetFullPath([string]$environment.state_dir) -ieq [IO.Path]::GetFullPath([string]$dev.state)) {
        throw 'production and development binary, pipe, Task, and state identities must all be distinct'
    }
    $devTask = "FairyPamLocalControlDev-$($Nonce.Substring(0, 24))"
    $wrongTask = "FairyPamLocalControlWrongSession-$($Nonce.Substring(0, 24))"
    $prodTaskOneName = "FairyPamLocalControlProdOne-$($Nonce.Substring(0, 24))"
    $prodTaskTwoName = "FairyPamLocalControlProdTwo-$($Nonce.Substring(0, 24))"
    $devProbeTaskName = "FairyPamLocalControlDevProbe-$($Nonce.Substring(0, 24))"
    $prodProbeTaskName = "FairyPamLocalControlProdProbe-$($Nonce.Substring(0, 24))"
    $devUnavailableTaskName = "FairyPamLocalControlDevAbsent-$($Nonce.Substring(0, 24))"
    $prodUnavailableTaskName = "FairyPamLocalControlProdAbsent-$($Nonce.Substring(0, 24))"
    if ((Get-ScheduledTask -TaskName $devTask -TaskPath '\' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $wrongTask -TaskPath '\' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $prodTaskOneName -TaskPath '\' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $prodTaskTwoName -TaskPath '\' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $devProbeTaskName -TaskPath '\' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $prodProbeTaskName -TaskPath '\' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $devUnavailableTaskName -TaskPath '\' -ErrorAction SilentlyContinue) -or
        (Get-ScheduledTask -TaskName $prodUnavailableTaskName -TaskPath '\' -ErrorAction SilentlyContinue)) {
        throw 'nonce-bound gate task already exists; explicit recovery is required'
    }
    $request = [ordered]@{
        schema_version = 1
        source_commit = $SourceCommit
        build_id = $BuildId
        nonce = $Nonce
        runner_sha256 = $RunnerSha256
        timeout_seconds = $TimeoutSeconds
        prod_agent = [ordered]@{ path = $prodAgent; sha256 = $ProdAgentSha256 }
        agentctl = [ordered]@{ path = $agentCtl; sha256 = $AgentCtlSha256 }
        dev_manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path (Split-Path -Parent ([string]$dev.slot)) 'dev-provision.json')).Hash.ToLowerInvariant()
        wrong_task_name = $wrongTask
    }
    Write-JsonFile (Join-Path $expectedStateRoot 'request.json') $request
    $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    if ($PSCommandPath.Contains('"') -or $expectedStateRoot.Contains('"')) { throw 'runner paths may not contain double quotes' }
    $gateTimeoutSeconds = ($TimeoutSeconds * 4) + 60
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Seconds $gateTimeoutSeconds)
    $devArguments = '--local-control-safe'
    $wrongArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Mode WrongSession -StateRoot `"$expectedStateRoot`""
    $devProbeArguments = "dev verify-status --build-id $BuildId --build-commit $SourceCommit"
    $prodProbeArguments = "dev verify-production --build-commit $SourceCommit"
    $devUnavailableArguments = 'dev verify-dev-unavailable'
    $prodUnavailableArguments = 'dev verify-production-unavailable'
    $powershellSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $powershell).Hash.ToLowerInvariant()
    $prodLaunchOne = Join-Path $expectedStateRoot 'prod-launch-one.ps1'
    $prodLaunchTwo = Join-Path $expectedStateRoot 'prod-launch-two.ps1'
    $prodLaunchOneSha256 = Write-ProductionLaunchScript $prodLaunchOne $prodAgent $environment
    $prodLaunchTwoSha256 = Write-ProductionLaunchScript $prodLaunchTwo $prodAgent $environment
    $prodOneArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$prodLaunchOne`""
    $prodTwoArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$prodLaunchTwo`""
    $devAction = New-ScheduledTaskAction -Execute ([string]$dev.agent) -Argument $devArguments -WorkingDirectory ([string]$dev.slot)
    $wrongAction = New-ScheduledTaskAction -Execute $powershell -Argument $wrongArguments -WorkingDirectory $AgentRoot
    $devProbeAction = New-ScheduledTaskAction -Execute $agentCtl -Argument $devProbeArguments -WorkingDirectory (Split-Path -Parent $agentCtl)
    $prodProbeAction = New-ScheduledTaskAction -Execute $agentCtl -Argument $prodProbeArguments -WorkingDirectory (Split-Path -Parent $agentCtl)
    $devUnavailableAction = New-ScheduledTaskAction -Execute $agentCtl -Argument $devUnavailableArguments -WorkingDirectory (Split-Path -Parent $agentCtl)
    $prodUnavailableAction = New-ScheduledTaskAction -Execute $agentCtl -Argument $prodUnavailableArguments -WorkingDirectory (Split-Path -Parent $agentCtl)
    $prodOneAction = New-ScheduledTaskAction -Execute $powershell -Argument $prodOneArguments -WorkingDirectory (Split-Path -Parent $prodAgent)
    $prodTwoAction = New-ScheduledTaskAction -Execute $powershell -Argument $prodTwoArguments -WorkingDirectory (Split-Path -Parent $prodAgent)
    $devPrincipal = New-ScheduledTaskPrincipal -UserId ([string]$dev.user_sid) -LogonType Interactive -RunLevel Limited
    $wrongPrincipal = New-ScheduledTaskPrincipal -UserId ([string]$dev.user_sid) -LogonType S4U -RunLevel Limited
    $recoveryIntent = [ordered]@{
        schema_version = 1
        nonce = $Nonce
        stage = 'prepared'
        prepared_at_unix_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        tasks = @(
            [ordered]@{ name = $devTask; execute = [string]$dev.agent; execute_sha256 = [string]$dev.manifest.agent_sha256; arguments = $devArguments; working_directory = [string]$dev.slot; user_id = [string]$dev.user_sid; logon_type = 'Interactive'; run_level = 'Limited'; owned_process_path = [string]$dev.agent },
            [ordered]@{ name = $wrongTask; execute = $powershell; execute_sha256 = $powershellSha256; arguments = $wrongArguments; working_directory = $AgentRoot; user_id = [string]$dev.user_sid; logon_type = 'S4U'; run_level = 'Limited'; owned_process_path = '' },
            [ordered]@{ name = $prodTaskOneName; execute = $powershell; execute_sha256 = $powershellSha256; arguments = $prodOneArguments; working_directory = (Split-Path -Parent $prodAgent); user_id = [string]$dev.user_sid; logon_type = 'Interactive'; run_level = 'Limited'; owned_process_path = $prodAgent; launch_script_path = $prodLaunchOne; launch_script_sha256 = $prodLaunchOneSha256 },
            [ordered]@{ name = $prodTaskTwoName; execute = $powershell; execute_sha256 = $powershellSha256; arguments = $prodTwoArguments; working_directory = (Split-Path -Parent $prodAgent); user_id = [string]$dev.user_sid; logon_type = 'Interactive'; run_level = 'Limited'; owned_process_path = $prodAgent; launch_script_path = $prodLaunchTwo; launch_script_sha256 = $prodLaunchTwoSha256 },
            [ordered]@{ name = $devProbeTaskName; execute = $agentCtl; execute_sha256 = $AgentCtlSha256; arguments = $devProbeArguments; working_directory = (Split-Path -Parent $agentCtl); user_id = [string]$dev.user_sid; logon_type = 'Interactive'; run_level = 'Limited'; owned_process_path = '' },
            [ordered]@{ name = $prodProbeTaskName; execute = $agentCtl; execute_sha256 = $AgentCtlSha256; arguments = $prodProbeArguments; working_directory = (Split-Path -Parent $agentCtl); user_id = [string]$dev.user_sid; logon_type = 'Interactive'; run_level = 'Limited'; owned_process_path = '' },
            [ordered]@{ name = $devUnavailableTaskName; execute = $agentCtl; execute_sha256 = $AgentCtlSha256; arguments = $devUnavailableArguments; working_directory = (Split-Path -Parent $agentCtl); user_id = [string]$dev.user_sid; logon_type = 'Interactive'; run_level = 'Limited'; owned_process_path = '' },
            [ordered]@{ name = $prodUnavailableTaskName; execute = $agentCtl; execute_sha256 = $AgentCtlSha256; arguments = $prodUnavailableArguments; working_directory = (Split-Path -Parent $agentCtl); user_id = [string]$dev.user_sid; logon_type = 'Interactive'; run_level = 'Limited'; owned_process_path = '' }
        )
        processes = @()
    }
    $devIntentTask = $recoveryIntent.tasks[0]
    $wrongIntentTask = $recoveryIntent.tasks[1]
    $prodOneIntentTask = $recoveryIntent.tasks[2]
    $prodTwoIntentTask = $recoveryIntent.tasks[3]
    $devProbeIntentTask = $recoveryIntent.tasks[4]
    $prodProbeIntentTask = $recoveryIntent.tasks[5]
    $devUnavailableIntentTask = $recoveryIntent.tasks[6]
    $prodUnavailableIntentTask = $recoveryIntent.tasks[7]
    Write-RecoveryIntent $expectedStateRoot $recoveryIntent
    $passed = $false
    try {
        Register-ScheduledTask -TaskName $wrongTask -Action $wrongAction -Principal $wrongPrincipal -Settings $settings | Out-Null
        Register-ScheduledTask -TaskName $devTask -Action $devAction -Principal $devPrincipal -Settings $settings | Out-Null
        Register-ScheduledTask -TaskName $prodTaskOneName -Action $prodOneAction -Principal $devPrincipal -Settings $settings | Out-Null
        Register-ScheduledTask -TaskName $prodTaskTwoName -Action $prodTwoAction -Principal $devPrincipal -Settings $settings | Out-Null
        Register-ScheduledTask -TaskName $devProbeTaskName -Action $devProbeAction -Principal $devPrincipal -Settings $settings | Out-Null
        Register-ScheduledTask -TaskName $prodProbeTaskName -Action $prodProbeAction -Principal $devPrincipal -Settings $settings | Out-Null
        Register-ScheduledTask -TaskName $devUnavailableTaskName -Action $devUnavailableAction -Principal $devPrincipal -Settings $settings | Out-Null
        Register-ScheduledTask -TaskName $prodUnavailableTaskName -Action $prodUnavailableAction -Principal $devPrincipal -Settings $settings | Out-Null
        $recoveryIntent.stage = 'registered'
        Write-RecoveryIntent $expectedStateRoot $recoveryIntent
        Invoke-OrdinaryGate $expectedStateRoot $request $environment $dev $devIntentTask $prodOneIntentTask $prodTwoIntentTask $devProbeIntentTask $prodProbeIntentTask $devUnavailableIntentTask $prodUnavailableIntentTask $wrongIntentTask
        $passed = $true
    } finally {
        $cleanupErrors = @()
        try { Remove-IntentTask $prodOneIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        try { Remove-IntentTask $prodTwoIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        try { Remove-IntentTask $devIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        try { Remove-IntentTask $devProbeIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        try { Remove-IntentTask $prodProbeIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        try { Remove-IntentTask $devUnavailableIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        try { Remove-IntentTask $prodUnavailableIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        try { Remove-IntentTask $wrongIntentTask } catch { $cleanupErrors += $_.Exception.Message }
        if (-not $passed -or $cleanupErrors.Count -ne 0) {
            Write-JsonFile (Join-Path $expectedStateRoot 'recovery.json') ([ordered]@{
                schema_version = 1
                source_commit = $SourceCommit
                build_id = $BuildId
                nonce = $Nonce
                runner_sha256 = $RunnerSha256
                cleanup_errors = $cleanupErrors
            })
            if ($cleanupErrors.Count -ne 0) { throw ($cleanupErrors -join '; ') }
        }
    }
    if (-not $passed) { throw 'local-control safe gate failed; nonce-bound recovery state was retained' }
    Remove-Item -Recurse -Force -LiteralPath $expectedStateRoot
    if (Test-Path -LiteralPath $expectedStateRoot) { throw 'nonce-bound temporary state cleanup was incomplete' }
    Write-JsonFile $ReceiptPath ([ordered]@{
        schema_version = 1
        gate = 'RUST-CLI-LOCAL-CONTROL-SAFE'
        status = 'passed'
        source_commit = $SourceCommit
        build_id = $BuildId
        nonce = $Nonce
        runner_sha256 = $RunnerSha256
        build_receipt_sha256 = $BuildReceiptSha256
        production_environment_sha256 = $ProdEnvironmentSha256
        binaries = [ordered]@{
            production_agent_sha256 = $ProdAgentSha256
            development_agent_sha256 = [string]$dev.manifest.agent_sha256
            agentctl_sha256 = $AgentCtlSha256
        }
        assertions = [ordered]@{
            local_control_only = $true
            exact_machine_errors = $true
            wrong_session_rejected = $true
            production_development_isolation = $true
            canonical_dev_task = $true
        }
        cleanup = [ordered]@{
            owned_processes = $true
            nonce_tasks = $true
            temporary_state = $true
            production_pipe_unreachable = $true
            development_pipe_unreachable = $true
        }
        created_at = [DateTimeOffset]::UtcNow.ToString('O')
    })
}

function Invoke-Authority {
    $slot = Split-Path -Parent $PSCommandPath
    $root = Split-Path -Parent $slot
    $expectedAuthorityRoot = [IO.Path]::GetFullPath((Join-Path $root 'state\local-control'))
    if ([string]::IsNullOrWhiteSpace($AuthorityRoot) -or
        -not [IO.Path]::IsPathRooted($AuthorityRoot) -or
        [IO.Path]::GetFullPath($AuthorityRoot) -ine $expectedAuthorityRoot) {
        throw 'fixed authority task root is absent or does not match the protected Dev provision'
    }
    $authorityRoot = Get-VerifiedDirectory $expectedAuthorityRoot 'local_control_authority_root'
    $manifestPath = Join-Path $root 'dev-provision.json'
    $manifest = Read-JsonFile (Assert-ProtectedFile $manifestPath 'dev_provision_manifest')
    $runner = Get-VerifiedFile $PSCommandPath ([string]$manifest.local_control_runner_sha256) 'embedded_local_control_runner'
    if ([IO.Path]::GetFullPath([string]$manifest.local_control_runner_path) -ine $runner) {
        throw 'embedded local-control runner path is not canonical'
    }
    $request = Read-JsonFile (Assert-ProtectedFile (Join-Path $authorityRoot 'request.json') 'local_control_authority_request')
    $claimPath = Join-Path $authorityRoot 'request.claim.json'
    $claim = Read-JsonFile (Assert-ProtectedFile $claimPath 'local_control_authority_claim')
    if (@($claim.PSObject.Properties.Name | Sort-Object) -join ',' -cne 'build_id,nonce,runner_sha256,schema_version,source_commit' -or
        [int]$claim.schema_version -ne 1 -or
        [string]$claim.source_commit -cne [string]$request.source_commit -or
        [string]$claim.build_id -cne [string]$request.build_id -or
        [string]$claim.nonce -cne [string]$request.nonce -or
        [string]$claim.runner_sha256 -cne [string]$request.runner_sha256) {
        throw 'authority claim does not bind the protected request'
    }
    if ([string]$request.build_id -cne [string]$manifest.build_id -or
        [string]$request.runner_sha256 -cne [string]$manifest.local_control_runner_sha256) {
        throw 'authority request does not bind the protected provision'
    }
    $receiptPath = Join-Path $authorityRoot "receipts\local-control-safe-receipt-$([string]$request.nonce).json"
    & $runner -Mode Run -SourceCommit ([string]$request.source_commit) -BuildId ([string]$request.build_id) -Nonce ([string]$request.nonce) -RunnerSha256 ([string]$request.runner_sha256) -ProdAgentPath ([string]$request.prod_agent_path) -ProdAgentSha256 ([string]$request.prod_agent_sha256) -AgentCtlPath ([string]$request.agentctl_path) -AgentCtlSha256 ([string]$request.agentctl_sha256) -ProdEnvironmentPath ([string]$request.prod_environment_path) -ProdEnvironmentSha256 ([string]$request.prod_environment_sha256) -BuildReceiptPath ([string]$request.build_receipt_path) -BuildReceiptSha256 ([string]$request.build_receipt_sha256) -ReceiptPath $receiptPath -AuthorityRoot $authorityRoot -TimeoutSeconds ([int]$request.timeout_seconds)
    if ($LASTEXITCODE -ne 0) { throw "fixed authority runner failed with exit code $LASTEXITCODE" }
    Remove-Item -Force -LiteralPath $claimPath
    if (Test-Path -LiteralPath $claimPath) { throw 'authority claim cleanup failed' }
}

switch ($Mode) {
    'Authority' { Invoke-Authority }
    'Run' { Invoke-Gate }
    'WrongSession' { Invoke-WrongSession $StateRoot }
}
