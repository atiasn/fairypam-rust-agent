param(
    [Parameter(Mandatory=$true)][ValidateSet('install','repair','uninstall')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$SourceRoot,
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot,
    [Parameter(Mandatory=$true)][string]$UserRoot,
    [Parameter(Mandatory=$true)][string]$AuthorizedUserSid,
    [Parameter(Mandatory=$true)][string]$BuildId,
    [Parameter(Mandatory=$true)][string]$SuiteVersion,
    [Parameter(Mandatory=$true)][string]$ManifestSha256,
    [Parameter(Mandatory=$true)][ValidateSet('true','false')][string]$PreserveUserData,
    [Parameter(Mandatory=$true)][string]$SecurityPolicyPath,
    [Parameter(Mandatory=$true)][string]$SecurityPolicySha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$AgentTask = 'FairyPam Agent'
$UiTask = 'FairyPam Agent UI'
$UpdateTask = 'FairyPam Agent Update'
$System32 = [Environment]::SystemDirectory
if ([string]::IsNullOrWhiteSpace($System32) -or -not [IO.Path]::IsPathRooted($System32)) { throw 'trusted System32 path is unavailable' }
$System32 = [IO.Path]::GetFullPath($System32)
$system32Item = Get-Item -Force -LiteralPath $System32
if (-not $system32Item.PSIsContainer -or ($system32Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'trusted System32 path is invalid' }
$Schtasks = Join-Path $System32 'schtasks.exe'
$Icacls = Join-Path $System32 'icacls.exe'
$Reg = Join-Path $System32 'reg.exe'
$TaskStoreRoot = Join-Path $System32 'Tasks'
foreach ($tool in @($Schtasks,$Icacls,$Reg)) {
    $item = Get-Item -Force -LiteralPath $tool
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "trusted System32 tool is invalid: $tool" }
}
$taskStoreItem = Get-Item -Force -LiteralPath $TaskStoreRoot
if (-not $taskStoreItem.PSIsContainer -or ($taskStoreItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'trusted task store is invalid' }
$Active = Join-Path $InstallRoot 'active'
$Backup = Join-Path $InstallRoot ('.rollback-' + $BuildId)
$Stage = Join-Path $InstallRoot ('.staging-' + $BuildId)
$AuditRoot = Join-Path $DataRoot 'audit'
$StatePath = Join-Path $DataRoot 'install-state.json'
$TaskBackupRoot = Join-Path $DataRoot ('task-backup-' + $BuildId)
$RegistryBackup = Join-Path $TaskBackupRoot 'uninstall.reg'
$PolicyBackup = Join-Path $TaskBackupRoot 'security-policy.json'
$StateBackup = Join-Path $TaskBackupRoot 'install-state.json'
$installRootExisted = Test-Path -LiteralPath $InstallRoot
$dataRootExisted = Test-Path -LiteralPath $DataRoot
$userRootExisted = Test-Path -LiteralPath $UserRoot
$stateExisted = Test-Path -LiteralPath $StatePath -PathType Leaf

function Invoke-Native([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Assert-AbsoluteProtectedPath([string]$Path, [string]$Root) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw "path is not absolute: $Path" }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (-not $full.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase) -and $full -cne $rootFull) {
        throw "path escaped protected root: $Path"
    }
}

function New-AclRule([string]$Sid, [Security.AccessControl.FileSystemRights]$Rights, [Security.AccessControl.InheritanceFlags]$Inheritance) {
    return [pscustomobject]@{Sid=$Sid;Rights=$Rights;Inheritance=$Inheritance}
}

function New-ExactSecurity([bool]$Directory, [string]$OwnerSid, [object[]]$Rules) {
    $security = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($OwnerSid))
    $security.SetAccessRuleProtection($true,$false)
    foreach ($rule in $Rules) {
        $accessRule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($rule.Sid),
            $rule.Rights,
            $rule.Inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($accessRule)
    }
    return $security
}

function Get-OwnerSid([Security.AccessControl.FileSystemSecurity]$Acl) {
    if ($Acl.Owner -match '^S-1-') { return $Acl.Owner }
    return ([Security.Principal.NTAccount]::new($Acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-AclRuleFingerprint([object]$Rule) {
    return '{0}|{1}|{2}|{3}|{4}|{5}' -f $Rule.IdentityReference.Value,[int64]$Rule.FileSystemRights,[int]$Rule.InheritanceFlags,[int]$Rule.PropagationFlags,[int]$Rule.AccessControlType,[bool]$Rule.IsInherited
}

function Test-ExactPathSecurity([string]$Path, [string]$OwnerSid, [object[]]$Rules) {
    $item = Get-Item -Force -LiteralPath $Path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "path is a reparse point: $Path" }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected -or (Get-OwnerSid $acl) -cne $OwnerSid) { return $false }
    $actual = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object { Get-AclRuleFingerprint $_ } | Sort-Object)
    $expected = @($Rules | ForEach-Object {
        Get-AclRuleFingerprint ([pscustomobject]@{
            IdentityReference=[Security.Principal.SecurityIdentifier]::new($_.Sid)
            FileSystemRights=$_.Rights
            InheritanceFlags=$_.Inheritance
            PropagationFlags=[Security.AccessControl.PropagationFlags]::None
            AccessControlType=[Security.AccessControl.AccessControlType]::Allow
            IsInherited=$false
        })
    } | Sort-Object)
    return -not (Compare-Object $actual $expected)
}

function Assert-ExactPathSecurity([string]$Path, [string]$OwnerSid, [object[]]$Rules) {
    if (-not (Test-ExactPathSecurity $Path $OwnerSid $Rules)) { throw "path owner or DACL is not exact: $Path" }
}

function Set-ExactPathSecurity([string]$Path, [string]$OwnerSid, [object[]]$Rules) {
    $item = Get-Item -Force -LiteralPath $Path
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "path is a reparse point: $Path" }
    Invoke-Native $Icacls @($Path,'/setowner',('*' + $OwnerSid))
    $security = New-ExactSecurity $item.PSIsContainer $OwnerSid $Rules
    $item.SetAccessControl($security)
    Assert-ExactPathSecurity $Path $OwnerSid $Rules
}

function Ensure-ExactDirectory([string]$Path, [string]$CreationOwnerSid, [string]$FinalOwnerSid, [object[]]$Rules) {
    if (Test-Path -LiteralPath $Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "directory path is occupied by a file: $Path" }
        Assert-ExactPathSecurity $Path $FinalOwnerSid $Rules
        return
    }
    $creationSecurity = New-ExactSecurity $true $CreationOwnerSid $Rules
    [IO.Directory]::CreateDirectory($Path,$creationSecurity) | Out-Null
    if (Test-ExactPathSecurity $Path $FinalOwnerSid $Rules) { return }
    Assert-ExactPathSecurity $Path $CreationOwnerSid $Rules
    Set-ExactPathSecurity $Path $FinalOwnerSid $Rules
}

$directoryInheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$SystemInstallDirectoryRules = @(
    (New-AclRule 'S-1-5-18' ([Security.AccessControl.FileSystemRights]::FullControl) $directoryInheritance),
    (New-AclRule 'S-1-5-32-544' ([Security.AccessControl.FileSystemRights]::FullControl) $directoryInheritance),
    (New-AclRule 'S-1-5-32-545' ([Security.AccessControl.FileSystemRights]::ReadAndExecute) $directoryInheritance)
)
$SystemDataDirectoryRules = @(
    (New-AclRule 'S-1-5-18' ([Security.AccessControl.FileSystemRights]::FullControl) $directoryInheritance),
    (New-AclRule 'S-1-5-32-544' ([Security.AccessControl.FileSystemRights]::FullControl) $directoryInheritance)
)
$UserDirectoryRules = @(
    (New-AclRule 'S-1-5-18' ([Security.AccessControl.FileSystemRights]::FullControl) $directoryInheritance),
    (New-AclRule $AuthorizedUserSid ([Security.AccessControl.FileSystemRights]::FullControl) $directoryInheritance)
)
$SystemInstallFileRules = @(
    (New-AclRule 'S-1-5-18' ([Security.AccessControl.FileSystemRights]::FullControl) ([Security.AccessControl.InheritanceFlags]::None)),
    (New-AclRule 'S-1-5-32-544' ([Security.AccessControl.FileSystemRights]::FullControl) ([Security.AccessControl.InheritanceFlags]::None)),
    (New-AclRule 'S-1-5-32-545' ([Security.AccessControl.FileSystemRights]::ReadAndExecute) ([Security.AccessControl.InheritanceFlags]::None))
)
$SystemDataFileRules = @(
    (New-AclRule 'S-1-5-18' ([Security.AccessControl.FileSystemRights]::FullControl) ([Security.AccessControl.InheritanceFlags]::None)),
    (New-AclRule 'S-1-5-32-544' ([Security.AccessControl.FileSystemRights]::FullControl) ([Security.AccessControl.InheritanceFlags]::None))
)
$TaskFileRules = @(
    (New-AclRule 'S-1-5-18' ([Security.AccessControl.FileSystemRights]::FullControl) ([Security.AccessControl.InheritanceFlags]::None)),
    (New-AclRule 'S-1-5-32-544' ([Security.AccessControl.FileSystemRights]::FullControl) ([Security.AccessControl.InheritanceFlags]::None)),
    (New-AclRule $AuthorizedUserSid ([Security.AccessControl.FileSystemRights]::ReadAndExecute) ([Security.AccessControl.InheritanceFlags]::None))
)

function Assert-ExactTreeSecurity([string]$Root, [object[]]$DirectoryRules, [object[]]$FileRules) {
    Assert-ExactPathSecurity $Root 'S-1-5-18' $DirectoryRules
    foreach ($item in @(Get-ChildItem -Force -Recurse -LiteralPath $Root)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "path is a reparse point: $($item.FullName)" }
        Assert-ExactPathSecurity $item.FullName 'S-1-5-18' $(if ($item.PSIsContainer) { $DirectoryRules } else { $FileRules })
    }
}

function Set-ExactTreeSecurity([string]$Root, [object[]]$DirectoryRules, [object[]]$FileRules) {
    Set-ExactPathSecurity $Root 'S-1-5-18' $DirectoryRules
    foreach ($item in @(Get-ChildItem -Force -Recurse -LiteralPath $Root)) {
        Set-ExactPathSecurity $item.FullName 'S-1-5-18' $(if ($item.PSIsContainer) { $DirectoryRules } else { $FileRules })
    }
    Assert-ExactTreeSecurity $Root $DirectoryRules $FileRules
}

function Remove-ExactTree([string]$Root, [object[]]$DirectoryRules, [object[]]$FileRules) {
    if (-not (Test-Path -LiteralPath $Root)) { return }
    Assert-ExactTreeSecurity $Root $DirectoryRules $FileRules
    Remove-Item -Recurse -Force -LiteralPath $Root
}

function Assert-StagedSuite([string]$Root) {
    $manifestPath = Join-Path $Root 'BUILD-MANIFEST.json'
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ManifestSha256) { throw 'staged manifest changed after Rust verification' }
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $declared = @($manifest.members.PSObject.Properties.Name | Sort-Object)
    $actual = @(Get-ChildItem -File -Recurse -LiteralPath $Root | ForEach-Object { $_.FullName.Substring($Root.Length + 1).Replace('\','/') } | Where-Object { $_ -cne 'BUILD-MANIFEST.json' } | Sort-Object)
    if (Compare-Object $declared $actual) { throw 'staged suite member set changed after Rust verification' }
    foreach ($name in $declared) {
        $file = Get-Item -LiteralPath (Join-Path $Root $name)
        $expected = $manifest.members.$name
        if ($file.Length -ne [long]$expected.size_bytes -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$expected.sha256) { throw "staged suite member changed: $name" }
    }
}

function Save-Task([string]$Name) {
    Ensure-ExactDirectory $TaskBackupRoot 'S-1-5-32-544' 'S-1-5-18' $SystemDataDirectoryRules
    $path = Join-Path $TaskBackupRoot (($Name -replace '[^A-Za-z0-9]','_') + '.xml')
    if (Test-Path -LiteralPath $path) { Assert-ExactPathSecurity $path 'S-1-5-18' $SystemDataFileRules }
    $output = & $Schtasks /Query /TN $Name /XML 2>$null
    if ($LASTEXITCODE -eq 0) {
        [IO.File]::WriteAllLines($path, [string[]]$output, [Text.UTF8Encoding]::new($false))
        Set-ExactPathSecurity $path 'S-1-5-18' $SystemDataFileRules
    }
}

function Protect-TaskAcl([string]$Name) {
    $path = Join-Path $TaskStoreRoot $Name
    Assert-AbsoluteProtectedPath $path $TaskStoreRoot
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "registered task file is missing: $Name" }
    Set-ExactPathSecurity $path 'S-1-5-18' $TaskFileRules
}

function Restore-Tasks {
    foreach ($name in @($AgentTask,$UiTask,$UpdateTask)) {
        & $Schtasks /Delete /F /TN $name 2>$null | Out-Null
        $path = Join-Path $TaskBackupRoot (($name -replace '[^A-Za-z0-9]','_') + '.xml')
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Assert-ExactPathSecurity $path 'S-1-5-18' $SystemDataFileRules
            Invoke-Native $Schtasks @('/Create','/F','/TN',$name,'/XML',$path)
            Protect-TaskAcl $name
        }
    }
}

function New-TaskXml([string]$Path, [string]$RunLevel, [string]$Command, [string]$Arguments, [bool]$LogonTrigger) {
    $escapedCommand = [Security.SecurityElement]::Escape($Command)
    $escapedArguments = [Security.SecurityElement]::Escape($Arguments)
    $trigger = if ($LogonTrigger) { "<LogonTrigger><Enabled>true</Enabled><UserId>$AuthorizedUserSid</UserId></LogonTrigger>" } else { '' }
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>FairyPam</Author></RegistrationInfo>
  <Triggers>$trigger</Triggers>
  <Principals><Principal id="Author"><UserId>$AuthorizedUserSid</UserId><LogonType>InteractiveToken</LogonType><RunLevel>$RunLevel</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority></Settings>
  <Actions Context="Author"><Exec><Command>$escapedCommand</Command><Arguments>$escapedArguments</Arguments><WorkingDirectory>$([Security.SecurityElement]::Escape($Active))</WorkingDirectory></Exec></Actions>
</Task>
"@
    if (Test-Path -LiteralPath $Path) { Assert-ExactPathSecurity $Path 'S-1-5-18' $SystemDataFileRules }
    [IO.File]::WriteAllText($Path, $xml, [Text.Encoding]::Unicode)
    Set-ExactPathSecurity $Path 'S-1-5-18' $SystemDataFileRules
}

function Register-FixedTasks {
    $taskRoot = Join-Path $DataRoot 'tasks'
    Ensure-ExactDirectory $taskRoot 'S-1-5-32-544' 'S-1-5-18' $SystemDataDirectoryRules
    $agentXml = Join-Path $taskRoot 'agent.xml'
    $uiXml = Join-Path $taskRoot 'ui.xml'
    $updateXml = Join-Path $taskRoot 'update.xml'
    New-TaskXml $agentXml 'HighestAvailable' (Join-Path $Active 'fairypam-agent.exe') '--run' $true
    New-TaskXml $uiXml 'LeastPrivilege' (Join-Path $Active 'fairypam-agent-ui.exe') '' $true
    $updateArgs = 'apply --security-policy "' + (Join-Path $DataRoot 'security-policy.json') + '"'
    New-TaskXml $updateXml 'HighestAvailable' (Join-Path $Active 'fairypam-agent-updater.exe') $updateArgs $false
    Assert-TransactionRoots
    $script:tasksTouched = $true
    Invoke-Native $Schtasks @('/Create','/F','/TN',$AgentTask,'/XML',$agentXml)
    Invoke-Native $Schtasks @('/Create','/F','/TN',$UiTask,'/XML',$uiXml)
    Invoke-Native $Schtasks @('/Create','/F','/TN',$UpdateTask,'/XML',$updateXml)
    foreach ($name in @($AgentTask,$UiTask,$UpdateTask)) { Protect-TaskAcl $name }
}

function Stop-SuiteSafely {
    $agentctl = Join-Path $Active 'fairypam-agentctl.exe'
    $agent = @(Get-Process -Name 'fairypam-agent' -ErrorAction SilentlyContinue)
    if ($agent.Count -gt 0) { Invoke-Native $agentctl @('maintenance-prepare-update','--timeout-ms','15000') }
    & $Schtasks /End /TN $AgentTask 2>$null | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (@(Get-Process -Name 'fairypam-agent','fairypam-agent-guardian' -ErrorAction SilentlyContinue).Count -gt 0) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'suite did not reach a safe stopped state' }
        Start-Sleep -Milliseconds 100
    }
}

function Assert-GuardianHealth([string]$Root) {
    $guardian = Join-Path $Root 'fairypam-agent-guardian.exe'
    $requests = @(
        (@{type='register_agent';agent_pid=$PID;heartbeat_timeout_ms=5000} | ConvertTo-Json -Compress),
        (@{type='heartbeat';sequence=1} | ConvertTo-Json -Compress),
        (@{type='status'} | ConvertTo-Json -Compress)
    )
    $responses = @($requests | & $guardian | ForEach-Object { $_ | ConvertFrom-Json })
    if ($LASTEXITCODE -ne 0 -or $responses.Count -ne 3 -or [string]$responses[2].type -cne 'status' -or [int]$responses[2].agent_pid -ne $PID -or [long]$responses[2].last_sequence -ne 1) { throw 'Guardian heartbeat health check failed' }
}

function Write-Audit([string]$Operation, [string]$Result) {
    Ensure-ExactDirectory $AuditRoot 'S-1-5-32-544' 'S-1-5-18' $SystemDataDirectoryRules
    $receipt = [ordered]@{schema_version=1;operation=$Operation;result=$Result;build_id=$BuildId;suite_version=$SuiteVersion;manifest_sha256=$ManifestSha256;authorized_user_sid=$AuthorizedUserSid;created_at=[DateTimeOffset]::UtcNow.ToString('O')}
    $path = Join-Path $AuditRoot (([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()) + '-' + $Operation + '.json')
    if (Test-Path -LiteralPath $path) { Assert-ExactPathSecurity $path 'S-1-5-18' $SystemDataFileRules }
    [IO.File]::WriteAllText($path, (ConvertTo-Json $receipt -Compress), [Text.UTF8Encoding]::new($false))
    Set-ExactPathSecurity $path 'S-1-5-18' $SystemDataFileRules
}

foreach ($path in @($SourceRoot,$InstallRoot,$DataRoot,$UserRoot,$SecurityPolicyPath)) {
    if (-not [IO.Path]::IsPathRooted($path)) { throw "all lifecycle paths must be absolute: $path" }
}
if ($AuthorizedUserSid -notmatch '^S-1-(?:\d+-){1,14}\d+$') { throw 'authorized user SID is invalid' }
Assert-AbsoluteProtectedPath $Active $InstallRoot
Assert-AbsoluteProtectedPath $Stage $InstallRoot
Assert-AbsoluteProtectedPath $Backup $InstallRoot
$installVendorRoot = Split-Path -Parent $InstallRoot
$dataVendorRoot = Split-Path -Parent $DataRoot
$userVendorRoot = Split-Path -Parent $UserRoot

function Assert-TransactionRoots {
    Assert-ExactPathSecurity $installVendorRoot 'S-1-5-18' $SystemInstallDirectoryRules
    Assert-ExactPathSecurity $dataVendorRoot 'S-1-5-18' $SystemDataDirectoryRules
    Assert-ExactPathSecurity $userVendorRoot $AuthorizedUserSid $UserDirectoryRules
    Assert-ExactPathSecurity $InstallRoot 'S-1-5-18' $SystemInstallDirectoryRules
    Assert-ExactPathSecurity $DataRoot 'S-1-5-18' $SystemDataDirectoryRules
    Assert-ExactPathSecurity $UserRoot $AuthorizedUserSid $UserDirectoryRules
}

if ($Mode -eq 'uninstall') {
    Assert-TransactionRoots
    Assert-ExactTreeSecurity $Active $SystemInstallDirectoryRules $SystemInstallFileRules
    Stop-SuiteSafely
    Assert-TransactionRoots
    foreach ($task in @($UpdateTask,$UiTask,$AgentTask)) { & $Schtasks /Delete /F /TN $task 2>$null | Out-Null }
    & $Reg delete 'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPamAgent' /f 2>$null | Out-Null
    Assert-TransactionRoots
    Remove-Item -Recurse -Force -LiteralPath $InstallRoot
    Remove-Item -Recurse -Force -LiteralPath $DataRoot
    if ($PreserveUserData -eq 'false') { Remove-Item -Recurse -Force -LiteralPath $UserRoot }
    return
}

$committed = $false
$oldActive = Test-Path -LiteralPath $Active
$activeMovedToBackup = $false
$newActiveInstalled = $false
$tasksTouched = $false
$registryTouched = $false
$policyTouched = $false
$stateTouched = $false
try {
    Ensure-ExactDirectory $installVendorRoot 'S-1-5-32-544' 'S-1-5-18' $SystemInstallDirectoryRules
    Ensure-ExactDirectory $dataVendorRoot 'S-1-5-32-544' 'S-1-5-18' $SystemDataDirectoryRules
    Ensure-ExactDirectory $userVendorRoot $AuthorizedUserSid $AuthorizedUserSid $UserDirectoryRules
    Ensure-ExactDirectory $InstallRoot 'S-1-5-32-544' 'S-1-5-18' $SystemInstallDirectoryRules
    Ensure-ExactDirectory $DataRoot 'S-1-5-32-544' 'S-1-5-18' $SystemDataDirectoryRules
    Ensure-ExactDirectory $UserRoot $AuthorizedUserSid $AuthorizedUserSid $UserDirectoryRules
    Assert-TransactionRoots
    if ($oldActive) { Assert-ExactTreeSecurity $Active $SystemInstallDirectoryRules $SystemInstallFileRules }
    $installedPolicy = Join-Path $DataRoot 'security-policy.json'
    $installedPolicyExisted = Test-Path -LiteralPath $installedPolicy -PathType Leaf
    if ($installedPolicyExisted) { Assert-ExactPathSecurity $installedPolicy 'S-1-5-18' $SystemDataFileRules }
    if ($stateExisted) { Assert-ExactPathSecurity $StatePath 'S-1-5-18' $SystemDataFileRules }
    foreach ($task in @($AgentTask,$UiTask,$UpdateTask)) { Save-Task $task }
    & $Reg export 'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPamAgent' $RegistryBackup /y 2>$null | Out-Null
    if (Test-Path -LiteralPath $RegistryBackup -PathType Leaf) { Set-ExactPathSecurity $RegistryBackup 'S-1-5-18' $SystemDataFileRules }
    if ($installedPolicyExisted) {
        Copy-Item -Force -LiteralPath $installedPolicy -Destination $PolicyBackup
        Set-ExactPathSecurity $PolicyBackup 'S-1-5-18' $SystemDataFileRules
    }
    if ($stateExisted) {
        Copy-Item -Force -LiteralPath $StatePath -Destination $StateBackup
        Set-ExactPathSecurity $StateBackup 'S-1-5-18' $SystemDataFileRules
    }
    Assert-TransactionRoots
    if ([IO.Path]::GetFullPath($SecurityPolicyPath) -cne [IO.Path]::GetFullPath($installedPolicy)) {
        $policyTouched = $true
        Copy-Item -Force -LiteralPath $SecurityPolicyPath -Destination $installedPolicy
    }
    if ((Get-FileHash -LiteralPath $installedPolicy -Algorithm SHA256).Hash.ToLowerInvariant() -cne $SecurityPolicySha256) { throw 'security policy changed during the install transaction' }
    Set-ExactPathSecurity $installedPolicy 'S-1-5-18' $SystemDataFileRules
    Assert-TransactionRoots
    $state = [ordered]@{schema_version=1;build_id=$BuildId;suite_version=$SuiteVersion;manifest_sha256=$ManifestSha256;security_policy_sha256=$SecurityPolicySha256;authorized_user_sid=$AuthorizedUserSid}
    $stateTouched = $true
    [IO.File]::WriteAllText($StatePath, (ConvertTo-Json $state -Compress), [Text.UTF8Encoding]::new($false))
    Set-ExactPathSecurity $StatePath 'S-1-5-18' $SystemDataFileRules
    Assert-TransactionRoots
    Remove-ExactTree $Stage $SystemInstallDirectoryRules $SystemInstallFileRules
    Remove-ExactTree $Backup $SystemInstallDirectoryRules $SystemInstallFileRules
    Ensure-ExactDirectory $Stage 'S-1-5-32-544' 'S-1-5-18' $SystemInstallDirectoryRules
    foreach ($entry in @(Get-ChildItem -Force -LiteralPath $SourceRoot)) { Copy-Item -Recurse -Force -LiteralPath $entry.FullName -Destination $Stage }
    Assert-StagedSuite $Stage
    Set-ExactTreeSecurity $Stage $SystemInstallDirectoryRules $SystemInstallFileRules
    if ($oldActive) {
        Stop-SuiteSafely
        Assert-ExactTreeSecurity $Active $SystemInstallDirectoryRules $SystemInstallFileRules
        Move-Item -LiteralPath $Active -Destination $Backup
        $activeMovedToBackup = $true
    }
    Move-Item -LiteralPath $Stage -Destination $Active
    $newActiveInstalled = $true
    Assert-ExactTreeSecurity $Active $SystemInstallDirectoryRules $SystemInstallFileRules
    Register-FixedTasks
    Invoke-Native $Schtasks @('/Run','/TN',$AgentTask)
    Start-Sleep -Seconds 2
    Invoke-Native (Join-Path $Active 'fairypam-agentctl.exe') @('doctor')
    Assert-GuardianHealth $Active
    Assert-TransactionRoots
    $registryTouched = $true
    Invoke-Native $Reg @('add','HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPamAgent','/f','/v','DisplayName','/d','FairyPam Agent Suite')
    Invoke-Native $Reg @('add','HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPamAgent','/f','/v','DisplayVersion','/d',$SuiteVersion)
    $setup = Join-Path $Active 'FairyPamAgentSetup.exe'
    $uninstall = '"' + $setup + '" uninstall'
    $repair = '"' + $setup + '" repair'
    Invoke-Native $Reg @('add','HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPamAgent','/f','/v','UninstallString','/d',$uninstall)
    Invoke-Native $Reg @('add','HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPamAgent','/f','/v','ModifyPath','/d',$repair)
    Remove-ExactTree $Backup $SystemInstallDirectoryRules $SystemInstallFileRules
    Remove-ExactTree $TaskBackupRoot $SystemDataDirectoryRules $SystemDataFileRules
    $committed = $true
    Write-Audit $Mode 'committed'
    Invoke-Native $Schtasks @('/Run','/TN',$UiTask)
}
finally {
    if (-not $committed) {
        & $Schtasks /End /TN $AgentTask 2>$null | Out-Null
        if ($tasksTouched) { try { Restore-Tasks } catch { Write-Warning ("task rollback failed: " + $_.Exception.Message) } }
        if ($newActiveInstalled) { Remove-ExactTree $Active $SystemInstallDirectoryRules $SystemInstallFileRules }
        Remove-ExactTree $Stage $SystemInstallDirectoryRules $SystemInstallFileRules
        if ($activeMovedToBackup -and (Test-Path -LiteralPath $Backup)) {
            Assert-ExactTreeSecurity $Backup $SystemInstallDirectoryRules $SystemInstallFileRules
            Move-Item -LiteralPath $Backup -Destination $Active
        }
        if ($registryTouched) {
            & $Reg delete 'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\FairyPamAgent' /f 2>$null | Out-Null
            if (Test-Path -LiteralPath $RegistryBackup -PathType Leaf) {
                Assert-ExactPathSecurity $RegistryBackup 'S-1-5-18' $SystemDataFileRules
                & $Reg import $RegistryBackup | Out-Null
            }
        }
        if ($policyTouched -and (Test-Path -LiteralPath $PolicyBackup -PathType Leaf)) {
            Assert-ExactPathSecurity $PolicyBackup 'S-1-5-18' $SystemDataFileRules
            Copy-Item -Force -LiteralPath $PolicyBackup -Destination $installedPolicy
            Set-ExactPathSecurity $installedPolicy 'S-1-5-18' $SystemDataFileRules
        }
        if ($stateTouched -and (Test-Path -LiteralPath $StateBackup -PathType Leaf)) {
            Assert-ExactPathSecurity $StateBackup 'S-1-5-18' $SystemDataFileRules
            Copy-Item -Force -LiteralPath $StateBackup -Destination $StatePath
            Set-ExactPathSecurity $StatePath 'S-1-5-18' $SystemDataFileRules
        } elseif ($stateTouched -and -not $stateExisted -and (Test-Path -LiteralPath $StatePath)) {
            Assert-ExactPathSecurity $StatePath 'S-1-5-18' $SystemDataFileRules
            Remove-Item -Force -LiteralPath $StatePath
        }
        try { Assert-ExactPathSecurity $DataRoot 'S-1-5-18' $SystemDataDirectoryRules; Write-Audit $Mode 'rolled_back' } catch { Write-Warning ("rollback audit failed: " + $_.Exception.Message) }
        if (-not $installRootExisted -and (Test-Path -LiteralPath $InstallRoot)) { Assert-ExactPathSecurity $InstallRoot 'S-1-5-18' $SystemInstallDirectoryRules; Remove-Item -Recurse -Force -LiteralPath $InstallRoot }
        if (-not $dataRootExisted -and (Test-Path -LiteralPath $DataRoot)) { Assert-ExactPathSecurity $DataRoot 'S-1-5-18' $SystemDataDirectoryRules; Remove-Item -Recurse -Force -LiteralPath $DataRoot }
        if (-not $userRootExisted -and (Test-Path -LiteralPath $UserRoot)) { Assert-ExactPathSecurity $UserRoot $AuthorizedUserSid $UserDirectoryRules; Remove-Item -Recurse -Force -LiteralPath $UserRoot }
    }
    if (Test-Path -LiteralPath $TaskBackupRoot) { Remove-ExactTree $TaskBackupRoot $SystemDataDirectoryRules $SystemDataFileRules }
}
