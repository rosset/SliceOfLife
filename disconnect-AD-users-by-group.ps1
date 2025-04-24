# If the user belongs to any $adGroups, then logoff it's session from the RDS / Windows TS
# Run the script as program / script inside task scheduler
# C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
# Arguments: -NoProfile -ExecutionPolicy Bypass -File "C:\temp\disconnect-AD-users-by-group\disconnect-AD-users-by-group.ps1"
# Start In: C:\temp\disconnect-AD-users-by-group

# TODO: remove Transcript lines when the script is stable 
Start-Transcript -Path "C:\temp\disconnect-AD-users-by-group\log\debug.log" -Append

# Requires: ActiveDirectory module
Import-Module ActiveDirectory

# Define AD groups
$adGroups = @("GROUP1", "GROUP2")

# Define log file
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = "C:\temp\disconnect-AD-users-by-group\log\$timestamp.log"
New-Item -ItemType Directory -Force -Path (Split-Path $logFile) | Out-Null

# Logging function
function Write-Log {
    param([string]$message)
    $entry = "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") - $message"
    Write-Output $entry
    Add-Content -Path $logFile -Value $entry
}

Write-Log "=== RDS Group-Based Session Termination Script ==="
Write-Log "Script started at $(Get-Date)"
Write-Log "Target groups: $($adGroups -join ', ')"

# Get users from AD groups
$groupMembers = @()
foreach ($group in $adGroups) {
    try {
        Write-Log "Fetching members of group '$group'..."
        $members = Get-ADGroupMember -Identity $group -Recursive |
                   Where-Object { $_.objectClass -eq 'user' } |
                   Select-Object -ExpandProperty SamAccountName
        $groupMembers += $members
        foreach ($user in $members) {
            Write-Log "Retrieved user from '$group': $user"
        }
    } catch {
        Write-Log "? Failed to retrieve members of '$group': $_"
    }
}
$groupMembers = $groupMembers | Sort-Object -Unique
Write-Log "Total unique users from all groups: $($groupMembers.Count)"

# Get sessions using quser and log the raw output
Write-Log "Retrieving sessions from localhost using 'quser'..."
$quserOutput = quser 2>$null

if (-not $quserOutput) {
    Write-Log "? No session data returned from quser. Are you running as admin?"
    exit
}

# Log raw quser output for audit
Write-Log "--- Raw quser output start ---"
$quserOutput | ForEach-Object { Write-Log $_ }
Write-Log "--- Raw quser output end ---"

# Skip header and parse lines using regex
$allSessions = @()
$quserOutput | Select-Object -Skip 1 | ForEach-Object {
    $line = $_.Trim()
    if ($line -match '^>?(?<User>\S+)\s+(?<SessionName>\S+)?\s+(?<ID>\d+)\s+(?<State>\w+)\s+(?<IdleTime>[\S ]+)\s+(?<LogonTime>.+)$') {
        $username = $matches['User']
        $sessionId = $matches['ID']
        $state = $matches['State']
        $allSessions += [PSCustomObject]@{
            UserName  = $username
            SessionID = $sessionId
            State     = $state
        }
    }
}

Write-Log "Total sessions parsed: $($allSessions.Count)"

# Disconnect matching users
foreach ($session in $allSessions) {
    if ($groupMembers -contains $session.UserName) {
        Write-Log "?? Logging off '$($session.UserName)' (Session ID: $($session.SessionID), State: $($session.State))"
        try {
            logoff $session.SessionID /server:localhost
            Write-Log "? Successfully logged off '$($session.UserName)'"
        } catch {
            Write-Log "? Failed to log off '$($session.UserName)': $_"
        }
    } else {
        Write-Log "?? Skipping '$($session.UserName)' – not in specified groups"
    }
}

Write-Log "? Script completed at $(Get-Date)"

# TODO: remove this line when the script is stable 
Stop-Transcript
