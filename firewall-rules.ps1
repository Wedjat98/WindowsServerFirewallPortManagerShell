#Requires -Modules NetSecurity

param (
    [switch]$RemoveRules, # Optional switch to remove rules instead of creating them
    [switch]$SkipAutoCleanup # Optional switch to skip automatic cleanup of removed ports
)

# --- Configuration ---
# Get the directory of the current script
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path

# Path to the CSV file (same directory as the script)
$csvFilePath = Join-Path -Path $scriptDirectory -ChildPath "ports.csv"

# Path to the state file (stores previous configuration)
$stateFilePath = Join-Path -Path $scriptDirectory -ChildPath "firewall_state.json"

# Base name for the firewall rules (used for both creation and identification for removal)
$ruleBaseName = "Docker WSL2"

# Firewall rule profile (where the rule applies - only relevant for creation)
$ruleProfiles = "Domain", "Private", "Public"

# --- Helper Functions ---

function Get-PortProtocolKey {
    param($Port, $Protocol)
    return "$Port/$Protocol"
}

function Save-CurrentState {
    param($PortsConfig)
    
    $stateData = @()
    foreach ($entry in $PortsConfig) {
        $portSpec = $entry.Port
        $description = $entry.Description
        $protocol = $entry.Protocol.ToUpper().Trim()
        $enabled = if ($entry.PSObject.Properties['Enabled']) { $entry.Enabled -eq '1' } else { $true }

        # Determine which protocols to process
        $protocolsToProcess = @()
        switch ($protocol) {
            "TCP" { $protocolsToProcess += "TCP" }
            "UDP" { $protocolsToProcess += "UDP" }
            "BOTH" { $protocolsToProcess += @("TCP", "UDP") }
        }

        # Parse port specification
        $portsToProcess = @()
        if ($portSpec -match '^\d+-\d+$') {
            $rangeParts = $portSpec.Split('-')
            $startPort = [int]$rangeParts[0]
            $endPort = [int]$rangeParts[1]
            for ($i = $startPort; $i -le $endPort; $i++) {
                $portsToProcess += $i
            }
        } elseif ($portSpec -match '^\d+$') {
            $portsToProcess += [int]$portSpec
        }

        # Add each port-protocol combination to state
        foreach ($currentProtocol in $protocolsToProcess) {
            foreach ($portNumber in $portsToProcess) {
                $stateData += @{
                    Port = $portNumber
                    Protocol = $currentProtocol
                    Description = $description
                    OriginalSpec = $portSpec
                    Enabled = $enabled
                }
            }
        }
    }

    try {
        $stateData | ConvertTo-Json -Depth 3 | Out-File -FilePath $stateFilePath -Encoding UTF8 -ErrorAction Stop
        Write-Host "INFO: Current state saved to: $stateFilePath" -ForegroundColor Cyan
    } catch {
        Write-Warning "WARNING: Failed to save current state: $($_.Exception.Message)"
    }
}

function Get-PreviousState {
    if (Test-Path -Path $stateFilePath -PathType Leaf) {
        try {
            $stateContent = Get-Content -Path $stateFilePath -Raw -ErrorAction Stop
            return ($stateContent | ConvertFrom-Json)
        } catch {
            Write-Warning "WARNING: Failed to read previous state file: $($_.Exception.Message)"
            return @()
        }
    }
    return @()
}

function Remove-ObsoleteRules {
    param($PreviousState, $CurrentState)
    
    $removedCount = 0
    $errorCount = 0
    
    # Create a lookup set for current port-protocol combinations
    $currentKeys = @{}
    foreach ($current in $CurrentState) {
        $key = Get-PortProtocolKey -Port $current.Port -Protocol $current.Protocol
        $currentKeys[$key] = $true
    }
    
    # Find ports that existed before but don't exist now
    foreach ($previous in $PreviousState) {
        $key = Get-PortProtocolKey -Port $previous.Port -Protocol $previous.Protocol
        if (-not $currentKeys.ContainsKey($key)) {
            # This port-protocol combination was removed from CSV
            $individualRuleName = "$ruleBaseName - $($previous.Description) (Port $($previous.Port)/$($previous.Protocol))"
            
            $existingRule = Get-NetFirewallRule -DisplayName $individualRuleName -ErrorAction SilentlyContinue
            if ($existingRule) {
                Write-Host "INFO: Auto-removing obsolete firewall rule: $individualRuleName" -ForegroundColor Magenta
                try {
                    Remove-NetFirewallRule -DisplayName $individualRuleName -Confirm:$false -ErrorAction Stop
                    $removedCount++
                    Write-Host "SUCCESS: Obsolete rule removed for port: $($previous.Port)/$($previous.Protocol)" -ForegroundColor Green
                } catch {
                    $errorCount++
                    Write-Warning "ERROR: Failed to remove obsolete rule for port '$($previous.Port)/$($previous.Protocol)': $($_.Exception.Message)"
                }
            }
        }
    }
    
    if ($removedCount -gt 0 -or $errorCount -gt 0) {
        Write-Host "`n--- Auto-Cleanup Summary ---" -ForegroundColor Magenta
        Write-Host "Obsolete Rules Removed: $removedCount" -ForegroundColor Green
        Write-Host "Auto-Cleanup Errors: $errorCount" -ForegroundColor Red
        Write-Host ""
    }
}

# --- Main Script Logic ---

Write-Host "--- Starting Intelligent Firewall Rule Management ---" -ForegroundColor Cyan
Write-Host "CSV File Path: $csvFilePath" -ForegroundColor Cyan
Write-Host "State File Path: $stateFilePath" -ForegroundColor Cyan
Write-Host "Rule Base Name: $ruleBaseName" -ForegroundColor Cyan

if ($RemoveRules.IsPresent) {
    Write-Host "Mode: REMOVING ALL RULES (triggered by -RemoveRules switch)" -ForegroundColor Red
} else {
    Write-Host "Mode: CREATING/UPDATING RULES" -ForegroundColor Green
    Write-Host "Rule Profiles: $($ruleProfiles -join ', ')" -ForegroundColor Cyan
    if ($SkipAutoCleanup.IsPresent) {
        Write-Host "Auto-Cleanup: DISABLED (triggered by -SkipAutoCleanup switch)" -ForegroundColor Yellow
    } else {
        Write-Host "Auto-Cleanup: ENABLED (will remove rules for ports deleted from CSV)" -ForegroundColor Green
    }
}
Write-Host ""

# Check if the CSV file exists
if (-not (Test-Path -Path $csvFilePath -PathType Leaf)) {
    Write-Error "Error: The CSV file '$csvFilePath' was not found."
    exit 1
}

# Import the CSV file
try {
    $portsConfig = Import-Csv -Path $csvFilePath -ErrorAction Stop
} catch {
    Write-Error "Error importing CSV file '$csvFilePath': $($_.Exception.Message)`nEnsure the CSV has 'Port', 'Description', and 'Protocol' columns."
    exit 1
}

# Check if the CSV file is empty
if (-not $portsConfig) {
    Write-Warning "Warning: The CSV file '$csvFilePath' is empty or contains no data."
    
    # If in remove mode or CSV is empty, we might want to clean up all existing rules
    if ($RemoveRules.IsPresent) {
        Write-Host "Proceeding with removal of all existing rules..." -ForegroundColor Yellow
    } else {
        Write-Host "No rules to process. Exiting." -ForegroundColor Yellow
        exit 0
    }
}

# Load previous state for comparison (only if not in RemoveRules mode)
$previousState = @()
$currentState = @()

if (-not $RemoveRules.IsPresent -and -not $SkipAutoCleanup.IsPresent) {
    $previousState = Get-PreviousState
    Write-Host "INFO: Loaded previous state with $($previousState.Count) port-protocol combinations" -ForegroundColor Cyan
}

$createdCount = 0
$skippedCount = 0
$removedCount = 0
$errorCount = 0

# Process current CSV configuration
if ($portsConfig) {
    # Loop through each port entry/range in the CSV
    foreach ($entry in $portsConfig) {
        # Validate CSV column presence
        if (-not $entry.PSObject.Properties['Port']) {
            Write-Warning "Skipping entry: Missing 'Port' column in CSV row: $($entry | ConvertTo-Json -Compress)"
            $errorCount++
            continue
        }
        if (-not $entry.PSObject.Properties['Description']) {
            Write-Warning "Skipping entry: Missing 'Description' column in CSV row: $($entry | ConvertTo-Json -Compress)"
            $errorCount++
            continue
        }
        if (-not $entry.PSObject.Properties['Protocol']) {
            Write-Warning "Skipping entry: Missing 'Protocol' column in CSV row: $($entry | ConvertTo-Json -Compress)"
            $errorCount++
            continue
        }

        $portSpec = $entry.Port # This can be a single port or a range like "2280-2290"
        $description = $entry.Description
        $protocol = $entry.Protocol.ToUpper().Trim() # Normalize protocol to uppercase
        $enabled = if ($entry.PSObject.Properties['Enabled']) { $entry.Enabled -eq '1' } else { $true }

        # Validate protocol
        if ($protocol -notin @("TCP", "UDP", "BOTH")) {
            Write-Warning "Skipping entry: Invalid protocol '$($entry.Protocol)' for port '$portSpec'. Must be 'TCP', 'UDP', or 'BOTH'."
            $errorCount++
            continue
        }

        # Determine which protocols to process
        $protocolsToProcess = @()
        switch ($protocol) {
            "TCP" { $protocolsToProcess += "TCP" }
            "UDP" { $protocolsToProcess += "UDP" }
            "BOTH" { $protocolsToProcess += @("TCP", "UDP") }
        }

        # --- Parse the port specification (single port or range) ---
        $portsToProcess = @()

        if ($portSpec -match '^\d+-\d+$') {
            # It's a range (e.g., "2280-2290")
            $rangeParts = $portSpec.Split('-')
            $startPort = [int]$rangeParts[0]
            $endPort = [int]$rangeParts[1]

            if ($startPort -gt $endPort) {
                Write-Warning "Skipping entry: Invalid port range '$portSpec' for description '$description'. Start port cannot be greater than end port."
                $errorCount++
                continue
            }

            # Generate all ports in the range
            for ($i = $startPort; $i -le $endPort; $i++) {
                $portsToProcess += $i
            }
        } elseif ($portSpec -match '^\d+$') {
            # It's a single port (e.g., "80")
            $portsToProcess += [int]$portSpec
        } else {
            # Invalid format
            Write-Warning "Skipping entry: Invalid port specification '$portSpec' for description '$description'. Must be a single port or a range (e.g., '80' or '2280-2290')."
            $errorCount++
            continue
        }

        # --- Process each protocol ---
        foreach ($currentProtocol in $protocolsToProcess) {
            # --- Process each individual port (from a single port or a range) ---
            foreach ($portNumber in $portsToProcess) {
                # Add to current state for comparison
                if (-not $RemoveRules.IsPresent) {
                    $currentState += @{
                        Port = $portNumber
                        Protocol = $currentProtocol
                        Description = $description
                        OriginalSpec = $portSpec
                        Enabled = $enabled
                    }
                }

                # Construct the unique rule name for each individual port and protocol
                $individualRuleName = "$ruleBaseName - $description (Port $portNumber/$currentProtocol)"

                # Check if the firewall rule already exists
                $existingRule = Get-NetFirewallRule -DisplayName $individualRuleName -ErrorAction SilentlyContinue

                if ($RemoveRules.IsPresent) {
                    # --- REMOVE RULES MODE ---
                    if ($existingRule) {
                        Write-Host "INFO: Attempting to remove firewall rule: $individualRuleName" -ForegroundColor DarkYellow
                        try {
                            Remove-NetFirewallRule -DisplayName $individualRuleName -Confirm:$false -ErrorAction Stop
                            $removedCount++
                            Write-Host "SUCCESS: Firewall rule removed for port: $portNumber/$currentProtocol (Description: $description)" -ForegroundColor Green
                        } catch {
                            $errorCount++
                            Write-Warning "ERROR: Failed to remove firewall rule for port '$portNumber/$currentProtocol' (Description: $description): $($_.Exception.Message)"
                            Write-Warning "       This might require administrator privileges or the rule is being used by another process."
                        }
                    } else {
                        Write-Host "INFO: No firewall rule found to remove for port: $portNumber/$currentProtocol (Description: $description) - SKIPPED" -ForegroundColor Cyan
                        $skippedCount++
                    }
                } else {
                    # --- CREATE/UPDATE RULES MODE (Default) ---
                    if (-not $existingRule) {
                        Write-Host "INFO: Attempting to create firewall rule: $individualRuleName" -ForegroundColor White
                        try {
                            New-NetFirewallRule -DisplayName $individualRuleName `
                                -Direction Inbound `
                                -Protocol $currentProtocol `
                                -LocalPort $portNumber `
                                -Action Allow `
                                -Profile $ruleProfiles `
                                -Enabled $enabled `
                                -ErrorAction Stop

                            $createdCount++
                            Write-Host "SUCCESS: Firewall rule created for port: $portNumber/$currentProtocol (Description: $description) - Enabled: $enabled" -ForegroundColor Green
                        } catch {
                            $errorCount++
                            Write-Warning "ERROR: Failed to create firewall rule for port '$portNumber/$currentProtocol' (Description: $description): $($_.Exception.Message)"
                            Write-Warning "       This might require administrator privileges or the rule already exists with a different display name."
                        }
                    } else {
                        # Update existing rule's enabled state
                        try {
                            Set-NetFirewallRule -DisplayName $individualRuleName -Enabled $enabled -ErrorAction Stop
                            Write-Host "INFO: Updated firewall rule state for port: $portNumber/$currentProtocol (Description: $description) - Enabled: $enabled" -ForegroundColor DarkYellow
                            $skippedCount++
                        } catch {
                            $errorCount++
                            Write-Warning "ERROR: Failed to update firewall rule state for port '$portNumber/$currentProtocol' (Description: $description): $($_.Exception.Message)"
                        }
                    }
                }
            } # End of foreach ($portNumber in $portsToProcess)
        } # End of foreach ($currentProtocol in $protocolsToProcess)
    } # End of foreach ($entry in $portsConfig)
}

# --- Auto-cleanup obsolete rules (only in create mode and if not skipped) ---
if (-not $RemoveRules.IsPresent -and -not $SkipAutoCleanup.IsPresent -and $previousState.Count -gt 0) {
    Write-Host "`n--- Auto-Cleanup Phase: Removing obsolete rules ---" -ForegroundColor Magenta
    Remove-ObsoleteRules -PreviousState $previousState -CurrentState $currentState
}

# --- Save current state (only in create mode and if we have data) ---
if (-not $RemoveRules.IsPresent -and $portsConfig) {
    Save-CurrentState -PortsConfig $portsConfig
}

# --- Clear state file if in remove mode ---
if ($RemoveRules.IsPresent -and (Test-Path -Path $stateFilePath)) {
    try {
        Remove-Item -Path $stateFilePath -Force -ErrorAction Stop
        Write-Host "INFO: State file cleared after rule removal" -ForegroundColor Cyan
    } catch {
        Write-Warning "WARNING: Failed to clear state file: $($_.Exception.Message)"
    }
}

Write-Host "`n--- Final Summary ---" -ForegroundColor Cyan
if ($RemoveRules.IsPresent) {
    Write-Host "Rules Removed: $removedCount" -ForegroundColor Green
    Write-Host "Rules Not Found (skipped removal): $skippedCount" -ForegroundColor Yellow
} else {
    Write-Host "Rules Created: $createdCount" -ForegroundColor Green
    Write-Host "Rules Skipped (already existed): $skippedCount" -ForegroundColor Yellow
}
Write-Host "Errors Encountered: $errorCount" -ForegroundColor Red
Write-Host "--- Script Finished ---" -ForegroundColor Cyan