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

function Get-AllExistingRules {
    param($RuleBaseName)
    
    Write-Host "INFO: Loading existing firewall rules (this may take a moment)..." -ForegroundColor Cyan
    
    try {
        # Get all rules that start with our base name in one query
        $existingRules = Get-NetFirewallRule -DisplayName "$RuleBaseName*" -ErrorAction SilentlyContinue
        
        # Create a hashtable for fast lookups with detailed rule information
        $ruleHashTable = @{}
        foreach ($rule in $existingRules) {
            $ruleHashTable[$rule.DisplayName] = @{
                Rule = $rule
                Enabled = $rule.Enabled
                DisplayName = $rule.DisplayName
            }
        }
        
        Write-Host "INFO: Found $($existingRules.Count) existing rules matching pattern '$RuleBaseName*'" -ForegroundColor Cyan
        return $ruleHashTable
    } catch {
        Write-Warning "WARNING: Error loading existing rules: $($_.Exception.Message)"
        return @{}
    }
}

function Save-CurrentState {
    param($PortsConfig)
    
    $stateData = @()
    foreach ($entry in $PortsConfig) {
        $portSpec = $entry.Port
        $description = $entry.Description
        $protocol = $entry.Protocol.ToUpper().Trim()
        $enabled = if ($entry.PSObject.Properties['Enabled']) { 
            if ($entry.Enabled -eq '1') { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True }
            else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False }
        } else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True }

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
    param($PreviousState, $CurrentState, $ExistingRulesHash)
    
    $removedCount = 0
    $errorCount = 0
    
    # Create a lookup set for current port-protocol combinations
    $currentKeys = @{}
    foreach ($current in $CurrentState) {
        $key = Get-PortProtocolKey -Port $current.Port -Protocol $current.Protocol
        $currentKeys[$key] = $true
    }
    
    # Collect all rules to remove first
    $rulesToRemove = @()
    
    # Find ports that existed before but don't exist now
    foreach ($previous in $PreviousState) {
        $key = Get-PortProtocolKey -Port $previous.Port -Protocol $previous.Protocol
        if (-not $currentKeys.ContainsKey($key)) {
            # This port-protocol combination was removed from CSV
            $individualRuleName = "$ruleBaseName - $($previous.Description) (Port $($previous.Port)/$($previous.Protocol))"
            
            if ($ExistingRulesHash.ContainsKey($individualRuleName)) {
                $rulesToRemove += $individualRuleName
            }
        }
    }
    
    # Remove rules in batch
    if ($rulesToRemove.Count -gt 0) {
        Write-Host "INFO: Auto-removing $($rulesToRemove.Count) obsolete firewall rules..." -ForegroundColor Magenta
        
        foreach ($ruleName in $rulesToRemove) {
            try {
                Remove-NetFirewallRule -DisplayName $ruleName -Confirm:$false -ErrorAction Stop
                $removedCount++
                Write-Host "SUCCESS: Obsolete rule removed: $ruleName" -ForegroundColor Green
            } catch {
                $errorCount++
                Write-Warning "ERROR: Failed to remove obsolete rule '$ruleName': $($_.Exception.Message)"
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

function Process-RulesBatch {
    param($RulesData, $ExistingRulesHash, $IsRemoveMode)
    
    $createdCount = 0
    $skippedCount = 0
    $removedCount = 0
    $errorCount = 0
    $updatedCount = 0
    
    # Group operations by type for better performance
    $rulesToCreate = @()
    $rulesToUpdate = @()
    $rulesToRemove = @()
    
    foreach ($ruleData in $RulesData) {
        $ruleName = $ruleData.RuleName
        $ruleExists = $ExistingRulesHash.ContainsKey($ruleName)
        
        if ($IsRemoveMode) {
            if ($ruleExists) {
                $rulesToRemove += $ruleData
            } else {
                $skippedCount++
                Write-Host "INFO: No firewall rule found to remove for port: $($ruleData.Port)/$($ruleData.Protocol) (Description: $($ruleData.Description)) - SKIPPED" -ForegroundColor Cyan
            }
        } else {
            if (-not $ruleExists) {
                $rulesToCreate += $ruleData
            } else {
                # Check if the enabled state actually needs to be updated
                $existingRule = $ExistingRulesHash[$ruleName]
                if ($existingRule.Enabled -ne $ruleData.Enabled) {
                    $rulesToUpdate += $ruleData
                } else {
                    $skippedCount++
                    Write-Host "INFO: Firewall rule already in correct state for port: $($ruleData.Port)/$($ruleData.Protocol) (Description: $($ruleData.Description)) - Enabled: $($ruleData.Enabled) - SKIPPED" -ForegroundColor Cyan
                }
            }
        }
    }
    
    # Process creations
    if ($rulesToCreate.Count -gt 0 -and -not $IsRemoveMode) {
        Write-Host "INFO: Creating $($rulesToCreate.Count) new firewall rules..." -ForegroundColor Green
        foreach ($ruleData in $rulesToCreate) {
            try {
                New-NetFirewallRule -DisplayName $ruleData.RuleName `
                    -Direction Inbound `
                    -Protocol $ruleData.Protocol `
                    -LocalPort $ruleData.Port `
                    -Action Allow `
                    -Profile $ruleProfiles `
                    -Enabled $ruleData.Enabled `
                    -ErrorAction Stop

                $createdCount++
                Write-Host "SUCCESS: Firewall rule created for port: $($ruleData.Port)/$($ruleData.Protocol) (Description: $($ruleData.Description)) - Enabled: $($ruleData.Enabled)" -ForegroundColor Green
            } catch {
                $errorCount++
                Write-Warning "ERROR: Failed to create firewall rule for port '$($ruleData.Port)/$($ruleData.Protocol)' (Description: $($ruleData.Description)): $($_.Exception.Message)"
            }
        }
    }
    
    # Process updates
    if ($rulesToUpdate.Count -gt 0 -and -not $IsRemoveMode) {
        Write-Host "INFO: Updating $($rulesToUpdate.Count) firewall rules that need state changes..." -ForegroundColor Yellow
        foreach ($ruleData in $rulesToUpdate) {
            try {
                Set-NetFirewallRule -DisplayName $ruleData.RuleName -Enabled $ruleData.Enabled -ErrorAction Stop
                Write-Host "SUCCESS: Updated firewall rule state for port: $($ruleData.Port)/$($ruleData.Protocol) (Description: $($ruleData.Description)) - Enabled: $($ruleData.Enabled)" -ForegroundColor Green
                $updatedCount++
            } catch {
                $errorCount++
                Write-Warning "ERROR: Failed to update firewall rule state for port '$($ruleData.Port)/$($ruleData.Protocol)' (Description: $($ruleData.Description)): $($_.Exception.Message)"
            }
        }
    }
    
    # Process removals
    if ($rulesToRemove.Count -gt 0 -and $IsRemoveMode) {
        Write-Host "INFO: Removing $($rulesToRemove.Count) firewall rules..." -ForegroundColor Red
        foreach ($ruleData in $rulesToRemove) {
            try {
                Remove-NetFirewallRule -DisplayName $ruleData.RuleName -Confirm:$false -ErrorAction Stop
                $removedCount++
                Write-Host "SUCCESS: Firewall rule removed for port: $($ruleData.Port)/$($ruleData.Protocol) (Description: $($ruleData.Description))" -ForegroundColor Green
            } catch {
                $errorCount++
                Write-Warning "ERROR: Failed to remove firewall rule for port '$($ruleData.Port)/$($ruleData.Protocol)' (Description: $($ruleData.Description)): $($_.Exception.Message)"
            }
        }
    }
    
    return @{
        Created = $createdCount
        Updated = $updatedCount
        Skipped = $skippedCount
        Removed = $removedCount
        Errors = $errorCount
    }
}

# --- Main Script Logic ---

Write-Host "--- Starting Optimized Firewall Rule Management ---" -ForegroundColor Cyan
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

# Load existing rules once at the beginning for performance
$existingRulesHash = Get-AllExistingRules -RuleBaseName $ruleBaseName

# Load previous state for comparison (only if not in RemoveRules mode)
$previousState = @()
$currentState = @()

if (-not $RemoveRules.IsPresent -and -not $SkipAutoCleanup.IsPresent) {
    $previousState = Get-PreviousState
    Write-Host "INFO: Loaded previous state with $($previousState.Count) port-protocol combinations" -ForegroundColor Cyan
}

# Prepare all rule data for batch processing
$allRulesData = @()

# Process current CSV configuration
if ($portsConfig) {
    Write-Host "INFO: Processing CSV configuration..." -ForegroundColor Cyan
    
    # Loop through each port entry/range in the CSV
    foreach ($entry in $portsConfig) {
        # Validate CSV column presence
        if (-not $entry.PSObject.Properties['Port']) {
            Write-Warning "Skipping entry: Missing 'Port' column in CSV row: $($entry | ConvertTo-Json -Compress)"
            continue
        }
        if (-not $entry.PSObject.Properties['Description']) {
            Write-Warning "Skipping entry: Missing 'Description' column in CSV row: $($entry | ConvertTo-Json -Compress)"
            continue
        }
        if (-not $entry.PSObject.Properties['Protocol']) {
            Write-Warning "Skipping entry: Missing 'Protocol' column in CSV row: $($entry | ConvertTo-Json -Compress)"
            continue
        }

        $portSpec = $entry.Port
        $description = $entry.Description
        $protocol = $entry.Protocol.ToUpper().Trim()
        $enabled = if ($entry.PSObject.Properties['Enabled']) { 
            if ($entry.Enabled -eq '1') { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True }
            else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False }
        } else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True }

        # Validate protocol
        if ($protocol -notin @("TCP", "UDP", "BOTH")) {
            Write-Warning "Skipping entry: Invalid protocol '$($entry.Protocol)' for port '$portSpec'. Must be 'TCP', 'UDP', or 'BOTH'."
            continue
        }

        # Determine which protocols to process
        $protocolsToProcess = @()
        switch ($protocol) {
            "TCP" { $protocolsToProcess += "TCP" }
            "UDP" { $protocolsToProcess += "UDP" }
            "BOTH" { $protocolsToProcess += @("TCP", "UDP") }
        }

        # Parse the port specification
        $portsToProcess = @()

        if ($portSpec -match '^\d+-\d+$') {
            $rangeParts = $portSpec.Split('-')
            $startPort = [int]$rangeParts[0]
            $endPort = [int]$rangeParts[1]

            if ($startPort -gt $endPort) {
                Write-Warning "Skipping entry: Invalid port range '$portSpec' for description '$description'. Start port cannot be greater than end port."
                continue
            }

            for ($i = $startPort; $i -le $endPort; $i++) {
                $portsToProcess += $i
            }
        } elseif ($portSpec -match '^\d+$') {
            $portsToProcess += [int]$portSpec
        } else {
            Write-Warning "Skipping entry: Invalid port specification '$portSpec' for description '$description'. Must be a single port or a range (e.g., '80' or '2280-2290')."
            continue
        }

        # Create rule data for each protocol and port combination
        foreach ($currentProtocol in $protocolsToProcess) {
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

                $individualRuleName = "$ruleBaseName - $description (Port $portNumber/$currentProtocol)"
                
                $allRulesData += @{
                    RuleName = $individualRuleName
                    Port = $portNumber
                    Protocol = $currentProtocol
                    Description = $description
                    Enabled = $enabled
                    OriginalSpec = $portSpec
                }
            }
        }
    }
}

# Process all rules in batches for better performance
Write-Host "INFO: Processing $($allRulesData.Count) rule operations..." -ForegroundColor Cyan
$results = Process-RulesBatch -RulesData $allRulesData -ExistingRulesHash $existingRulesHash -IsRemoveMode $RemoveRules.IsPresent

# Auto-cleanup obsolete rules (only in create mode and if not skipped)
if (-not $RemoveRules.IsPresent -and -not $SkipAutoCleanup.IsPresent -and $previousState.Count -gt 0) {
    Write-Host "`n--- Auto-Cleanup Phase: Removing obsolete rules ---" -ForegroundColor Magenta
    Remove-ObsoleteRules -PreviousState $previousState -CurrentState $currentState -ExistingRulesHash $existingRulesHash
}

# Save current state (only in create mode and if we have data)
if (-not $RemoveRules.IsPresent -and $portsConfig) {
    Save-CurrentState -PortsConfig $portsConfig
}

# Clear state file if in remove mode
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
    Write-Host "Rules Removed: $($results.Removed)" -ForegroundColor Green
    Write-Host "Rules Not Found (skipped removal): $($results.Skipped)" -ForegroundColor Yellow
} else {
    Write-Host "Rules Created: $($results.Created)" -ForegroundColor Green
    Write-Host "Rules Updated: $($results.Updated)" -ForegroundColor Yellow
    Write-Host "Rules Skipped (already in correct state): $($results.Skipped)" -ForegroundColor Cyan
}
Write-Host "Errors Encountered: $($results.Errors)" -ForegroundColor Red
Write-Host "--- Script Finished ---" -ForegroundColor Cyan