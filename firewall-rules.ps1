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
$ruleBaseName = "WSL2-open"

# Firewall rule profile (where the rule applies - only relevant for creation)
$ruleProfiles = "Domain", "Private", "Public"

# --- Helper Functions ---

function Get-WSLAddress {
    Write-Host "INFO: Auto-detecting WSL address..." -ForegroundColor Cyan
    
    try {
        # Method 1: Try to get WSL IP from wsl command
        $wslIP = (wsl hostname -I 2>$null | Out-String).Trim()
        if ($wslIP -and $wslIP -match '\d+\.\d+\.\d+\.\d+') {
            $wslIP = ($wslIP -split '\s+')[0]  # Take first IP if multiple
            Write-Host "INFO: Detected WSL address via wsl command: $wslIP" -ForegroundColor Green
            return $wslIP
        }
        
        # Method 2: Try to get from vEthernet WSL adapter
        $wslAdapter = Get-NetIPAddress -InterfaceAlias "*WSL*" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($wslAdapter) {
            # WSL adapter IP is usually the gateway, so we try .2 or scan range
            $adapterIP = $wslAdapter.IPAddress
            $baseIP = $adapterIP.Split('.')[0..2] -join '.'
            
            # Try common WSL guest IPs
            foreach ($lastOctet in @(2, 226, 128)) {
                $testIP = "$baseIP.$lastOctet"
                if (Test-Connection -ComputerName $testIP -Count 1 -Quiet -TimeoutSeconds 2) {
                    Write-Host "INFO: Detected WSL guest address: $testIP" -ForegroundColor Green
                    return $testIP
                }
            }
        }
        
        Write-Warning "WARNING: Could not auto-detect WSL address. Port forwarding will be skipped."
        return $null
        
    } catch {
        Write-Warning "WARNING: Error detecting WSL address: $($_.Exception.Message)"
        return $null
    }
}

function Get-ExistingPortForwards {
    Write-Host "INFO: Checking existing port forwarding rules..." -ForegroundColor Cyan
    
    try {
        $existingForwards = @()
        $output = netsh interface portproxy show all 2>$null
        
        if ($output) {
            $inDataSection = $false
            foreach ($line in $output) {
                # Skip header lines until we reach the data section
                if ($line -match '^-+\s+-+\s+-+\s+-+') {
                    $inDataSection = $true
                    continue
                }
                
                # Parse data lines (format: Address Port Address Port)
                if ($inDataSection -and $line -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$') {
                    $existingForwards += @{
                        ListenAddress = $matches[1]
                        ListenPort = [int]$matches[2]
                        ConnectAddress = $matches[3]
                        ConnectPort = [int]$matches[4]
                    }
                }
            }
        }
        
        Write-Host "INFO: Found $($existingForwards.Count) existing port forwarding rules" -ForegroundColor Cyan
        return $existingForwards
    } catch {
        Write-Warning "WARNING: Error checking existing port forwards: $($_.Exception.Message)"
        return @()
    }
}

function Remove-AllPortForwards {
    Write-Host "INFO: Removing all existing port forwarding rules..." -ForegroundColor Magenta
    
    try {
        $existingForwards = Get-ExistingPortForwards
        $removedCount = 0
        
        foreach ($forward in $existingForwards) {
            try {
                $result = netsh interface portproxy delete v4tov4 listenport=$($forward.ListenPort) listenaddress=$($forward.ListenAddress) 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $removedCount++
                    Write-Host "SUCCESS: Removed port forward: $($forward.ListenAddress):$($forward.ListenPort) -> $($forward.ConnectAddress):$($forward.ConnectPort)" -ForegroundColor Green
                }
            } catch {
                Write-Warning "WARNING: Failed to remove port forward for $($forward.ListenAddress):$($forward.ListenPort): $($_.Exception.Message)"
            }
        }
        
        Write-Host "INFO: Removed $removedCount port forwarding rules" -ForegroundColor Green
    } catch {
        Write-Warning "WARNING: Error removing port forwards: $($_.Exception.Message)"
    }
}

function Configure-PortForwarding {
    param($Ports, $WSLAddress)
    
    if (-not $WSLAddress) {
        Write-Warning "WARNING: No WSL address provided. Skipping port forwarding configuration."
        return
    }
    
    Write-Host "`n--- Port Forwarding Configuration ---" -ForegroundColor Magenta
    Write-Host "INFO: Configuring port forwarding to WSL address: $WSLAddress" -ForegroundColor Cyan
    
    # First, remove all existing port forwards
    Remove-AllPortForwards
    
    # Wait a moment to ensure all rules are removed
    Start-Sleep -Seconds 1
    
    $successCount = 0
    $errorCount = 0
    $skippedCount = 0
    $excludedPorts = @()
    
    # Load previous state to check for changes
    $previousState = Get-PreviousState
    $previousPortForwards = @{}
    foreach ($state in $previousState) {
        $key = "$($state.Port)/$($state.Protocol)"
        $previousPortForwards[$key] = $state.PortForwarding
    }
    
    # First pass: collect ports that don't need forwarding
    foreach ($portConfig in $Ports) {
        $port = $portConfig.Port
        $needsForwarding = $portConfig.PortForwarding
        
        if ($needsForwarding -eq "0") {
            $excludedPorts += $port
            Write-Host "INFO: Port $port will be excluded from forwarding ($($portConfig.Description)) - PortForwarding=0" -ForegroundColor Yellow
        }
    }
    
    # Second pass: configure port forwards
    foreach ($portConfig in $Ports) {
        $port = $portConfig.Port
        
        # Skip if port doesn't need forwarding
        if ($port -in $excludedPorts) {
            $skippedCount++
            continue
        }
        
        try {
            # First ensure any existing forward for this port is removed
            netsh interface portproxy delete v4tov4 listenport=$port listenaddress=0.0.0.0 2>$null
            
            # Add new port proxy
            $result = netsh interface portproxy add v4tov4 listenport=$port listenaddress=0.0.0.0 connectport=$port connectaddress=$WSLAddress
            
            if ($LASTEXITCODE -eq 0) {
                $successCount++
                Write-Host "SUCCESS: Port forwarding configured: 0.0.0.0:$port -> $WSLAddress`:$port ($($portConfig.Description))" -ForegroundColor Green
            } else {
                $errorCount++
                Write-Warning "ERROR: Failed to configure port forwarding for port $port"
            }
        } catch {
            $errorCount++
            Write-Warning "ERROR: Exception configuring port forwarding for port $port`: $($_.Exception.Message)"
        }
    }
    
    Write-Host "`n--- Port Forwarding Summary ---" -ForegroundColor Magenta
    Write-Host "Port Forwards Configured: $successCount" -ForegroundColor Green
    Write-Host "Port Forwards Skipped (PortForwarding=0): $skippedCount" -ForegroundColor Yellow
    Write-Host "Port Forward Errors: $errorCount" -ForegroundColor Red
    
    if ($successCount -gt 0) {
        Write-Host "`nCurrent port forwarding configuration:" -ForegroundColor Cyan
        netsh interface portproxy show all
        
        Write-Host "`nExternal access should now work via Windows host IP for WSL services" -ForegroundColor Yellow
    }
}

function Remove-PortForwarding {
    param($Ports)
    
    Write-Host "`n--- Removing Port Forwarding ---" -ForegroundColor Magenta
    
    # Get all existing port forwards
    $existingForwards = Get-ExistingPortForwards
    $removedCount = 0
    $errorCount = 0
    
    # Create a set of ports to remove
    $portsToRemove = @{}
    foreach ($port in $Ports) {
        $portsToRemove[$port.Port] = $true
    }
    
    # Remove matching port forwards
    foreach ($forward in $existingForwards) {
        if ($portsToRemove.ContainsKey($forward.ListenPort)) {
            try {
                $result = netsh interface portproxy delete v4tov4 listenport=$($forward.ListenPort) listenaddress=$($forward.ListenAddress) 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $removedCount++
                    Write-Host "SUCCESS: Port forwarding removed for port: $($forward.ListenPort)" -ForegroundColor Green
                }
            } catch {
                $errorCount++
                Write-Warning "WARNING: Failed to remove port forwarding for port $($forward.ListenPort): $($_.Exception.Message)"
            }
        }
    }
    
    Write-Host "`n--- Port Forwarding Removal Summary ---" -ForegroundColor Magenta
    Write-Host "Port Forwards Removed: $removedCount" -ForegroundColor Green
    Write-Host "Removal Errors: $errorCount" -ForegroundColor Red
}

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
        $portForwarding = if ($entry.PSObject.Properties['PortForwarding']) { $entry.PortForwarding } else { "1" }

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
                    PortForwarding = $portForwarding
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
    if (Test-Path $stateFilePath) {
        try {
            $stateData = Get-Content -Path $stateFilePath -Raw | ConvertFrom-Json
            Write-Host "INFO: Loaded previous state with $($stateData.Count) port-protocol combinations" -ForegroundColor Cyan
            return $stateData
        } catch {
            Write-Warning "WARNING: Failed to load previous state: $($_.Exception.Message)"
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

Write-Host "--- Starting Enhanced Firewall + Port Forwarding Management ---" -ForegroundColor Magenta
Write-Host "CSV File Path: $csvFilePath" -ForegroundColor Cyan
Write-Host "State File Path: $stateFilePath" -ForegroundColor Cyan
Write-Host "Rule Base Name: $ruleBaseName" -ForegroundColor Cyan

if ($RemoveRules.IsPresent) {
    Write-Host "Mode: REMOVING ALL RULES (triggered by -RemoveRules switch)" -ForegroundColor Yellow
    
    # First remove all port forwarding rules
    Write-Host "`n--- Removing Port Forwarding Rules ---" -ForegroundColor Magenta
    Remove-AllPortForwards
    
    # Then remove firewall rules
    Write-Host "`n--- Removing Firewall Rules ---" -ForegroundColor Magenta
    $existingRules = Get-AllExistingRules -RuleBaseName $ruleBaseName
    $removedCount = 0
    $notFoundCount = 0
    $errorCount = 0
    
    Write-Host "INFO: Loading existing firewall rules (this may take a moment)..." -ForegroundColor Cyan
    Write-Host "INFO: Found $($existingRules.Count) existing rules matching pattern '$ruleBaseName*'" -ForegroundColor Cyan
    
    # Load CSV to get descriptions
    $portsConfig = Import-Csv -Path $csvFilePath -ErrorAction Stop
    Write-Host "INFO: Processing CSV configuration..." -ForegroundColor Cyan
    Write-Host "INFO: Processing $($portsConfig.Count) rule operations..." -ForegroundColor Cyan
    Write-Host "INFO: Removing $($existingRules.Count) firewall rules..." -ForegroundColor Cyan
    
    foreach ($rule in $existingRules) {
        try {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            $removedCount++
            Write-Host "SUCCESS: Firewall rule removed for port: $($rule.Port)/$($rule.Protocol) (Description: $($rule.Description))" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -like "*No MSFT_NetFirewallRule objects found*") {
                $notFoundCount++
            } else {
                $errorCount++
                Write-Warning "ERROR: Failed to remove rule for port $($rule.Port): $($_.Exception.Message)"
            }
        }
    }
    
    # Clear state file
    try {
        if (Test-Path $stateFilePath) {
            Remove-Item $stateFilePath -Force
            Write-Host "INFO: State file cleared after rule removal" -ForegroundColor Cyan
        }
    } catch {
        Write-Warning "WARNING: Failed to clear state file: $($_.Exception.Message)"
    }
    
    Write-Host "`n--- Final Summary ---" -ForegroundColor Magenta
    Write-Host "Rules Removed: $removedCount" -ForegroundColor Green
    Write-Host "Rules Not Found (skipped removal): $notFoundCount" -ForegroundColor Yellow
    Write-Host "Errors Encountered: $errorCount" -ForegroundColor Red
    Write-Host "--- Script Finished ---" -ForegroundColor Magenta
} else {
    Write-Host "Mode: CREATING/UPDATING RULES" -ForegroundColor Green
    Write-Host "Rule Profiles: $($ruleProfiles -join ', ')" -ForegroundColor Cyan
    Write-Host "Auto-Cleanup: $(if ($SkipAutoCleanup.IsPresent) { 'DISABLED' } else { 'ENABLED' }) (will remove rules for ports deleted from CSV)" -ForegroundColor Cyan
    
    # Load and process CSV
    try {
        $portsConfig = Import-Csv -Path $csvFilePath -ErrorAction Stop
        Write-Host "INFO: Processing CSV configuration..." -ForegroundColor Cyan
        Write-Host "INFO: Processing $($portsConfig.Count) rule operations..." -ForegroundColor Cyan
        
        # Get forwarding address from CSV or auto-detect
        $forwardAddress = $null
        foreach ($portConfig in $portsConfig) {
            if ($portConfig.PSObject.Properties['ForwardAddress'] -and $portConfig.ForwardAddress) {
                $forwardAddress = $portConfig.ForwardAddress
                Write-Host "INFO: Using forwarding address from CSV: $forwardAddress" -ForegroundColor Green
                break
            }
        }
        
        # If no ForwardAddress in CSV, try to auto-detect
        if (-not $forwardAddress) {
            $forwardAddress = Get-WSLAddress
        }
        
        if (-not $forwardAddress) {
            Write-Warning "WARNING: No forwarding address specified in CSV and could not auto-detect WSL address. Port forwarding will be skipped."
        }
        
        # Initialize arrays for processing
        $allRulesData = @()
        $currentState = @()
        $portsForForwarding = @()
        
        # Process each port configuration
        foreach ($portConfig in $portsConfig) {
            # Validate CSV column presence
            if (-not $portConfig.PSObject.Properties['Port']) {
                Write-Warning "Skipping entry: Missing 'Port' column in CSV row: $($portConfig | ConvertTo-Json -Compress)"
                continue
            }
            if (-not $portConfig.PSObject.Properties['Description']) {
                Write-Warning "Skipping entry: Missing 'Description' column in CSV row: $($portConfig | ConvertTo-Json -Compress)"
                continue
            }
            if (-not $portConfig.PSObject.Properties['Protocol']) {
                Write-Warning "Skipping entry: Missing 'Protocol' column in CSV row: $($portConfig | ConvertTo-Json -Compress)"
                continue
            }

            $portSpec = $portConfig.Port
            $description = $portConfig.Description
            $protocol = $portConfig.Protocol.ToUpper().Trim()
            $enabled = if ($portConfig.PSObject.Properties['Enabled']) { 
                if ($portConfig.Enabled -eq '1') { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True }
                else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::False }
            } else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True }

            # Validate protocol
            if ($protocol -notin @("TCP", "UDP", "BOTH")) {
                Write-Warning "Skipping entry: Invalid protocol '$($portConfig.Protocol)' for port '$portSpec'. Must be 'TCP', 'UDP', or 'BOTH'."
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
                    # Collect port info for port forwarding (only TCP ports that need forwarding)
                    if ($currentProtocol -eq "TCP" -and $forwardAddress) {
                        $portForwarding = if ($portConfig.PSObject.Properties['PortForwarding']) { $portConfig.PortForwarding } else { "1" }
                        
                        $portsForForwarding += @{
                            Port = $portNumber
                            Description = $description
                            PortForwarding = $portForwarding
                        }
                    }
                    
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
        
        # Process all rules in batches for better performance
        Write-Host "INFO: Processing $($allRulesData.Count) rule operations..." -ForegroundColor Cyan
        $existingRules = Get-AllExistingRules -RuleBaseName $ruleBaseName
        $results = Process-RulesBatch -RulesData $allRulesData -ExistingRulesHash $existingRules -IsRemoveMode $false
        
        # Auto-cleanup obsolete rules (only in create mode and if not skipped)
        if (-not $SkipAutoCleanup.IsPresent) {
            $previousState = Get-PreviousState
            if ($previousState.Count -gt 0) {
                Write-Host "`n--- Auto-Cleanup Phase: Removing obsolete rules ---" -ForegroundColor Magenta
                Remove-ObsoleteRules -PreviousState $previousState -CurrentState $currentState -ExistingRulesHash $existingRules
            }
        }
        
        # Configure port forwarding
        if ($forwardAddress -and $portsForForwarding.Count -gt 0) {
            Configure-PortForwarding -Ports $portsForForwarding -WSLAddress $forwardAddress
        }
        
        # Save current state
        Save-CurrentState -PortsConfig $portsConfig
        
        Write-Host "`n--- Final Summary ---" -ForegroundColor Cyan
        Write-Host "Rules Created: $($results.Created)" -ForegroundColor Green
        Write-Host "Rules Updated: $($results.Updated)" -ForegroundColor Yellow
        Write-Host "Rules Skipped (already in correct state): $($results.Skipped)" -ForegroundColor Cyan
        Write-Host "Errors Encountered: $($results.Errors)" -ForegroundColor Red
        Write-Host "--- Script Finished ---" -ForegroundColor Cyan
        
    } catch {
        Write-Error "ERROR: Failed to process CSV file: $($_.Exception.Message)"
        exit 1
    }
}

# === Prevent the script from closing automatically ===
Write-Host "`nScript execution completed. Press any key to close this window..." -ForegroundColor Yellow
try {
    # Attempt to use a more direct keyboard input method
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
} catch {
    # If the above method fails, use Read-Host as a fallback
    Read-Host "Press Enter to close this window"
}