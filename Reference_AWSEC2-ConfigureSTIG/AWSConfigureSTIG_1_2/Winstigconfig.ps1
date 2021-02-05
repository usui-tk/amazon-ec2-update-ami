<#
    Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: MIT-0

     Permission is hereby granted, free of charge, to any person obtaining a copy of this
    software and associated documentation files (the "Software"), to deal in the Software
    without restriction, including without limitation the rights to use, copy, modify,
    merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
    INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#>


<#
    .SYNOPSIS
    Designed to apply STIG settings to various Windows environments.

    .DESCRIPTION
    This Script applies various STIG settings using ether local group policies, registry changes, or installing the certificate software.

    .PARAMETER Level
    Used to set what level of severity STIG the system at.  Examples High, Medium, Low

    .PARAMETER StagingPath
    The location used to run files out of as needed.
#>

#Set input parameters to be used with SSM doc
Param(
    [Parameter (Position = 1)]
    [ValidateSet("High", "Medium", "Low")]
    [string]$Level = "High", #Default level to run

    [Parameter (Position = 2)]
    [string]$StagingPath = "C:\ConfigPrep"      #To allow pass through of custom path for BOM.
)

#Variables
[IO.FileInfo]$IRmsi = "$StagingPath\Support Files\InstallRoot.msi"

#Function to force a exit, reboot
Function ExitWithReboot {
    Exit 3010
}

#Create StateObject to track reboots if required by an installer.
Function New-StateObject {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory = $false)]
        [UInt32]$Install = 0,

        [Parameter(Mandatory = $false)]
        [UInt32]$TryCount = 0
    )

    [Object]$stateObject = $null

    $stateObject = New-Object -TypeName PSObject -Property @{Install = $Install; TryCount = $TryCount }

    Return $stateObject
}

#Read the state record, only used if required by a installer.
Function Read-StateObject {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    [Object]$stateObject = $null

    If (Test-Path -Path $Path) {
        $stateObject = Get-Content $Path -Raw | ConvertFrom-Json
    }
    Else {
        $stateObject = New-StateObject
    }

    Return $stateObject
}

#Writes to the StateObject to keep track of progress.
Function Write-StateObject {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory = $true)]
        [Object]$State,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    ConvertTo-Json -InputObject $State | Out-File $Path -Force
}

#Determine OS and set variable names for future use.
Function Identify-OS {

    [Parameter(Mandatory = $true)]
    [string]$OSReg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    [array]$OSRegValues = Get-ItemProperty -Path $OSReg
    [string]$OSNameTmp = $OSRegValues.ProductName
    [string]$OSTypeTmp = $OSRegValues.InstallationType

    #Set name to match folder structure
    If ($OSNameTmp -like "*2019*") {
        $script:OSName = "2019"
    }
    ElseIf ($OSNameTmp -like "*2016*") {
        $script:OSName = "2016"
    }
    ElseIf ($OSNameTmp -like "*2012*") {
        $script:OSName = "2012R2"
    }

    If ($OSTypeTmp -like "*Nano*") {
        "Nano server is currently unsupported.  Exiting SSM."
        Exit -1
    }
}

#A function to copy over the ADMX, ADML, and if needs xml file to apply further configuration settings.
Function Apply-ADML {

    #A number of STIGs require a xml file to be used for configuration this is to copy it from staging
    If ($script:OSName -eq "2019") {
        Try {
            New-Item -ItemType Directory -Path "${Env:Programfiles(x86)}\STIG" -Force | Out-Null
        }
        Catch {
            "Failed to create directory, due to: $_"
            Exit -1
        }

        Try {
            Copy-Item -Path "$StagingPath\2019\Support Files\DOD_EP_V2.XML" -Destination "${Env:Programfiles(x86)}\STIG" | Out-Null
            "DOD_EP_V2.xml is copied to ${Env:Programfiles(x86)}\STIG for multiple STIG settings."
        }
        Catch {
            "Failed to copy XML file, due to: $_"
            Exit -1
        }
    }

    If ($script:OSName -eq "2019" -or $script:OSName -eq "2016") {
        Try {
            Copy-Item -Path "$StagingPath\$script:OSName\Support Files\MSS-Legacy.admx" -Destination "$Env:WinDir\PolicyDefinitions\MSS-Legacy.admx" | Out-Null
            Copy-Item -Path "$StagingPath\$script:OSName\Support Files\MSS-Legacy.adml" -Destination "$Env:WinDir\PolicyDefinitions\en-US\MSS-Legacy.adml" | Out-Null
            "Copied MSS-Legacy admx/adml files to be used for their STIG settings."
        }
        Catch {
            "Failed to copy MSS-Legacy policies, due to: $_"
            Exit -1
        }
    }

    Try {
        Copy-Item -Path "$StagingPath\$script:OSName\Support Files\SecGuide.admx" -Destination "$Env:WinDir\PolicyDefinitions\SecGuide.admx" | Out-Null
        Copy-Item -Path "$StagingPath\$script:OSName\Support Files\SecGuide.adml" -Destination "$Env:WinDir\PolicyDefinitions\en-US\SecGuide.adml" | Out-Null
        "Copied SecGuide admx/adml files to be used for their STIG settings."
    }
    Catch {
        "Failed to copy SecGuide policies, due to: $_"
        Exit -1
    }

    If ($script:OSName -eq "2012R2") {
        Update-sceregvl
    }
}

#Function to apply group policies va LGPO.exe
Function Invoke-LGPO {

    [string]$GPBackupPath = "$StagingPath\$script:OSName\$Level"
    [string]$GPBackup = Get-ChildItem -Directory -Path $GPBackupPath
    $GPBackup = "$GPBackupPath\$GPBackup"

    If ($GPBackup -eq $null) {
        "No policy located."
        Cleanup
        Exit -1
    }

    Try {
        &"$StagingPath\Support Files\LGPO.exe" /g $GPBackup
    }
    Catch {
        "Failed to apply setting, due to: $_"
        Cleanup
        Exit -1
    }

    Try {
        &Gpupdate /force
    }
    Catch {
        "Failed to update group policy, due to: $_"
        Exit -1
    }
}

#Check InstallRoot Version
Function Check-InstallRoot {

    Try {
        $Installed = (Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like "*InstallRoot*" })
    }
    Catch {
        "Failed to check if InstallRoot is installed due to: $_"
        Exit -1
    }

    If ( $null -ne $Installed ) {
        [string]$major = $Installed.VersionMajor
        [string]$minor = $Installed.VersionMinor
        [string]$installedVersion = $major + "." + $minor

        Try {
            $winInstaller = New-Object -com WindowsInstaller.Installer
            $winInsDB = $winInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $Null, $winInstaller, @($IRmsi.FullName, 0))

            $query = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
            $view = $winInsDB.GetType().InvokeMember("OpenView", "InvokeMethod", $Null, $winInsDB, ($query))

            $view.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $view, $Null)
            $record = $View.GetType().InvokeMember( "Fetch", "InvokeMethod", $Null, $view, $Null )
            $MSIversion = $record.GetType().InvokeMember( "StringData", "GetProperty", $Null, $record, 1 )

        }
        Catch {
            "Unable to get the MSI version, due to: $_"
        }

        If ($installedVersion -ne $MSIversion) {
            Install-InstallRoot
        }
        Else {
            "InstallRoot already installed at the current version, $InstalledVersion"
        }
    }
    Else {
        Install-InstallRoot
    }
}

#Function to install InstallRoot
Function Install-InstallRoot {

    [UInt32]$MaxRetry = 3
    [string]$StateFile = "$StagingPath\sate_installroot.txt"
    [PSObject]$StateObj = Read-StateObject -Path $StateFile

    If ($stateObj.Install -eq "0") {
        "Attempting to install InstallRoot attempt $($StateObj.TryCount) of $($MaxRetry)."

        Try {
            $InstallRootInstall = Start-Process -Wait "$IRmsi" -ArgumentList '/q' -PassThru
        }
        Catch {
            "Failed to install InstallRoot, due to: $_"
        }

        If (($InstallRootInstall.ExitCode -eq 0) ) {
            "Installation was successful."
            $StateObj.Install = 1
            Write-StateObject -State $StateObj -Path $StateFile
        }
        Elseif (($StateObj.TryCount) -ge $MaxRetry) {
            Write-Warning "Rebooted and attempted to install $($StateObj.TryCount) times. Max retry count is 3, exiting."
            Throw "Rebooted and tried to install $($StateObj.TryCount) times. Max retry count is 3, exiting."
            Exit -1
        }
        Else {
            "Will reboot and retry $($MaxRetry - ($StateObj.TryCount)) more times."
            $StateObj.TryCount += 1
            ExitWithReboot
        }
    }
}

<#
    Windows STIG settings
#>

#Update sceregvl.inf on 2012 as required for multiple 2012 STIGs and check it.  Regsvr32 needs to run silently to prevent pluginrunner from hanging.
Function Update-sceregvl {

    [string]$ogsceregvl = "$Env:WinDir\Inf\sceregvl.inf"
    [string]$updatedsceregvl = "$StagingPath\2012R2\Support Files\sceregvl.inf"

    If (!(Get-Content -Path $ogsceregvl | Where-Object { $_ -match "MSS" })) {
        If (Test-Path "$Env:WinDir\Inf\sceregvl.old") {
            Remove-Item "$Env:WinDir\Inf\sceregvl.old"
        }

        If (Test-Path "$Env:WinDir\Inf\sceregvl.inf") {
            Try {
                takeown /f $ogsceregvl
                icacls $ogsceregvl /grant Administrators:f
                Rename-Item -Path $ogsceregvl -NewName "sceregvl.old" -Force
                Copy-Item -Path "$updatedsceregvl" -Destination $Env:WinDir\Inf
            }
            Catch {
                "Failed to replace sceregvl.inf, due to: $_."
                Exit -1
            }
        }
        Else {
            Copy-Item -Path $updatedsceregvl -Destination $Env:WinDir\Inf
        }

        regsvr32.exe scecli.dll /s
    }
    Else {
        "Sceregvl.inf has already been updated on this system."
    }
}

#Clear registry key of any stored passwords as per STIG V-1145
Function V-1145 {

    [string]$pswdPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"

    Try {
        New-ItemProperty -Path "$pswdPath" -Name "DefaultPassword" -Value $null -PropertyType DWord -Force
    }
    Catch {
        "Failed to clear stored passwords from registry, due to: $_. Not compliant with V-1145."
        Exit -1
    }
}

#Set Optional subsystems to blank per Vul ID V-4445
Function V-4445 {

    [string]$subsysReg = "HKLM:\System\CurrentControlSet\Control\Session Manager\Subsystems\"

    Try {
        New-ItemProperty -Path "$subsysReg" -Name "Optional" -Value $null -PropertyType MultiString -Force
    }
    Catch {
        "Failed to blank optional subsystems due to: $_. Not complaint with V-4445."
        Exit -1
    }
}

#Remove fax service per Vul ID V-26600\93383\73287
Function V-26600 {

    If (Get-WindowsFeature -Name Fax | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Fax
            "The fax service has been uninstalled from the system, per V-26600."
        }
        Catch {
            "Failed to uninstall the fax service due to: $_. Not compliant with V-26600."
            Exit -1
        }
    }
    Else {
        "The fax service is uninstalled from the system, per V-26600."
    }
}

#Remove MS FTP service per V-26602\93223\93225\73289\93421
Function V-26602 {

    If (Get-WindowsFeature -Name Web-FTP-Server | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Web-FTP-Server
            "The FTP service has been uninstalled, per V-26602."
        }
        Catch {
            "Failed to uninstall the FTP service, due to: $_. Not compliant with V-26602."
            Exit -1
        }
    }
    Else {
        "The FTP service is uninstalled from the system, per v-26602."
    }
}

#Remove Peer Networking Identity Manager (Peer Name Resolution Protocol) from server, per V-26604\73291\93385
Function V-26604 {

    If (Get-WindowsFeature -Name PNRP | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name PNRP
            "The Peer Networking Identity Manager service has been removed, per V-26604."
        }
        Catch {
            "Failed to uninstall Peer Networking Identity Manager service, due to: $_. Not compliant with V-26604."
            Exit -1
        }
    }
    Else {
        "The Peer Networking Identity Manager service has been removed, per V-26604."
    }
}

#Remove simple TCPIP service from server, per V-26605\93387\73293
Function V-26605 {

    If (Get-WindowsFeature -Name PNRP | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Simple-TCPIP
            "The Simple TCPIP service has been removed, per V-26605."
        }
        Catch {
            "Failed to uninstall Simple TCPIP service, due to: $_. Not compliant with V-26605."
            Exit -1
        }
    }
    Else {
        "The Simple TCPIP service has been removed, per V-26605."
    }
}

#Remove simple telnet client from server, per V-26606\93423\73295
Function V-26606 {

    If (Get-WindowsFeature -Name Telnet-Client | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Telnet-Client
            "The Telnet service has been removed, per V-26606."
        }
        Catch {
            "Failed to uninstall the Telnet service, due to: $_. Not compliant with V-26606."
            Exit -1
        }
    }
    Else {
        "The Telnet service has been removed, per V-26606."
    }
}

#Remove fax service per Vul ID V-36710
Function V-36710 {

    If (Get-WindowsFeature -Name Desktop-Experience | Where-Object InstallState -eq Installed) {
        Try {
            Uninstall-WindowsFeature -Name Desktop-Experience
            "The desktop experience has been uninstalled from the system, per V-36710."
        }
        Catch {
            "Failed to uninstall the desktop experience due to: $_. Not compliant with V-36710."
            Exit -1
        }
    }
    Else {
        "The fax service is uninstalled from the system, per V-26600."
    }
}

#Set Smart Card Removal Policy to start automatically per Vul ID V-40206 and check it.
Function V-40206 {

    Try {
        Set-Service SCPolicySvc -StartupType Automatic
        "Set the Smart Card Removal Policy Service to automatic, per V-40206."
    }
    Catch {
        "Failed to set the Smart Card Removal Policy Service to automatic due to $_. Not complaint with V-40206."
        Exit -1
    }
}

#
#Remove SMB 1 per Vul ID V-73299\93391, will require a restart to take full affect and check.
Function V-73299 {

    If (Get-WindowsFeature -Name FS-SMB1 | Where-Object InstallState -EQ Installed) {
        Try {
            Uninstall-WindowsFeature -Name FS-SMB1
            "SMB1 uninstalled from system, per V-73299."
        }
        Catch {
            "Failed to uninstall SMB1 due to: $_. Not complaint with V-73299."
            Exit -1
        }
    }
}

<#
Checks to see if InstallRoot is installed, required for various DoD certs.  STIG Vul ID's V-73605, V-73607, V-73609, V-32272, V-32274, V-40237, V-93487, V-93489,
V-93491.
If InstallRoot isn't installed will run the Install-InstallRoot function to install it.  Then cleans it after.
#>

Function V-73605 {

    Check-InstallRoot

    Try {
        &"$Env:Programfiles\DoD-PKE\InstallRoot\InstallRoot.exe" | Out-Null
        "Ran InstallRoot and Certificates Updated"
    }
    Catch {
        "Failed to run InstallRoot, due to: $_"
        Exit -1
    }

    Try {
        &"$StagingPath\Support Files\FBCA_crosscert_remover.exe" /s
    }
    Catch {
        "Failed to run the FBCA Crosscert Remover, due to: $_"
    }
}

#Disable SMBv1 support on a server per V-73805
Function V-73805 {

    Try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    }
    Catch {
        "Failed to Disable SMBv1, due to: $_. Not compliant with V-73805."
        Exit -1
    }
}

#Uninstall Powershell 2.0 per V-80477\93397\73301
Function V-80477 {

    Try {
        Uninstall-WindowsFeature -Name PowerShell-v2
    }
    Catch {
        "Failed to uninstall PowerShell V2, due to: $_. Not compliant with V-80477."
        Exit -1
    }
}

#Uninstall TFTP-Client per V-93389\73297
Function V-93389 {

    Try {
        Uninstall-WindowsFeature -Name TFTP-Client
    }
    Catch {
        "Failed to uninstall TFTP-Client, due to: $_. Not compliant with V-93389."
        Exit -1
    }
}

#Uninstall Web-FTP-Service per V-93421\73303\73305\73289
Function V-93421 {

    Try {
        Uninstall-WindowsFeature -Name Web-FTP-Service
    }
    Catch {
        "Failed to uninstall Web-FTP-Service, due to: $_. Not compliant with V-93421."
        Exit -1
    }
}

#Enable DEP per V-93313\93325\93329
Function V-93313 {

    Try {
        Set-Processmitigation -System -Enable DEP, EmulateAtlThunks
    }
    Catch {
        "Failed to set DEP to enabled, due to: $_. Not compliant with V-93313."
        Exit -1
    }
}

#Enable CFG per V-93315
Function V-93315 {

    Try {
        Set-Processmitigation -System -Enable CFG, StrictCFG, SuppressExports
    }
    Catch {
        "Failed to set CFG to enabled, due to: $_. Not compliant with V-93315."
        Exit -1
    }
}

#Enable SEHOP per V-93317
Function V-93317 {

    Try {
        Set-Processmitigation -System -Enable SEHOP, SEHOPTelemetry
    }
    Catch {
        "Failed to set SEHOP to enabled, due to: $_. Not compliant with V-93317."
        Exit -1
    }
}

#Enable Heap: TerminateOnError per V-93319
Function V-93319 {

    Try {
        Set-Processmitigation -System -Enable TerminateOnError
    }
    Catch {
        "Failed to set Heap: TerminateOnError to enabled, due to: $_. Not compliant with V-93319."
        Exit -1
    }
}

#Enable Bottum-Up ASLR per V-93565
Function V-93565 {

    Try {
        Set-Processmitigation -System -Enable BottomUp, HighEntropy
    }
    Catch {
        "Failed to set Bottom-Up ASLR to enabled, due to: $_. Not compliant with V-93565."
        Exit -1
    }
}

<#
STIG Vulnerabilities for Firewall
#>

#If Applying settings for the Firewall this will run
#Set Firewall log size per V-17425
Function V-17425 {

    Try {
        netsh advfirewall set domainprofile logging maxfilesize 16384
    }
    Catch {
        "Failed to set the domain firewall log size, due to: $_. Not compliant with V-17425."
        Exit -1
    }
}

Function V-17435 {

    Try {
        netsh advfirewall set privateprofile logging maxfilesize 16384
    }
    Catch {
        "Failed to set the private firewall log size, due to: $_. Not compliant with V-17435."
        Exit -1
    }
}

Function V-17445 {

    Try {
        netsh advfirewall set publicprofile logging maxfilesize 16384
    }
    Catch {
        "Failed to set the public firewall log size, due to: $_. Not compliant with V-17445."
        Exit -1
    }
}

#Set Firewall to log dropped packets V-17426\17436\17446
Function V-17426 {

    Try {
        netsh advfirewall set allprofiles logging droppedconnections enable
    }
    Catch {
        "Failed to set all firewall profiles to log dropped packets, due to $_. Not compliant with V-17426, V-17436, and V-17446."
        Exit -1
    }
}

#Set firewall to log successful connections V-17427\17437\17447
Function V-17427 {

    Try {
        netsh advfirewall set allprofiles logging allowedconnections enable
    }
    Catch {
        "Failed to set all firewall profiles to log successful connection, due to $_. Not compliant with V-17427, V-17437, and V-17447."
        Exit -1
    }
}

#Set the firewalls to be enabled. V-17415\17416\17417
Function V-17415 {

    Try {
        netsh advfirewall set allprofiles state on
    }
    Catch {
        "Failed to enable all firewall profiles, due to $_. Not compliant with V-17415, V-17416, and V-17417."
        Exit -1
    }
}

<#
STIG Vulnerabilities for .NetFramework.
#>

#.NetFramework 4 V-81495 Disable TLS RC4 cipher in .Net
Function V-81495 {

    [string]$TLSRC4Reg64 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"
    [string]$TLSRC4Reg32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\"

    Try {
        New-ItemProperty -Path "$TLSRC4Reg64" -Name "SchUseStrongCrypto" -Value 1 -PropertyType DWord -Force
        New-ItemProperty -Path "$TLSRC4Reg32" -Name "SchUseStrongCrypto" -Value 1 -PropertyType DWord -Force
    }
    Catch {
        "Failed to disable TLS RC4 ciper on .Net, not in compliance with V-81495. Due to $_"
        Exit -1
    }
}

<#
STIG Vulnerabilities for IE 11
#>

#IE 11 must check for publisher's certificate revocation
Function V-46477 {

    [string]$IEPublish = "HKCU:\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"

    Try {
        New-ItemProperty -Path $IEPublish -Name "State" -Value "146432" -PropertyType DWord -Force
    }
    Catch {
        "Failed to set IE to check the publisher's certificate revocation, not in compliance with V-46477. Due to $_"
        Exit -1
    }
}

#IE 11 must not allow VBScript to run in Internet Zone
Function V-75169 {

    [string]$internetZoneVB = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\"

    Try {
        New-ItemProperty -Path "$internetZoneVB" -Name "140C" -Value 3 -PropertyType DWord -Force
    }
    Catch {
        "Failed to set IE to not allow VBScript to run in the internet zone, not in compliance with V-75169. Due to $_"
        Exit -1
    }
}

#IE 11 must not allow VBScript to run in the restricted zone.
Function V-75171 {

    $restrictedVB = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\"

    Try {
        New-ItemProperty -Path "$restrictedVB" -Name "140C" -Value 3 -PropertyType DWord -Force
    }
    Catch {
        "Failed to set IE to not allow VBScript to run in the restricted zone, per V-75171. Due to $_"
        Exit -1
    }
}

#All the CatI\High STIGs
Function STIG-High {
    #Firewall STIGs
    V-17425
    V-17435
    V-17445
    V-17426
    V-17427
}

#ALL the CatII STIGs
Function STIG-Medium {
    #OS STIGs
    V-26600
    V-26602
    V-26604
    V-26605
    V-26606
    V-73605
    V-80477

    #.Net STIGs
    V-81495

    #IE STIGs
    V-75169
    V-75171

    #Firewall STIGs
    V-17415

    If ($script:OSName -eq "2012R2") {
        V-1145
        V-40206
        V-73805
    }
    ElseIf ($script:OSName -eq "2016" -or $script:OSName -eq "2019") {
        V-73299
        V-93389
        V-93421
    }
    ElseIf ($script:OSName -eq "2019") {
        V-93313
        V-93315
        V-93317
        V-93319
        V-93565
    }
}

#ALL the CATIII STIGs
Function STIG-Low {
    #OS STIGs
    V-36710

    If ($script:OSName -eq "2012R2") {
        V-4445
    }

    #Firewall STIGs
    V-17425
    V-17435
    V-17445
    V-17426
    V-17427

    #IE STIGs
    V-46477
}

#Apply STIGs
Function Apply-STIG {

    If ($Level -eq "Medium") {
        STIG-Medium
        STIG-Low
    }
    ElseIf ($Level -eq "High") {
        STIG-High
        STIG-Medium
        STIG-Low
    }
    ElseIf ($Level -eq "Low") {
        STIG-Low
    }
}

#Cleanup StigPrep
Function Cleanup {

    Try {
        Push-Location C:\
        Remove-Item -Path "$StagingPath" -Recurse
        Exit 0
    }
    Catch {
        "Failed to clean up the staging area, due to: $_"
        Exit -1
    }
}

#Validate/Set Level
If ($Level -like "High") {
    $Level = "High"
}
ElseIf ($Level -like "Medium") {
    $Level = "Medium"
}
ElseIf ($Level -like "Low") {
    $Level = "Low"
}
Else {
    "$Level is not a valid severity level, exiting."
    Exit -1
}

Identify-OS
Apply-ADML
Apply-STIG
Invoke-LGPO
Cleanup