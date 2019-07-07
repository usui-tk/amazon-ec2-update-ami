# Parameter
Set-Variable -Name BASE_DIR -Value "$Env:SystemDrive\EC2-Bootstrap"
Set-Variable -Name TOOL_DIR -Value "$BASE_DIR\Tools"
Set-Variable -Name LOGS_DIR -Value "$BASE_DIR\Logs"
Set-Variable -Name TEMP_DIR -Value "$Env:SystemRoot\Temp"
Set-Variable -Name USERDATA_LOG -Value "$TEMP_DIR\userdata.log"
Set-Variable -Name TRANSCRIPT_LOG -Value "$LOGS_DIR\userdata-transcript.log"

# Function
function Format-Message {
    param([string]$message)
    
    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff zzz"
    "$timestamp - $message"
}

function Write-Log {
    param([string]$message, $log = $USERDATA_LOG)
    
    Format-Message $message | Out-File $log -Append -Force
}

function Write-LogSeparator {
    param([string]$message)
    Write-Log "#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    Write-Log ("#   Script Executetion Step : " + $message)
    Write-Log "#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
}

function New-Directory {
    param([string]$dir)

    if (!(Test-Path -Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force
    }
}

function Get-WebContentToFile {
    Param([String]$Uri, [String]$OutFile)
    Set-Variable -Name DownloadStatus -Value ($Null)
    Set-Variable -Name ProgressPreference -Value "SilentlyContinue"
    Write-Log ("# [Get-WebContentToFile] Download processing start    [" + $Uri + "] -> [" + $OutFile + "]" )
    $DownloadStatus = Measure-Command { (Invoke-WebRequest -Uri $Uri -UseBasicParsing -OutFile $OutFile) } 
    Write-Log ("# [Get-WebContentToFile] Download processing time      ( " + $DownloadStatus.TotalSeconds + " seconds )" )
    Write-Log ("# [Get-WebContentToFile] Download processing complete [" + $Uri + "] -> [" + $OutFile + "]" )
}

function Get-WindowsServerInformation {
    Set-Variable -Name productName -Value ($Null)
    Set-Variable -Name installOption -Value ($Null)
    Set-Variable -Name osVersion -Value ($Null)
    Set-Variable -Name osBuildLabEx -Value ($Null)
    Set-Variable -Name windowInfoKey -Value "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    Set-Variable -Name fullServer -Value "Full"
    Set-Variable -Name nanoServer -Value "Nano"
    Set-Variable -Name serverCore -Value "Server Core"
    Set-Variable -Name serverOptions -Value @{ 0 = "Undefined"; 12 = $serverCore; 13 = $serverCore;
        14 = $serverCore; 29 = $serverCore; 39 = $serverCore; 40 = $serverCore; 41 = $serverCore; 43 = $serverCore;
        44 = $serverCore; 45 = $serverCore; 46 = $serverCore; 63 = $serverCore; 143 = $nanoServer; 144 = $nanoServer;
        147 = $serverCore; 148 = $serverCore; 
    }

    # Get ProductName and BuildLabEx from HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    if (Test-Path $windowInfoKey) {
        $windowInfo = Get-ItemProperty -Path $windowInfoKey
        $productName = $windowInfo.ProductName
        $osBuildLabEx = $windowInfo.BuildLabEx

        if ($windowInfo.CurrentMajorVersionNumber -and $windowInfo.CurrentMinorVersionNumber) {
            $osVersion = ("{0}.{1}" -f $windowInfo.CurrentMajorVersionNumber, $windowInfo.CurrentMinorVersionNumber)
        }
    }

    # Get Version and SKU from Win32_OperatingSystem
    $osInfo = Get-CimInstance Win32_OperatingSystem | Select-Object Version, OperatingSystemSKU
    $osSkuNumber = [int]$osInfo.OperatingSystemSKU
    if (-not $osVersion -and $osInfo.Version) {
        $osVersionSplit = $osInfo.Version.Split(".")
        if ($osVersionSplit.Count -gt 1) {
            $osVersion = ("{0}.{1}" -f $osVersionSplit[0], $osVersionSplit[1])
        }
        elseif ($osVersionSplit.Count -eq 1) {
            $osVersion = ("{0}.0" -f $osVersionSplit[0])
        }
    }

    if ($serverOptions[$osSkuNumber]) {
        $installOption = $serverOptions[$osSkuNumber]
    }
    else {
        $installOption = $fullServer
    }

    Write-Log ("# [Windows] Microsoft Windows NT version : {0}" -f $osVersion)
    Write-Log ("# [Windows] Windows Server OS Product Name : {0}" -f $productName)
    Write-Log ("# [Windows] Windows Server OS Install Option : {0}" -f $installOption)
    Write-Log ("# [Windows] Windows Server OS Version : {0}" -f $osVersion)
    Write-Log ("# [Windows] Windows Server Build Lab Ex : {0}" -f $osBuildLabEx)
    Write-Log ("# [Windows] Windows Server OS Language : {0}" -f ([CultureInfo]::CurrentCulture).IetfLanguageTag)
    Write-Log ("# [Windows] Windows Server OS TimeZone : {0}" -f ([TimeZoneInfo]::Local).StandardName)
    Write-Log ("# [Windows] Windows Server OS Offset : {0}" -f ([TimeZoneInfo]::Local).GetUtcOffset([DateTime]::Now))
    Set-Variable -Name WindowsOSVersion -Value ($osVersion.ToString())
    Set-Variable -Name WindowsOSLanguage -Value (([CultureInfo]::CurrentCulture).IetfLanguageTag)
}

#---------------------------------------------------------------------------------------------------------------------------

# Start of script
Set-Variable -Name ScriptFullPath -Value ($MyInvocation.InvocationName)
New-Directory $BASE_DIR
New-Directory $TOOL_DIR
New-Directory $LOGS_DIR
Start-Transcript -Path "$TRANSCRIPT_LOG" -Append -Force
Set-Location -Path $BASE_DIR

Write-LogSeparator "Start Script Execution Bootstrap Script"


# Exe-1 
Write-LogSeparator "Change PowerShell SecurityProtocol"
[System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12;

# Exe-2
Write-LogSeparator "Windows Server OS Configuration [Windows Time Service (w32tm) Setting]"
Set-Variable -Name W32TM -Value "C:\Windows\System32\w32tm.exe"
Start-Process -FilePath $W32TM -Verb runas -Wait -ArgumentList @("/config /update /manualpeerlist:169.254.169.123 /syncfromflags:manual")

# Exe-3
Write-LogSeparator "Windows Server OS Configuration [Folder Option Setting]"
Set-Variable -Name HKLM_FolderOptionRegistry -Option Constant -Scope Local -Value "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-Variable -Name HKCU_FolderOptionRegistry -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

if (Test-Path -Path $HKLM_FolderOptionRegistry) {
    # [Check] Show hidden files, folders, or drives
    if ((Get-Item -Path $HKLM_FolderOptionRegistry).GetValueNames() -contains 'Hidden') {
        Set-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'Hidden' -Value '1' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_FolderOptionRegistry + "\Hidden")
    }
    else {
        New-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'Hidden' -Value '1' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_FolderOptionRegistry + "\Hidden")
    }

    # [UnCheck] Hide extensions for known file types
    if ((Get-Item -Path $HKLM_FolderOptionRegistry).GetValueNames() -contains 'HideFileExt') {
        Set-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_FolderOptionRegistry + "\HideFileExt")
    }
    else {
        New-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_FolderOptionRegistry + "\HideFileExt")
    }

    # [Check] Restore previous folders windows
    if ((Get-Item -Path $HKLM_FolderOptionRegistry).GetValueNames() -contains 'PersistBrowsers') {
        Set-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_FolderOptionRegistry + "\PersistBrowsers")
    }
    else {
        New-ItemProperty -Path $HKLM_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_FolderOptionRegistry + "\PersistBrowsers")
    }
}

if ( -Not (Test-Path -Path $HKCU_FolderOptionRegistry ) ) {
    Write-Log ("# New-Item - " + $HKCU_FolderOptionRegistry)
    New-Item -Path $HKCU_FolderOptionRegistry -Force 
    Start-Sleep -Seconds 5
}

if (Test-Path -Path $HKCU_FolderOptionRegistry) {
    # [Check] Show hidden files, folders, or drives
    if ((Get-Item -Path $HKCU_FolderOptionRegistry).GetValueNames() -contains 'Hidden') {
        Set-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'Hidden' -Value '1' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_FolderOptionRegistry + "\Hidden")
    }
    else {
        New-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'Hidden' -Value '1' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_FolderOptionRegistry + "\Hidden")
    }

    # [UnCheck] Hide extensions for known file types
    if ((Get-Item -Path $HKCU_FolderOptionRegistry).GetValueNames() -contains 'HideFileExt') {
        Set-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_FolderOptionRegistry + "\HideFileExt")
    }
    else {
        New-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'HideFileExt' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_FolderOptionRegistry + "\HideFileExt")
    }

    # [Check] Restore previous folders windows
    if ((Get-Item -Path $HKCU_FolderOptionRegistry).GetValueNames() -contains 'PersistBrowsers') {
        Set-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_FolderOptionRegistry + "\PersistBrowsers")
    }
    else {
        New-ItemProperty -Path $HKCU_FolderOptionRegistry -Name 'PersistBrowsers' -Value '1' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_FolderOptionRegistry + "\PersistBrowsers")
    }
}

# Exe-4
Write-LogSeparator "Windows Server OS Configuration [Display Desktop Icon Setting]"
Set-Variable -Name HKLM_DesktopIconRegistrySetting -Option Constant -Scope Local -Value "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
Set-Variable -Name HKCU_DesktopIconRegistry -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
Set-Variable -Name HKCU_DesktopIconRegistrySetting -Option Constant -Scope Local -Value "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"

if (Test-Path -Path $HKLM_DesktopIconRegistrySetting) {
    #[CLSID] : My Computer
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{20D04FE0-3AEA-1069-A2D8-08002B30309D}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }

    #[CLSID] : Control Panel
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }

    #[CLSID] : User's Files
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{59031a47-3f72-44a7-89c5-5595fe6b30ee}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }

    #[CLSID] : Recycle Bin
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{645FF040-5081-101B-9F08-00AA002F954E}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }

    #[CLSID] : Network
    if ((Get-Item -Path $HKLM_DesktopIconRegistrySetting).GetValueNames() -contains '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}') {
        Set-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
    else {
        New-ItemProperty -Path $HKLM_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKLM_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
}

if ( -Not (Test-Path -Path $HKCU_DesktopIconRegistry ) ) {
    Write-Log ("# New-Item - " + $HKCU_DesktopIconRegistry)
    New-Item -Path $HKCU_DesktopIconRegistry -Force 
    Start-Sleep -Seconds 5

    Write-Log ("# New-Item - " + $HKCU_DesktopIconRegistrySetting)
    New-Item -Path $HKCU_DesktopIconRegistrySetting -Force 
    Start-Sleep -Seconds 5
}

if (Test-Path -Path $HKCU_DesktopIconRegistrySetting) {
    #[CLSID] : My Computer
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{20D04FE0-3AEA-1069-A2D8-08002B30309D}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    }

    #[CLSID] : Control Panel
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}")
    }

    #[CLSID] : User's Files
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{59031a47-3f72-44a7-89c5-5595fe6b30ee}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{59031a47-3f72-44a7-89c5-5595fe6b30ee}")
    }

    #[CLSID] : Recycle Bin
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{645FF040-5081-101B-9F08-00AA002F954E}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{645FF040-5081-101B-9F08-00AA002F954E}")
    }

    #[CLSID] : Network
    if ((Get-Item -Path $HKCU_DesktopIconRegistrySetting).GetValueNames() -contains '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}') {
        Set-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -Force
        Write-Log ("# Set-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
    else {
        New-ItemProperty -Path $HKCU_DesktopIconRegistrySetting -Name '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' -Value '0' -PropertyType "DWord" -Force
        Write-Log ("# New-ItemProperty - " + $HKCU_DesktopIconRegistrySetting + "\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}")
    }
}

# Exec-5
Write-LogSeparator "Windows Server OS Configuration [Network Connection Profile Setting]"
Set-NetConnectionProfile -InterfaceAlias (Get-NetConnectionProfile -IPv4Connectivity Internet).InterfaceAlias -NetworkCategory Private
Start-Sleep -Seconds 5

# Exec-6
Write-LogSeparator "Windows Server OS Configuration [IPv6 Disable Setting]"

if (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Amazon Elastic Network Adapter" }) {
    Disable-NetAdapterBinding -InterfaceDescription "Amazon Elastic Network Adapter" -ComponentID ms_tcpip6 -Confirm:$false
}
elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "Intel(R) 82599 Virtual Function" }) {
    Disable-NetAdapterBinding -InterfaceDescription "Intel(R) 82599 Virtual Function" -ComponentID ms_tcpip6 -Confirm:$false
}
elseif (Get-NetAdapter | Where-Object { $_.InterfaceDescription -eq "AWS PV Network Device #0" }) {
    Disable-NetAdapterBinding -InterfaceDescription "AWS PV Network Device #0" -ComponentID ms_tcpip6 -Confirm:$false
}
else {
    Write-Log "# [Windows - OS Settings] Disable-NetAdapterBinding(IPv6) : No Target Device"
}

Start-Sleep -Seconds 5

# Exec-7
Write-LogSeparator "Windows Server OS Configuration [System PowerPlan]"
$Guid_HighPower = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
Start-Process "powercfg.exe" -Verb runas -Wait -ArgumentList @("/setactive", "$Guid_HighPower")
Start-Sleep -Seconds 5

# Exec-8
Write-LogSeparator "Package Install System Utility (AWS-CLI)"
Get-WebContentToFile -Uri 'https://s3.amazonaws.com/aws-cli/AWSCLI64PY3.msi' -OutFile "$TOOL_DIR\AWSCLI64PY3.msi"
Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\AWSCLI64PY3.msi", "/qn", "/L*v $LOGS_DIR\APPS_AWS_AWSCLISetup.log")
Start-Sleep -Seconds 5

# Exec-9
Write-LogSeparator "Package ReInstall[Uninstall and Install] (AWS CloudFormation Helper Scripts)"
(Get-WmiObject -Class Win32_Product -Filter "Name='aws-cfn-bootstrap'" -ComputerName . ).Uninstall()
Start-Sleep -Seconds 5
Get-WebContentToFile -Uri 'https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-win64-latest.msi' -OutFile "$TOOL_DIR\aws-cfn-bootstrap-win64-latest.msi"
Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\aws-cfn-bootstrap-win64-latest.msi", "/qn", "/L*v $LOGS_DIR\APPS_AWS_AWSCloudFormationHelperScriptSetup.log")
Start-Sleep -Seconds 5
Get-Service -Name "cfn-hup"

# Exec-10
Write-LogSeparator "Package Install System Utility (Amazon CloudWatch Agent)"
Get-WebContentToFile -Uri 'https://s3.amazonaws.com/amazoncloudwatch-agent/windows/amd64/latest/amazon-cloudwatch-agent.msi' -OutFile "$TOOL_DIR\amazon-cloudwatch-agent.msi"
Start-Process "msiexec.exe" -Verb runas -Wait -ArgumentList @("/i $TOOL_DIR\amazon-cloudwatch-agent.msi", "/qn", "/L*v $LOGS_DIR\APPS_AWS_AmazonCloudWatchAgentSetup.log")
Start-Sleep -Seconds 5
Get-Service -Name "AmazonCloudWatchAgent"
powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" -m ec2 -a status
Get-Service -Name "AmazonCloudWatchAgent"

# Exec-11
Write-LogSeparator "Package Install System Utility (Amazon Inspector Agent)"
Get-WebContentToFile -Uri 'https://d1wk0tztpsntt1.cloudfront.net/windows/installer/latest/AWSAgentInstall.exe' -OutFile "$TOOL_DIR\AWSAgentInstall.exe"
Start-Process -FilePath "$TOOL_DIR\AWSAgentInstall.exe" -Verb runas -ArgumentList @('/install', '/quiet', '/norestart', '/log C:\EC2-Bootstrap\Logs\APPS_AWS_AmazonInspecterAgentSetup.log') -Wait | Out-Null
Start-Sleep -Seconds 10
Get-Service -Name "AWSAgent"
Set-Service -Name "AWSAgent" -StartupType Automatic
Start-Service -Name "AWSAgent"
Start-Sleep -Seconds 15
Get-Service -Name "AWSAgent"

# Exec-12
Write-LogSeparator "Package Install System Utility (Visual Studio Code)"
Get-WebContentToFile -Uri 'https://go.microsoft.com/fwlink/?linkid=852157' -OutFile "$TOOL_DIR\VSCodeSetup-x64.exe"
Start-Process -FilePath "$TOOL_DIR\VSCodeSetup-x64.exe" -Verb runas -Wait -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/mergetasks=!runCode, desktopicon, quicklaunchicon, addcontextmenufiles, addcontextmenufolders, addtopath", "/LOG=C:\EC2-Bootstrap\Logs\APPS_VSCodeSetup.log") | Out-Null

# Exec-Last
Write-LogSeparator "Collect Script/Config Files & Logging Data Files"

Get-WebContentToFile -Uri 'https://s3.amazonaws.com/ec2rescue/windows/EC2Rescue_latest.zip' -OutFile "$TOOL_DIR\EC2Rescue_latest.zip"

Add-Type -AssemblyName 'System.IO.Compression.Filesystem'
[System.IO.Compression.ZipFile]::ExtractToDirectory("$TOOL_DIR\EC2Rescue_latest.zip", "$TOOL_DIR\EC2Rescue_latest")

Write-Log "# Execution System Utility (EC2Rescue) - Start"
Start-Process -FilePath "$TOOL_DIR\EC2Rescue_latest\EC2RescueCmd.exe" -Verb runas -PassThru -Wait -ArgumentList @("/accepteula", "/online", "/collect:all", "/output:$LOGS_DIR\EC2RescueCmd.zip") | Out-Null
Write-Log "# Execution System Utility (EC2Rescue) - Complete"

Write-LogSeparator "Complete Script Execution Bootstrap Script"
Copy-Item -Path $USERDATA_LOG -Destination $LOGS_DIR 
Copy-Item -Path "$TEMP_DIR\userdata-transcript-*.log" -Destination $LOGS_DIR
Copy-Item -Path "$TEMP_DIR\*.tmp" -Destination $LOGS_DIR 
Stop-Transcript
Start-Sleep -Seconds 15

# Setting Hostname
Set-Variable -Name PrivateIp -Value (Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/local-ipv4")
Set-Variable -Name Hostname -Value ($PrivateIp.Replace(".", "-"))
Rename-Computer $Hostname -Force
