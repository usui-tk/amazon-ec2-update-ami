# Parameter
Set-Variable -Name BASE_DIR -Value "$Env:SystemDrive\EC2-Bootstrap"
Set-Variable -Name TEMP_DIR -Value "$Env:SystemRoot\Temp"

# Function
function Format-Message {
    param([string]$message)
    
    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss.fffffff zzz"
    "$timestamp - $message"
}

function Write-Message {
    param([string]$message)
    
    Format-Message $message
}

function Write-MessageSeparator {
    param([string]$message)
    Write-Message "#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
    Write-Message ("#   Script Executetion Step : " + $message)
    Write-Message "#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------"
}

#---------------------------------------------------------------------------------------------------------------------------

# Start of script
Write-MessageSeparator "Start Script Execution Cleanup Script"

# Delete Bootstrap working directory
if (Test-Path -Path $BASE_DIR) {
    Write-Message ("# Delete directory [" + $BASE_DIR + "]")
    Remove-Item -Path $BASE_DIR -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}

# Delete Windows TEMP directory
if (Test-Path -Path $TEMP_DIR) {
    Write-Message ("# Delete directory [" + $TEMP_DIR + "]")
    Remove-Item -Path $TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}

# Delete RecycleBin's files
if (Get-Command -CommandType Cmdlet | Where-Object { $_.Name -eq "Clear-RecycleBin" }) {
    Write-Message "# Delete RecycleBin's files [Clear-RecycleBin]"
    Clear-RecycleBin -DriveLetter "C" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}
else {
    Write-Message "# Delete RecycleBin's files [Remove-Item]"
    Get-ChildItem -Path 'C:\$Recycle.Bin' -Force | Remove-Item -Recurse -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
}

# Clear AWS Utility and Tool Log
Set-Variable -Name Ec2ConfigLogFile -Value "C:\Program Files\Amazon\Ec2ConfigService\Logs\Ec2ConfigLog.txt"
if (Test-Path -Path $Ec2ConfigLogFile) {
    Write-Message ("# Clear file [" + $Ec2ConfigLogFile + "]")
    Clear-Content -Path $Ec2ConfigLogFile -Force -ErrorAction SilentlyContinue
}

Set-Variable -Name Ec2LaunchLogFile -Value "C:\ProgramData\Amazon\EC2-Windows\Launch\Log\Ec2Launch.log"
if (Test-Path -Path $Ec2LaunchLogFile) {
    Write-Message ("# Clear file [" + $Ec2LaunchLogFile + "]")
    Clear-Content -Path $Ec2LaunchLogFile -Force -ErrorAction SilentlyContinue
}

Set-Variable -Name SSMAgentLogFile -Value "C:\ProgramData\Amazon\SSM\Logs\amazon-ssm-agent.log"
if (Test-Path -Path $SSMAgentLogFile) {
    Write-Message ("# Clear file [" + $SSMAgentLogFile + "]")
    Clear-Content -Path $SSMAgentLogFile -Force -ErrorAction SilentlyContinue
}

Set-Variable -Name CWAgentLogFile -Value "C:\ProgramData\Amazon\AmazonCloudWatchAgent\Logs\amazon-cloudwatch-agent.log"
if (Test-Path -Path $CWAgentLogFile) {
    Write-Message ("# Clear file [" + $CWAgentLogFile + "]")
    Clear-Content -Path $CWAgentLogFile -Force -ErrorAction SilentlyContinue
}

# Clear Windows Event Log
if (Get-Command -CommandType Cmdlet | Where-Object { $_.Name -eq "Clear-EventLog" }) {
    Write-Message "# Clear Windows Event Log [Get-EventLog (Before Cleanup EventLog)]"
    Get-EventLog -List
    Write-Message "# Clear Windows Event Log [Clear-EventLog]"
    Get-EventLog -LogName * | ForEach-Object -Process { Clear-EventLog $_.Log -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 5
    Write-Message "# Clear Windows Event Log [Get-EventLog (After Cleanup EventLog)]"
    Get-EventLog -List
}
else {
    Write-Message "# Clear Windows Event Log [Get-EventLog (Before Cleanup EventLog)]"
    Get-EventLog -List
    Write-Message "# Clear Windows Event Log [GlobalSession.ClearLog]"
    Get-WinEvent -ListLog * | ForEach-Object -Process { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }
    Start-Sleep -Seconds 5
    Write-Message "# Clear Windows Event Log [Get-EventLog (After Cleanup EventLog)]"
    Get-EventLog -List
}

# Clear PowerShell history
Get-History
Clear-History

Write-MessageSeparator "Complete Script Execution Cleanup Script"
