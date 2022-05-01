function Is-TLSVersion-Enabled {
    param( [string]$TLSVersion )
    [string] $TLSRegKey = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS " + $TLSVersion + "\Client"
    if (Test-path -path Registry::$TLSRegKey)
    {
      $TLSClientReg = Get-ItemProperty -Path Registry::$TLSRegKey
      $TLSClientReg.Enabled -gt 0
    }
    else
    {
      $True
    }
  }
  if (Is-TLSVersion-Enabled "1.2")
  {
    Write-Host "Using TLS 1.2"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::TLS12
  }
  elseif (Is-TLSVersion-Enabled "1.1")
  {
    Write-Host "Using TLS 1.1"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::TLS11
  }
  elseif (Is-TLSVersion-Enabled "1.0")
  {
    Write-Host "Defaulting to TLS 1.0"
  }
  else
  {
    Write-Host "Installation failed, All supported TLS protocols are disabled"
    Write-Host $_.Exception|format-list -force
    exit 7
  }
  $tempdir = split-path -parent $MyInvocation.MyCommand.Definition
  Set-Location -Path $tempdir
  $thumbprint=""
  $agentInstaller="AWSAgentInstall.exe"
  $token =%{iwr -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri http://169.254.169.254/latest/api/token -UseBasicParsing | Select-Object -Expand Content}
  $tokenHeader = @{}
  if (-not ([string]::IsNullOrEmpty($token)))
  {
    $tokenHeader = @{"X-aws-ec2-metadata-token" = "$token"}
  }
  $region=%{iwr -Headers $tokenHeader http://169.254.169.254/latest/meta-data/placement/availability-zone -UseBasicParsing | Select-Object -Expand Content | %{$_.TrimEnd([char[]]([char]"a"..[char]"z"))}}
  if ([string]::IsNullOrWhiteSpace($region))
  {
    Write-Host "Failed to retrieve instance region from meta-data"
    exit 1
  }
  if ($Env:os -ne "Windows_NT")
  {
    Write-Host "This step of SSM document can only install the Amazon Inspector Agent on Windows servers"
    exit 1
  }
  function Send-Metric {
    Param([string]$result,[string]$result_param)
    $partialMetricsUrl="https://s3.dualstack." + $region + ".amazonaws.com/aws-agent." + $region + "/windows/awsagent/inventory.cab?x-installer-version=1.0.2&x-installer-type=ssm-installer&x-op={{Operation}}"
    $metricsUrl=$partialMetricsUrl + "&x-result=" + $result + "&x-result-param=" + $result_param
    Try
    {
      Invoke-WebRequest -Method Head $metricsUrl
    }
    Catch
    {
    }
  }
  if (Get-Service "AWS Agent Service" -ErrorAction SilentlyContinue)
  {
    Write-Host "AWS Agent is already installed, Exiting"
    exit 0
  }
  $installerUrl="https://s3.dualstack." + $region + ".amazonaws.com/aws-agent." + $region + "/windows/installer/latest/$agentInstaller"
  Try
  {
    Invoke-WebRequest $installerUrl -OutFile $agentInstaller
  }
  Catch
  {
    Send-Metric "FILE_DOWNLOAD_ERROR" "$agentInstaller"
    Write-Host "Error while downloading installer"
    Write-Host $_.Exception|format-list -force
    exit 3
  }
  Try
  {
    $installerSig=Get-AuthenticodeSignature -FilePath $agentInstaller
    $thumbprint=$installerSig.SignerCertificate.Thumbprint
    $certificateStatus=$installerSig.Status
    Write-Host "Thumbprint: " $thumbprint
    Write-Host "Certificate status: " $certificateStatus
  }
  Catch
  {
    Send-Metric "THUMBPRINT_RETRIEVAL_ERROR" "$agentInstaller"
    Write-Host "Error while retrieving installer certificate thumbprint"
    Write-Host $_.Exception|format-list -force
    exit 4
  }
  if ($certificateStatus.value__ -ne [System.Management.Automation.SignatureStatus]::Valid.value__)
  {
    Send-Metric "CERTIFICATE_INVALID" "$agentInstaller"
    Write-Host "This is not signed by a valid certificate : " $thumbprint
    exit 7
  }
  else
  {
    Write-Host "Certificate validated "
  }
  $PREVIOUS_CERTIFICATE_THUMBPRINT = "166749A7B8CC5B8A571DDF4B7A379DB16A5E6580"
  $LATEST_CERTIFICATE_THUMBPRINT = "B0ADCEEF6292D4AAD1B03E32FBC342F4A2C0D179"
  if (($thumbprint -ne $LATEST_CERTIFICATE_THUMBPRINT) -and ($thumbprint -ne $PREVIOUS_CERTIFICATE_THUMBPRINT))
  {
    Send-Metric "SIGNATURE_MISMATCH" "$agentInstaller"
    Write-Host "Invalid installer signature : " $thumbprint
    exit 5
  }
  else
  {
    Write-Host "Signature validated : " $thumbprint
  }
  Try
  {
    $p = (Start-Process -FilePath ".\$agentInstaller" -ArgumentList "/install /quiet /norestart" -Wait -NoNewWindow -PassThru).ExitCode
    if ($p -eq 3010)
    {
      Write-Host "Installation succeeded, but there were files in use, please restart to complete installation."
      exit 0
    }
    elseif ($p -eq 0)
    {
      Write-Host "Installation succeeded"
    }
    else
    {
      Write-Host "Installation failed : "  $p
    }
    exit $p
  }
  Catch
  {
    Send-Metric "INSTALLATION_FAILURE" "$agentInstaller" ""
    Write-Host "Installation failed, exception raised during installation"
    Write-Host $_.Exception|format-list -force
    exit 6
  }
