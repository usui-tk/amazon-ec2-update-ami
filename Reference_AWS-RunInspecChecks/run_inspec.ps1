# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# PowerShell script to install InSpec and run checks.
# Results are reported to Compliance to after the run.

# Install ChefDK if not already installed
$CHEFDK_UNINSTALL=0

$chef = Get-WmiObject Win32_Product | select -ExpandProperty Name | select-string -Pattern "Chef Development Kit"
if (!$chef) {
  Write-Output "Installing Chef Development Kit"
  try {
    . { iwr -useb https://omnitruck.chef.io/install.ps1 -ErrorAction Stop} | iex -ErrorAction Stop 2>&1 | out-null
    install -channel stable -project chefdk 2>&1 | out-null
  } catch {
    Write-Output "Failed to install Chef Development Kit"
    exit 1
  }
  $CHEFDK_UNINSTALL=1
} else {
  Write-Output "Using existing Chef Development Kit"
}

# Add ChefDK to our path
$env:Path += ";C:\opscode\chefdk\bin"

# Use the ChefDK version of ruby
chef shell-init powershell | Invoke-Expression

# Ensure aws-sdk-ssm is installed
gem install --no-document aws-sdk-ssm

# Show inspec version
#$version_info=$(inspec --version)
#Write-Output "inspec $version_info"

# Run InSpec tests against this server and report compliance
$EXITCODE=0
Write-Output "Executing InSpec tests"

# Accept Chefdk license
$env:CHEF_LICENSE = "accept-no-persist"

# need to do this in two steps as inspec exits with error code if any tests fail
$results=inspec exec . --reporter json 2> errors.txt
$results | ruby ./report_compliance
if(!$?) {
  Write-Host "Failed to execute InSpec tests: see stderr"
  $EXITCODE=2
}

# Uninstall ChefDK if we installed it above
if ($CHEFDK_UNINSTALL -eq 1) {
  Write-Output "Uninstalling Chef Development Kit"
  $chef = Get-WmiObject Win32_Product | select -ExpandProperty Name | select-string -Pattern "Chef Development Kit"
  $application = Get-WmiObject Win32_Product -Filter "Name='$chef'"
  $application.Uninstall() | out-null
}

exit $EXITCODE
