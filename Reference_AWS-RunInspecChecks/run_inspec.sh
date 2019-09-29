#!/bin/sh

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

# Shell script to install InSpec and run checks.
# Results are reported to Compliance to after the run.
export HOME=/root
set -eo pipefail

# Install ChefDK if not already installed
CHEFDK_UNINSTALL=0
if ! [ -x "$(command -v inspec)" ]; then
  echo "Installing Chef Development Kit"
  curl -sS https://omnitruck.chef.io/install.sh | bash -s -- -c stable -P chefdk >> /dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo "Failed to install Chef Development Kit"
    exit 1
  fi
  CHEFDK_UNINSTALL=1
else
  echo "Using existing Chef Development Kit"
fi

# Use the ChefDK version of ruby
eval "$(chef shell-init sh)"


# Ensure aws-sdk-ssm is installed
gem install --no-document aws-sdk-ssm

# Show inspec version
#version_info=`inspec --version`
#echo "inspec $version_info"

# Run InSpec tests against this server and report compliance
EXITCODE=0
echo "Executing InSpec tests"

# Accept Chefdk license
export CHEF_LICENSE=accept-no-persist

# unset pipefail as inspec exits with error code if any tests fail
set +eo pipefail
inspec exec . --reporter json | ruby ./report_compliance
if [ $? -ne 0 ]; then
  echo "Failed to execute InSpec tests: see stderr"
  EXITCODE=2
fi

# Uninstall ChefDK if we installed it above
if [ "$CHEFDK_UNINSTALL" = "1" ]; then
  # use the appropriate package manager
  echo "Uninstalling Chef Development Kit"
  if [ -x "$(command -v yum)" ]; then
    PACKAGE=`rpm -qa *chefdk*`
    yum remove -y $PACKAGE >> /dev/null 2>&1
  else
    dpkg -P chefdk >> /dev/null 2>&1
  fi
fi

exit $EXITCODE
