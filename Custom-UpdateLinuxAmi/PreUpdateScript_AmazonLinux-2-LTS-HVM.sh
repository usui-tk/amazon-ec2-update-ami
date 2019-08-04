#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - Amazon Linux 2 
#    https://aws.amazon.com/jp/amazon-linux-2/
#    https://aws.amazon.com/jp/amazon-linux-2/release-notes/
#    https://aws.amazon.com/jp/amazon-linux-2/faqs/
#    https://cdn.amazonlinux.com/os-images/latest/
#
#    https://github.com/amazonlinux
#
#    http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-linux-ami-basics.html
#-------------------------------------------------------------------------------

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

cat /etc/system-release

cat /etc/image-id

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [yum command]
yum list installed > /tmp/command-log_yum_installed-package.txt

# Default repository package [yum command]
yum list all > /tmp/command-log_yum_repository-package-list.txt

# Special package information
amazon-linux-extras list

# systemd service config
systemctl list-unit-files --no-pager -all > /tmp/command-log_systemctl_list-unit-files.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# yum repository metadata Clean up
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install Amazon Linux System Administration Tools (from Amazon Official Repository)
yum install -y acpid arptables bash-completion bc dstat dmidecode ebtables fio gdisk git hdparm jq lsof lzop iperf3 iotop mlocate mtr nc nmap nvme-cli numactl perf rsync strace sysstat system-lsb-core tcpdump traceroute tree uuid vim-enhanced yum-plugin-versionlock yum-utils wget zstd
yum install -y amazon-efs-utils cifs-utils nfs-utils nfs4-acl-tools
yum install -y iscsi-initiator-utils lsscsi scsi-target-utils sdparm sg3_utils

# Package Install Amazon Linux Specific Tools (from Amazon Official Repository)
yum install -y ec2-hibinit-agent hibagent 

#-------------------------------------------------------------------------------
# Set AWS Instance MetaData
#-------------------------------------------------------------------------------

# Instance MetaData
AZ=$(curl -s "http://169.254.169.254/latest/meta-data/placement/availability-zone")
Region=$(echo $AZ | sed -e 's/.$//g')
InstanceId=$(curl -s "http://169.254.169.254/latest/meta-data/instance-id")
InstanceType=$(curl -s "http://169.254.169.254/latest/meta-data/instance-type")
PrivateIp=$(curl -s "http://169.254.169.254/latest/meta-data/local-ipv4")
AmiId=$(curl -s "http://169.254.169.254/latest/meta-data/ami-id")

# IAM Role & STS Information
if [ $(command -v jq) ]; then
    RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
	RoleName=$(echo $RoleArn | cut -d '/' -f 2)
fi

if [ -n "$RoleName" ]; then
	StsCredential=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$RoleName")
	if [ $(command -v jq) ]; then
		StsAccessKeyId=$(echo $StsCredential | jq -r '.AccessKeyId')
		StsSecretAccessKey=$(echo $StsCredential | jq -r '.SecretAccessKey')
		StsToken=$(echo $StsCredential | jq -r '.Token')
	fi
fi

# AWS Account ID
if [ $(command -v jq) ]; then
    AwsAccountId=$(curl -s "http://169.254.169.254/latest/dynamic/instance-identity/document" | jq -r '.accountId')
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------
aws --version

# Setting AWS-CLI default Region & Output format
aws configure << __EOF__ 



json

__EOF__

# Setting AWS-CLI Logging
aws configure set cli_history enabled

# Getting AWS-CLI default Region & Output format
aws configure list
cat ~/.aws/config

# Get AWS Region Information
if [ -n "$RoleName" ]; then
	echo "# Get AWS Region Infomation"
	aws ec2 describe-regions --region ${Region}
fi

#-------------------------------------------------------------------------------
# Custom Package Update [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------
# yum localinstall -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"
# yum localinstall -y "https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm"

# yum install -y amazon-ssm-agent

rpm -qi amazon-ssm-agent

# systemctl daemon-reload

systemctl status -l amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

# systemctl restart amazon-ssm-agent
# systemctl status -l amazon-ssm-agent

# ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
# https://docs.aws.amazon.com/inspector/latest/userguide/inspector_installing-uninstalling-agents.html
#-------------------------------------------------------------------------------

curl -sS "https://inspector-agent.amazonaws.com/linux/latest/install" -o "/tmp/Install-Amazon-Inspector-Agent"

chmod 700 /tmp/Install-Amazon-Inspector-Agent
bash /tmp/Install-Amazon-Inspector-Agent

rpm -qi AwsAgent

/opt/aws/awsagent/bin/awsagent status

# Configure Amazon Inspector Agent software (Start Daemon awsagent)
systemctl status awsagent
systemctl enable awsagent
systemctl is-enabled awsagent

systemctl restart awsagent
systemctl status awsagent

/opt/aws/awsagent/bin/awsagent status

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
#-------------------------------------------------------------------------------

yum localinstall -y "https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm"

# Package Information 
rpm -qi amazon-cloudwatch-agent

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
yum clean all

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
yum install -y chrony

# Configure NTP Client software (Configure chronyd)
cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

sed -i 's/#log measurements statistics tracking/log measurements statistics tracking/g' /etc/chrony.conf

# Configure NTP Client software (Start Daemon chronyd)
systemctl status chronyd
systemctl restart chronyd
systemctl status chronyd

systemctl enable chronyd
systemctl is-enabled chronyd

# Configure NTP Client software (Time adjustment)
sleep 3

chronyc tracking
chronyc sources -v
chronyc sourcestats -v

#-------------------------------------------------------------------------------
# Configure Amazon Linux Kernel Autotuning (ec2sys-autotune)
# https://github.com/amazonlinux/autotune
#-------------------------------------------------------------------------------

# Package Install ec2sys-autotune
yum install -y ec2sys-autotune

# Configure ec2sys-autotune software (Start Daemon autotune)
systemctl status autotune
systemctl restart autotune
systemctl status autotune

systemctl enable autotune
systemctl is-enabled autotune

autotune status
autotune list

# Configure ec2sys-autotune software (Check Current profile)
autotune active
autotune showconfig

# Configure ec2sys-autotune software
# autotune profile base
# autotune profile placement-group
# autotune profile udp-server
# autotune apply
# autotune active
# autotune showconfig

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Disable IPv6 Kernel Module
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf

# Disable IPv6 Kernel Parameter
sysctl -a

cat > /etc/sysctl.d/90-ipv6-disable.conf << __EOF__
# Custom sysctl Parameter for ipv6 disable
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
__EOF__

sysctl -p

sysctl -a | grep -ie "local_port" -ie "ipv6" | sort

#-------------------------------------------------------------------------------
# End of File
#-------------------------------------------------------------------------------
