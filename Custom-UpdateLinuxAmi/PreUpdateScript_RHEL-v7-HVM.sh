#!/bin/bash -v

# set -e -x

# Logger
exec > >(tee /var/log/user-data_bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - RHEL v7
#    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/
#    https://access.redhat.com/support/policy/updates/extras
#    https://access.redhat.com/articles/1150793
#    https://access.redhat.com/solutions/3358
#
#    https://access.redhat.com/articles/3135121
#
#    https://aws.amazon.com/marketplace/pp/B00KWBZVK6
#
#-------------------------------------------------------------------------------

# Cleanup repository information
yum clean all

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

cat /etc/redhat-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [yum command]
yum list installed > /tmp/command-log_yum_installed-package.txt

# Default repository package [yum command]
yum list all > /tmp/command-log_yum_repository-package-list.txt

# Default repository package group [yum command]
yum groups list -v > /tmp/command-log_yum_repository-package-group-list.txt

# systemd service config
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# Default repository list [yum command]
yum repolist all > /tmp/command-log_yum_repository-list.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------
#  - RHEL v7 - Red Hat Yum Repository Default Status (Enable/Disable)
#
#    [Default - Enable]
#        rhel-7-server-rhui-rpms
#        rhel-7-server-rhui-rh-common-rpms
#        rhui-client-config-server-7
#    [Default - Disable]
#        rhel-7-server-rhui-extras-rpms
#        rhel-7-server-rhui-optional-rpms
#        rhel-7-server-rhui-supplementary-rpms
#        rhel-7-server-dotnet-rhui-rpms
#        rhel-server-rhui-rhscl-7-rpms
#-------------------------------------------------------------------------------

# Red Hat Update Infrastructure Client Package Update
yum clean all
yum update -y rh-amazon-rhui-client

# Checking repository information
yum repolist all

# Get Yum Repository List (Exclude Yum repository related to "beta, debug, source, test")
repolist=$(yum repolist all | grep -ie "enabled" -ie "disabled" | grep -ve "Loaded plugins" -ve "beta" -ve "debug" -ve "source" -ve "test" | awk '{print $1}' | awk '{ sub("/.*$",""); print $0; }' | sort)

# Enable Yum Repository Data from RHUI (Red Hat Update Infrastructure)
for repo in $repolist
do
	echo "[Target repository Name (Enable yum repository)] :" $repo
	yum-config-manager --enable ${repo}
	sleep 3
done

# Checking repository information
yum repolist all

# yum repository metadata Clean up
yum clean all

# RHEL/RHUI repository package [yum command]
for repo in $repolist
do
	echo "[Target repository Name (Collect yum repository package list)] :" $repo
	yum --disablerepo="*" --enablerepo=${repo} list available > /tmp/command-log_yum_repository-package-list_${repo}.txt
	sleep 3
done

# yum repository metadata Clean up
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
yum install -y acpid arptables bash-completion bc bcc bcc-tools bind-utils blktrace bpftool crash-trace-command crypto-utils curl dstat ebtables ethtool expect fio gdisk git hdparm intltool iotop iperf3 iptraf-ng kexec-tools libicu lsof lvm2 lzop man-pages mcelog mdadm mlocate mtr nc ncompress net-snmp-utils nftables nmap numactl nvme-cli nvmetcli pmempool psacct psmisc rsync smartmontools sos strace symlinks sysfsutils sysstat tcpdump traceroute tree unzip util-linux vdo vim-enhanced wget xfsdump xfsprogs zip zsh
yum install -y cifs-utils nfs-utils nfs4-acl-tools
yum install -y iscsi-initiator-utils lsscsi sdparm sg3_utils
yum install -y setroubleshoot-server selinux-policy* setools-console checkpolicy policycoreutils policycoreutils-restorecond
yum install -y pcp pcp-manager pcp-pmda* pcp-selinux pcp-system-tools pcp-zeroconf

# Package Install Red Hat Enterprise Linux support tools (from Red Hat Official Repository)
yum install -y redhat-lsb-core redhat-support-tool redhat-access-insights

# Package Install Red Hat Enterprise Linux kernel live-patching tools (from Red Hat Official Repository)
yum install -y kpatch

# Package Install Python 3 Runtime (from Red Hat Official Repository)
yum install -y python3 python3-pip python3-devel python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel

#-------------------------------------------------------------------------------
# Custom Package Installation [EPEL]
#-------------------------------------------------------------------------------

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# yum localinstall -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
cat > /etc/yum.repos.d/epel-bootstrap.repo << __EOF__
[epel-bootstrap]
name=Bootstrap EPEL
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-7&arch=\$basearch
failovermethod=priority
enabled=0
gpgcheck=0
__EOF__

yum clean all

yum --enablerepo=epel-bootstrap -y install epel-release

# Delete yum temporary data
rm -f /etc/yum.repos.d/epel-bootstrap.repo
rm -rf /var/cache/yum/x86_64/7Server/epel-bootstrap*

# Disable EPEL yum repository
egrep '^\[|enabled' /etc/yum.repos.d/epel*
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel-*.repo
egrep '^\[|enabled' /etc/yum.repos.d/epel*

# yum repository metadata Clean up
yum clean all

# EPEL repository package [yum command]
yum --disablerepo="*" --enablerepo="epel" list available > /tmp/command-log_yum_repository-package-list_epel.txt

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y atop bash-completion-extras collectl jq moreutils moreutils-parallel zstd

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

# IAM Role Information
if [ $(compgen -ac | sort | uniq | grep -x jq) ]; then
	RoleArn=$(curl -s "http://169.254.169.254/latest/meta-data/iam/info" | jq -r '.InstanceProfileArn')
	RoleName=$(echo $RoleArn | cut -d '/' -f 2)
fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS-CLI]
#-------------------------------------------------------------------------------

# Package Install AWS-CLI Tools (from Python Package Index (PyPI) Repository)
yum install -y python3 python3-pip python3-devel python3-rpm-generators python3-rpm-macros python3-setuptools python3-test python3-wheel
python3 --version

pip3 install awscli
pip3 show awscli

# Configuration AWS-CLI tools [AWS-CLI/Python3]
alternatives --list
alternatives --install "/usr/bin/aws" aws "/usr/local/bin/aws" 1
alternatives --install "/usr/bin/aws_completer" aws_completer "/usr/local/bin/aws_completer" 1
alternatives --list

cat > /etc/bash_completion.d/aws_bash_completer << __EOF__
# Typically that would be added under one of the following paths:
# - /etc/bash_completion.d
# - /usr/local/etc/bash_completion.d
# - /usr/share/bash-completion/completions

complete -C aws_completer aws
__EOF__

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

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS CloudFormation Helper Scripts]
# https://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/cfn-helper-scripts-reference.html
# https://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/releasehistory-aws-cfn-bootstrap.html
#-------------------------------------------------------------------------------
# yum --enablerepo=epel localinstall -y https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.amzn1.noarch.rpm

# yum install -y python-setuptools

# easy_install --script-dir "/opt/aws/bin" https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz

# mkdir -m 755 -p /etc/cfn/hooks.d

# # cfn-hup.conf Configuration File
# cat > /etc/cfn/cfn-hup.conf << __EOF__
# [main]
# stack=
# __EOF__

# # cfn-auto-reloader.conf Configuration File
# cat > /etc/cfn/hooks.d/cfn-auto-reloader.conf << __EOF__
# [hookname]
# triggers=post.update
# path=Resources.EC2Instance.Metadata.AWS::CloudFormation::Init
# action=
# runas=root
# __EOF__

# # cfn-hup.service Configuration File
# cat > /lib/systemd/system/cfn-hup.service << __EOF__
# [Unit]
# Description=cfn-hup daemon

# [Service]
# Type=simple
# ExecStart=/opt/aws/bin/cfn-hup
# Restart=always

# [Install]
# WantedBy=multi-user.target
# __EOF__

# # Execute AWS CloudFormation Helper software
# systemctl daemon-reload

# systemctl restart cfn-hup

# systemctl status -l cfn-hup

# # Configure AWS CloudFormation Helper software (Start Daemon awsagent)
# if [ $(systemctl is-enabled cfn-hup) = "disabled" ]; then
# 	systemctl enable cfn-hup
# 	systemctl is-enabled cfn-hup
# fi

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------

# yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

# systemctl daemon-reload

# systemctl restart amazon-ssm-agent

systemctl status -l amazon-ssm-agent

# Configure AWS Systems Manager Agent software (Start Daemon awsagent)
if [ $(systemctl is-enabled amazon-ssm-agent) = "disabled" ]; then
	systemctl enable amazon-ssm-agent
	systemctl is-enabled amazon-ssm-agent
fi

# ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon Inspector Agent]
# https://docs.aws.amazon.com/inspector/latest/userguide/inspector_installing-uninstalling-agents.html
#-------------------------------------------------------------------------------

# Variable initialization
InspectorInstallStatus="0"

# Run Amazon Inspector Agent installer script
curl -fsSL "https://inspector-agent.amazonaws.com/linux/latest/install" | bash -ex || InspectorInstallStatus=$?

# Check the exit code of the Amazon Inspector Agent installer script
if [ $InspectorInstallStatus -eq 0 ]; then
	rpm -qi AwsAgent

	systemctl daemon-reload

	systemctl restart awsagent

	systemctl status -l awsagent

	# Configure Amazon Inspector Agent software (Start Daemon awsagent)
	if [ $(systemctl is-enabled awsagent) = "disabled" ]; then
		systemctl enable awsagent
		systemctl is-enabled awsagent
	fi

	sleep 15

	/opt/aws/awsagent/bin/awsagent status
else
	echo "Failed to execute Amazon Inspector Agent installer script"
fi

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
#-------------------------------------------------------------------------------

yum localinstall --nogpgcheck -y "https://s3.amazonaws.com/amazoncloudwatch-agent/redhat/amd64/latest/amazon-cloudwatch-agent.rpm"

rpm -qi amazon-cloudwatch-agent

cat /opt/aws/amazon-cloudwatch-agent/bin/CWAGENT_VERSION

cat /opt/aws/amazon-cloudwatch-agent/etc/common-config.toml

systemctl daemon-reload

# Configure Amazon CloudWatch Agent software (Start Daemon awsagent)
if [ $(systemctl is-enabled amazon-cloudwatch-agent) = "disabled" ]; then
	systemctl enable amazon-cloudwatch-agent
	systemctl is-enabled amazon-cloudwatch-agent
fi

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

#-------------------------------------------------------------------------------
# Custom Package Installation [Amazon EC2 Rescue for Linux (ec2rl)]
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Linux-Server-EC2Rescue.html
# https://github.com/awslabs/aws-ec2rescue-linux
#-------------------------------------------------------------------------------

# Package Amazon EC2 Administration Tools (from S3 Bucket)
curl -sS "https://s3.amazonaws.com/ec2rescuelinux/ec2rl-bundled.tgz" -o "/tmp/ec2rl-bundled.tgz"

mkdir -p "/opt/aws"

rm -rf /opt/aws/ec2rl*

tar -xzf "/tmp/ec2rl-bundled.tgz" -C "/opt/aws"

mv --force /opt/aws/ec2rl* "/opt/aws/ec2rl"

cat > /etc/profile.d/ec2rl.sh << __EOF__
export PATH=\$PATH:/opt/aws/ec2rl
__EOF__

source /etc/profile.d/ec2rl.sh

# Check Version
/opt/aws/ec2rl/ec2rl version

/opt/aws/ec2rl/ec2rl list

# Required Software Package
/opt/aws/ec2rl/ec2rl software-check

# Diagnosis [dig modules]
# /opt/aws/ec2rl/ec2rl run --only-modules=dig --domain=amazon.com

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

rpm -qi chrony

systemctl daemon-reload

systemctl restart chronyd

systemctl status -l chronyd

# Configure NTP Client software (Start Daemon chronyd)
if [ $(systemctl is-enabled chronyd) = "disabled" ]; then
	systemctl enable chronyd
	systemctl is-enabled chronyd
fi

# Configure NTP Client software (Configure chronyd)
cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

sed -i 's/#log measurements statistics tracking/log measurements statistics tracking/g' /etc/chrony.conf

sed -i "1i# use the local instance NTP service, if available\nserver 169.254.169.123 prefer iburst\n" /etc/chrony.conf

cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

# Configure NTP Client software (Time adjustment)
systemctl restart chronyd

sleep 3
chronyc tracking
sleep 3
chronyc sources -v
sleep 3
chronyc sourcestats -v

#-------------------------------------------------------------------------------
# Configure Tuned
#-------------------------------------------------------------------------------

# Package Install Tuned (from Red Hat Official Repository)
yum install -y tuned tuned-utils tuned-profiles-oracle

rpm -qi tuned

systemctl restart tuned

systemctl status -l tuned

# Configure Tuned software (Start Daemon tuned)
if [ $(systemctl is-enabled tuned) = "disabled" ]; then
	systemctl enable tuned
	systemctl is-enabled tuned
fi

# Configure Tuned software (select profile - throughput-performance)
tuned-adm list

tuned-adm active
tuned-adm profile throughput-performance
tuned-adm active

#-------------------------------------------------------------------------------
# System Setting
#-------------------------------------------------------------------------------

# Setting SELinux permissive mode
getenforce
sestatus
cat /etc/selinux/config
sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config
cat /etc/selinux/config
setenforce 0
getenforce

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
# For normal termination of SSM "Run Command"
#-------------------------------------------------------------------------------

exit 0

#-------------------------------------------------------------------------------
# End of File
#-------------------------------------------------------------------------------
