#!/bin/bash -v

set -e -x

# Logger
exec > >(tee /var/log/user-data_bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - SUSE Linux Enterprise Server 15
#    https://www.suse.com/documentation/sles-15/
#    https://www.suse.com/ja-jp/documentation/sles-15/
#    https://www.suse.com/documentation/suse-best-practices/
#    https://forums.suse.com/forumdisplay.php?94-Amazon-EC2
#    
#    https://susepubliccloudinfo.suse.com/v1/amazon/images/active.json
#    https://susepubliccloudinfo.suse.com/v1/amazon/images/active.xml
#
#    https://aws.amazon.com/jp/partners/suse/faqs/
#    https://aws.amazon.com/marketplace/pp/B07SPX8ML1
#    http://d36cz9buwru1tt.cloudfront.net/SUSE_Linux_Enterprise_Server_on_Amazon_EC2_White_Paper.pdf
#
#    https://en.opensuse.org/YaST_Software_Management
#
#    https://github.com/SUSE-Enceladus
#-------------------------------------------------------------------------------

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/os-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [zypper command]
zypper search --installed-only > /tmp/command-log_zypper_installed-package.txt

# Default repository package [zypper command]
zypper search > /tmp/command-log_zypper_repository-package-list.txt

# systemd service config
systemctl list-unit-files --no-pager -all > /tmp/command-log_systemctl_list-unit-files.txt

# Default repository list [zypper command]
zypper products > /tmp/command-log_zypper_repository-list.txt

# Default repository pattern [zypper command]
zypper search --type pattern > /tmp/command-log_zypper_repository-patterm-list.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# SUSE Linux Enterprise Server Software repository metadata Clean up
zypper clean --all
zypper --quiet refresh -fdb

zypper repos

# Package Configure SLES Modules
#   https://www.suse.com/products/server/features/modules/
SUSEConnect --list-extensions

# Update default package
zypper --quiet --non-interactive update --auto-agree-with-licenses

#-------------------------------------------------------------------------------
# Custom Package Installation (from SUSE Linux Enterprise Server Software repository)
#-------------------------------------------------------------------------------

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository - Select pattern)
zypper --quiet --non-interactive install --type pattern base
zypper --quiet --non-interactive install --type pattern yast2_basis
zypper --quiet --non-interactive install --type pattern apparmor
zypper --quiet --non-interactive install --type pattern enhanced_base

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository - Select package)
SlesForSp1Flag=$(find /etc/zypp/repos.d/ | grep -c "SLE-Product-SLES15-SP1")
if [ $SlesForSp1Flag -gt 0 ];then
	echo "SUSE Linux Enterprise Server 15 SP1"
	zypper --quiet --non-interactive install arptables bash-completion bcc-tools cloud-netconfig-ec2 dstat ebtables git-core hdparm hostinfo iotop jq kmod-bash-completion lsb-release lzop nmap nvme-cli sdparm seccheck supportutils supportutils-plugin-suse-public-cloud sysstat systemd-bash-completion time traceroute tuned unrar unzip zypper-log
	zypper --quiet --non-interactive install aws-efs-utils cifs-utils nfs-client nfs-utils nfs4-acl-tools yast2-nfs-client
	zypper --quiet --non-interactive install libiscsi-utils libiscsi8 lsscsi open-iscsi sdparm sg3_utils yast2-iscsi-client
else
	echo "SUSE Linux Enterprise Server 15 (non SP1)" 
	zypper --quiet --non-interactive install arptables bash-completion bcc-tools cloud-netconfig-ec2 dstat ebtables git-core hdparm hostinfo iotop kmod-bash-completion lsb-release lzop nmap nvme-cli sdparm seccheck supportutils supportutils-plugin-suse-public-cloud sysstat systemd-bash-completion time traceroute tuned unrar unzip zypper-log
	zypper --quiet --non-interactive install aws-efs-utils cifs-utils nfs-client nfs-utils nfs4-acl-tools yast2-nfs-client
	zypper --quiet --non-interactive install libiscsi-utils libiscsi8 lsscsi open-iscsi sdparm sg3_utils yast2-iscsi-client
fi

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository - Select package)
SlesForSp1Flag=$(find /etc/zypp/repos.d/ | grep -c "SLE-Product-SLES15-SP1")
if [ $SlesForSp1Flag -gt 0 ];then
	echo "SUSE Linux Enterprise Server 15 SP1"
	# Package Install SLES System AWS Tools (from SUSE Linux Enterprise Server Software repository)
	#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
	zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
	zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
	zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
	zypper --quiet --non-interactive install python3-susepubliccloudinfo
else
	echo "SUSE Linux Enterprise Server 15 (non SP1)" 
	# Package Install SLES System AWS Tools (from SUSE Linux Enterprise Server Software repository)
	#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
	zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
	# zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
	zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
fi

# Package Install SAP Utility and Tools (from SUSE Linux Enterprise Server Software repository)
SlesForSapFlag=$(find /etc/zypp/repos.d/ | grep -c "SLE-Product-SLES_SAP15")
if [ $SlesForSapFlag -gt 0 ];then
	echo "SUSE Linux Enterprise Server for SAP Applications 15"

	# Package Install SAP Utility and Tools (from SUSE Linux Enterprise Server Software repository - Select pattern)
	zypper --quiet --non-interactive install --type pattern sap_server
	zypper --quiet --non-interactive install --type pattern sap-hana

	# Package Install SAP Utility and Tools (from SUSE Linux Enterprise Server Software repository - Select package)
	zypper --quiet --non-interactive install sapconf saptune insserv-compat
	zypper --quiet --non-interactive install libz1-32bit libcurl4-32bit libX11-6-32bit libidn11-32bit libgcc_s1-32bit libopenssl1_0_0 glibc-32bit glibc-i18ndata glibc-locale-32bit
else
	echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"  
fi

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

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------
# zypper --quiet --non-interactive --no-gpg-checks install "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"
# zypper --quiet --non-interactive --no-gpg-checks install "https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm"
# zypper --quiet --non-interactive install amazon-ssm-agent

# zypper --quiet --non-interactive --no-gpg-checks install "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

# systemctl daemon-reload

systemctl status -l amazon-ssm-agent
systemctl enable amazon-ssm-agent
systemctl is-enabled amazon-ssm-agent

# systemctl restart amazon-ssm-agent
# systemctl status -l amazon-ssm-agent

# ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
#-------------------------------------------------------------------------------

zypper --quiet --non-interactive --no-gpg-checks install "https://s3.amazonaws.com/amazoncloudwatch-agent/suse/amd64/latest/amazon-cloudwatch-agent.rpm"

# Package Information 
rpm -qi amazon-cloudwatch-agent

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -m ec2 -a status

#-------------------------------------------------------------------------------
# Custom Package Clean up
#-------------------------------------------------------------------------------
zypper clean --all
zypper --quiet refresh -fdb

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
zypper --quiet --non-interactive install chrony
systemctl daemon-reload

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
# Configure Tuned
#-------------------------------------------------------------------------------

# Package Install Tuned (from SUSE Linux Enterprise Server Software repository)
zypper --quiet --non-interactive install tuned

# Configure Tuned software (Start Daemon tuned)
systemctl status tuned
systemctl restart tuned
systemctl status tuned

systemctl enable tuned
systemctl is-enabled tuned

# Configure Tuned software
SlesForSapFlag=$(find /etc/zypp/repos.d/ | grep -c "SLE-Product-SLES_SAP15")
if [ $SlesForSapFlag -gt 0 ];then
	echo "SUSE Linux Enterprise Server for SAP Applications 15"
	# Configure Tuned software (select profile - sapconf)
	tuned-adm list
	tuned-adm active
	tuned-adm profile sapconf
	# tuned-adm profile saptune
	tuned-adm active
else
	echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"  
	# Configure Tuned software (select profile - throughput-performance)
	tuned-adm list
	tuned-adm active
	tuned-adm profile throughput-performance 
	tuned-adm active
fi 

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
