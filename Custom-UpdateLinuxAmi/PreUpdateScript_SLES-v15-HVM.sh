#!/bin/bash -v

# set -e -x

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
#    https://scc.suse.com/packages/?name=SUSE%20Linux%20Enterprise%20Server&version=15.1&arch=x86_64&query=&module=
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

# Cleanup repository information
zypper clean --all
zypper --quiet refresh -fdb

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

# systemd service config
systemctl list-unit-files --all --no-pager > /tmp/command-log_systemctl_list-unit-files.txt

# Default repository products list [zypper command]
zypper products > /tmp/command-log_zypper_repository-products-list.txt

# Default repository patterns list [zypper command]
zypper patterns > /tmp/command-log_zypper_repository-patterns-list.txt

# Default repository packages list [zypper command]
zypper packages > /tmp/command-log_zypper_repository-packages-list.txt

# Determine the OS release
eval $(grep ^VERSION_ID= /etc/os-release)

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

# Apply SLES Service Pack
ZypperMigrationStatus="0"

# if [ -n "$VERSION_ID" ]; then
# 	if [ "${VERSION_ID}" = "15.2" ]; then
# 		echo "SUSE Linux Enterprise Server 15 SP2 -> SUSE Linux Enterprise Server 15 Lastest ServicePack"
# 		cat /etc/os-release
# 		zypper migration --quiet --non-interactive --migration "1" --auto-agree-with-licenses --recommends --details || ZypperMigrationStatus=$?
# 		if [ $ZypperMigrationStatus -eq 0 ]; then
# 			echo "Successful execution [Zypper Migration Command]"
# 			eval $(grep ^VERSION_ID= /etc/os-release)
# 		else
# 			echo "Failed to execute [Zypper Migration Command]"
# 		fi
# 		cat /etc/os-release

# 	elif [ "${VERSION_ID}" = "15.1" ]; then
# 		echo "SUSE Linux Enterprise Server 15 SP1 -> SUSE Linux Enterprise Server 15 Lastest ServicePack"
# 		cat /etc/os-release
# 		zypper migration --quiet --non-interactive --migration "1" --auto-agree-with-licenses --recommends --details || ZypperMigrationStatus=$?
# 		if [ $ZypperMigrationStatus -eq 0 ]; then
# 			echo "Successful execution [Zypper Migration Command]"
# 			eval $(grep ^VERSION_ID= /etc/os-release)
# 		else
# 			echo "Failed to execute [Zypper Migration Command]"
# 		fi
# 		cat /etc/os-release

# 	elif [ "${VERSION_ID}" = "15" ]; then
# 		echo "SUSE Linux Enterprise Server 15 GA -> SUSE Linux Enterprise Server 15 Lastest ServicePack"
# 		cat /etc/os-release
# 		zypper migration --quiet --non-interactive --migration "1" --auto-agree-with-licenses --recommends --details || ZypperMigrationStatus=$?
# 		if [ $ZypperMigrationStatus -eq 0 ]; then
# 			echo "Successful execution [Zypper Migration Command]"
# 			eval $(grep ^VERSION_ID= /etc/os-release)
# 		else
# 			echo "Failed to execute [Zypper Migration Command]"
# 		fi
# 		cat /etc/os-release

# 	else
# 		echo "SUSE Linux Enterprise Server 15 (Unknown)"
# 	fi
# fi

# SUSE Linux Enterprise Server Software repository metadata Clean up
zypper clean --all
zypper --quiet refresh -fdb

# Install recommended packages
# zypper --quiet --non-interactive install-new-recommends

#-------------------------------------------------------------------------------
# Custom Package Installation (from SUSE Linux Enterprise Server Software repository)
#-------------------------------------------------------------------------------

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository - Select pattern)
zypper --quiet --non-interactive install --type pattern base
zypper --quiet --non-interactive install --type pattern yast2_basis
zypper --quiet --non-interactive install --type pattern apparmor
zypper --quiet --non-interactive install --type pattern enhanced_base

# Package Install SLES System Administration Tools (from SUSE Linux Enterprise Server Software repository - Select package)
zypper --quiet --non-interactive install arptables bash-completion bcc-tools cloud-netconfig-ec2 dstat ebtables git-core hdparm hostinfo iotop kexec-tools kmod-bash-completion lsb-release lzop net-snmp nmap nvme-cli sdparm seccheck supportutils supportutils-plugin-suse-public-cloud sysstat systemd-bash-completion time traceroute tuned unrar unzip zypper-log
zypper --quiet --non-interactive install aws-efs-utils cifs-utils nfs-client nfs-utils nfs4-acl-tools yast2-nfs-client
zypper --quiet --non-interactive install libiscsi-utils libiscsi8 lsscsi open-iscsi sdparm sg3_utils yast2-iscsi-client

if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.2" ]; then
		echo "SUSE Linux Enterprise Server 15 SP2"
		zypper --quiet --non-interactive install jq
		zypper --quiet --non-interactive install pcp pcp-conf pcp-system-tools
	elif [ "${VERSION_ID}" = "15.1" ]; then
		echo "SUSE Linux Enterprise Server 15 SP1"
		zypper --quiet --non-interactive install jq
		zypper --quiet --non-interactive install pcp pcp-conf pcp-system-tools
	elif [ "${VERSION_ID}" = "15" ]; then
		echo "SUSE Linux Enterprise Server 15 GA"
		zypper --quiet --non-interactive install pcp pcp-conf
	else
		echo "SUSE Linux Enterprise Server 15 (Unknown)"
	fi
fi

# SUSE Linux Enterprise Server Software repository metadata Clean up
zypper clean --all
zypper --quiet refresh -fdb

# Package Install SLES System AWS Tools (from SUSE Linux Enterprise Server Software repository)
SapFlag=0
SapFlag=$(find /etc/zypp/repos.d/ -name "*SLE-Product-SLES_SAP15*" | wc -l)

if [ -n "$VERSION_ID" ]; then
	if [ "${VERSION_ID}" = "15.2" ]; then
		echo "SUSE Linux Enterprise Server 15 SP2"
		
		zypper --quiet --non-interactive install python3-susepubliccloudinfo
		
		if [ $SapFlag -gt 0 ]; then
			echo "SUSE Linux Enterprise Server for SAP Applications 15"
			#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
			# zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		else
			echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"
			#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		fi
		
	elif [ "${VERSION_ID}" = "15.1" ]; then
		echo "SUSE Linux Enterprise Server 15 SP1"

		zypper --quiet --non-interactive install python3-susepubliccloudinfo

		if [ $SapFlag -gt 0 ]; then
			echo "SUSE Linux Enterprise Server for SAP Applications 15"
			#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
			# zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		else
			echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"
			#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		fi

	elif [ "${VERSION_ID}" = "15" ]; then

		echo "SUSE Linux Enterprise Server 15 GA"

		if [ $SapFlag -gt 0 ]; then
			echo "SUSE Linux Enterprise Server for SAP Applications 15"
			#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
			# zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		else
			echo "SUSE Linux Enterprise Server 15 (non SUSE Linux Enterprise Server for SAP Applications 15)"
			#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
			# zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
			zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
		fi

	else
		echo "SUSE Linux Enterprise Server 15 (Unknown)"
		#  zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Init
		# zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Instance-Tools
		zypper --quiet --non-interactive install patterns-public-cloud-15-Amazon-Web-Services-Tools
	fi
fi

# Package Install Python 3 Runtime (from SUSE Linux Enterprise Server Software repository)
zypper --quiet --non-interactive install python3 python3-base python3-pip python3-setuptools python3-tools python3-virtualenv python3-wheel
zypper --quiet --non-interactive install python3-Babel python3-PyJWT python3-PyYAML python3-pycrypto python3-pycurl python3-cryptography python3-python-dateutil python3-requests-aws python3-simplejson python3-six python3-urllib3

# SUSE Linux Enterprise Server Software repository metadata Clean up
zypper clean --all
zypper --quiet refresh -fdb

# Package Install SAP Utility and Tools (from SUSE Linux Enterprise Server Software repository
SapFlag=0
SapFlag=$(find /etc/zypp/repos.d/ -name "*SLE-Product-SLES_SAP15*" | wc -l)

if [ $SapFlag -gt 0 ]; then
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

# IAM Role Information
if [ $(compgen -ac | sort | uniq | grep jq) ]; then
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

rpm -qi amazon-ssm-agent

# systemctl daemon-reload

# systemctl restart amazon-ssm-agent

# systemctl status -l amazon-ssm-agent

# Configure AWS Systems Manager Agent software (Start Daemon awsagent)
if [ $(systemctl is-enabled amazon-ssm-agent) = "disabled" ]; then
	systemctl enable amazon-ssm-agent
	systemctl is-enabled amazon-ssm-agent
fi

# ssm-cli get-instance-information

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
#-------------------------------------------------------------------------------

zypper --quiet --non-interactive --no-gpg-checks install "https://s3.amazonaws.com/amazoncloudwatch-agent/suse/amd64/latest/amazon-cloudwatch-agent.rpm"

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
zypper clean --all
zypper --quiet refresh -fdb

zypper --quiet --non-interactive update

#-------------------------------------------------------------------------------
# Configure Amazon Time Sync Service
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
#-------------------------------------------------------------------------------

# Configure NTP Client software (Install chrony Package)
zypper --quiet --non-interactive install chrony

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

# Package Install Tuned (from SUSE Linux Enterprise Server Software repository)
zypper --quiet --non-interactive install tuned

rpm -qi tuned

systemctl daemon-reload

systemctl restart tuned

systemctl status -l tuned

# Configure Tuned software (Start Daemon tuned)
if [ $(systemctl is-enabled tuned) = "disabled" ]; then
	systemctl enable tuned
	systemctl is-enabled tuned
fi

# Configure Tuned software
SapFlag=0
SapFlag=$(find /etc/zypp/repos.d/ -name "*SLE-Product-SLES_SAP15*" | wc -l)

if [ $SapFlag -gt 0 ]; then
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

# Update default configuration for Zypper
ZypperFlag=0
ZypperFlag=$(cat /etc/zypp/zypper.conf | grep -w runSearchPackages | grep -w ask | wc -l)

if [ $ZypperFlag -gt 0 ]; then
	cat /etc/zypp/zypper.conf | grep -w runSearchPackages
	sed -i 's/# runSearchPackages = ask/runSearchPackages = never/g' /etc/zypp/zypper.conf
	cat /etc/zypp/zypper.conf | grep -w runSearchPackages
fi

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
