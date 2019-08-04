#!/bin/bash -v

# Logger
exec > >(tee /var/log/user-data_bootstrap.log || logger -t user-data -s 2> /dev/console) 2>&1

#-------------------------------------------------------------------------------
# Acquire unique information of Linux distribution
#  - RHEL v6
#    https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/
#    https://access.redhat.com/support/policy/updates/extras
#    https://access.redhat.com/articles/1150793
#    https://access.redhat.com/solutions/3358
#
#    https://access.redhat.com/articles/3135121
#
#    https://aws.amazon.com/marketplace/pp/B00CFQWLS6
#
#-------------------------------------------------------------------------------

# Show Linux Distribution/Distro information
if [ $(command -v lsb_release) ]; then
    lsb_release -a
fi

# Show Linux System Information
uname -a

# Show Linux distribution release Information
cat /etc/redhat-release

# Default installation package [rpm command]
rpm -qa --qf="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" | sort > /tmp/command-log_rpm_installed-package.txt

# Default installation package [yum command]
yum list installed > /tmp/command-log_yum_installed-package.txt

# Default repository package [yum command]
yum list all > /tmp/command-log_yum_repository-package-list.txt

# upstartd service config [chkconfig command]
chkconfig --list > /tmp/command-log_chkconfig_list.txt

# Default repository list [yum command]
yum repolist all > /tmp/command-log_yum_repository-list.txt

#-------------------------------------------------------------------------------
# Default Package Update
#-------------------------------------------------------------------------------

# Red Hat Update Infrastructure Client Package Update
yum clean all
yum update -y rh-amazon-rhui-client

# Checking repository information
yum repolist all

# Enable Channnel (RHEL Server RPM) - [Default Enable]
yum-config-manager --enable rhui-REGION-rhel-server-releases
yum-config-manager --enable rhui-REGION-rhel-server-rh-common
yum-config-manager --enable rhui-REGION-client-config-server-6

# Enable Channnel (RHEL Server RPM) - [Default Disable]
yum-config-manager --enable rhui-REGION-rhel-server-extras
yum-config-manager --enable rhui-REGION-rhel-server-releases-optional
yum-config-manager --enable rhui-REGION-rhel-server-supplementary
# yum-config-manager --enable rhui-REGION-rhel-server-rhscl

# yum repository metadata Clean up
yum clean all

# Default Package Update
yum update -y

#-------------------------------------------------------------------------------
# Custom Package Installation
#-------------------------------------------------------------------------------

# Package Install RHEL System Administration Tools (from Red Hat Official Repository)
yum install -y dstat gdisk git hdparm libicu lsof lzop iotop mtr nc nmap sos tcpdump traceroute tree unzip uuid vim-enhanced yum-priorities yum-plugin-versionlock yum-utils wget
yum install -y cifs-utils nfs-utils nfs4-acl-tools
yum install -y iscsi-initiator-utils lsscsi scsi-target-utils sdparm sg3_utils
yum install -y setroubleshoot-server setools-console

# Package Install Red Hat Enterprise Linux support tools (from Red Hat Official Repository)
yum install -y redhat-lsb-core redhat-support-tool

# Package Install EPEL(Extra Packages for Enterprise Linux) Repository Package
# yum localinstall -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm

cat > /etc/yum.repos.d/epel-bootstrap.repo << __EOF__
[epel]
name=Bootstrap EPEL
mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-6&arch=\$basearch
failovermethod=priority
enabled=0
gpgcheck=0
__EOF__

yum --enablerepo=epel -y install epel-release
rm -f /etc/yum.repos.d/epel-bootstrap.repo

sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/epel.repo
# yum-config-manager --disable epel epel-debuginfo epel-source

yum clean all

# Package Install RHEL System Administration Tools (from EPEL Repository)
yum --enablerepo=epel install -y bash-completion fio iperf3 jq zstd

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
yum --enablerepo=epel install -y python-pip python2-colorama python2-rsa python2-jmespath python-futures python-ordereddict
pip install awscli
pip show awscli

# Workaround - SSL-Warnings
# https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
cat /usr/bin/aws
sed -i "/import os/a import urllib3" /usr/bin/aws
sed -i "/import urllib3/a urllib3.disable_warnings()" /usr/bin/aws
cat /usr/bin/aws

# Setting Bash-Completion
cat > /etc/profile.d/aws-cli.sh << __EOF__
if [ -n "\$BASH_VERSION" ]; then
   complete -C /usr/bin/aws_completer aws
fi
__EOF__

source /etc/profile.d/aws-cli.sh

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
# yum --enablerepo=epel install -y python-pip
# pip install --upgrade pip

pip install pystache
pip install argparse
pip install python-daemon
pip install requests

curl -sS "https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz" -o "/tmp/aws-cfn-bootstrap-latest.tar.gz"
tar -pxvzf /tmp/aws-cfn-bootstrap-latest.tar.gz -C /tmp

cd /tmp/aws-cfn-bootstrap-1.4/
python setup.py build
python setup.py install

chmod 775 /usr/init/redhat/cfn-hup
ln -s /usr/init/redhat/cfn-hup /etc/init.d/cfn-hup

cd /tmp

#-------------------------------------------------------------------------------
# Custom Package Installation [AWS Systems Manager agent (aka SSM agent)]
# http://docs.aws.amazon.com/ja_jp/systems-manager/latest/userguide/sysman-install-ssm-agent.html
# https://github.com/aws/amazon-ssm-agent
#-------------------------------------------------------------------------------
# yum localinstall -y "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm"

# yum localinstall -y "https://amazon-ssm-${Region}.s3.amazonaws.com/latest/linux_amd64/amazon-ssm-agent.rpm"

rpm -qi amazon-ssm-agent

status amazon-ssm-agent
# /sbin/restart amazon-ssm-agent
# status amazon-ssm-agent

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
service awsagent status
service awsagent restart
service awsagent status

chkconfig --list awsagent
chkconfig awsagent on
chkconfig --list awsagent

#-------------------------------------------------------------------------------
# Custom Package Install [Amazon CloudWatch Agent]
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/download-cloudwatch-agent-commandline.html
#-------------------------------------------------------------------------------

yum localinstall -y "https://s3.amazonaws.com/amazoncloudwatch-agent/redhat/amd64/latest/amazon-cloudwatch-agent.rpm"

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

# Replace NTP Client software (Uninstall ntpd Package)
chkconfig --list ntpd
service ntpd stop
yum erase -y ntp*

# Replace NTP Client software (Install chrony Package)
yum install -y chrony

# Configure NTP Client software (Configure chronyd)
cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

sed -i 's/#log measurements statistics tracking/log measurements statistics tracking/g' /etc/chrony.conf

sed -i "1i# use the local instance NTP service, if available\nserver 169.254.169.123 prefer iburst\n" /etc/chrony.conf

cat /etc/chrony.conf | grep -ie "169.254.169.123" -ie "pool" -ie "server"

# Configure NTP Client software (Start Daemon chronyd)
service chronyd status
service chronyd restart
service chronyd status

chkconfig --list chronyd
chkconfig chronyd on
chkconfig --list chronyd

# Configure NTP Client software (Time adjustment)
sleep 3

chronyc tracking
chronyc sources -v
chronyc sourcestats -v

#-------------------------------------------------------------------------------
# Configure Tuned
#-------------------------------------------------------------------------------

# Package Install Tuned (from Red Hat Official Repository)
yum install -y tuned tuned-utils tuned-profiles-oracle

# Configure Tuned software (Start Daemon tuned)
service tuned status
service tuned restart
service tuned status

chkconfig --list tuned
chkconfig tuned on
chkconfig --list tuned

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

# Firewall Service Disabled (iptables/ip6tables)
service iptables stop
chkconfig --list iptables
chkconfig iptables off
chkconfig --list iptables

service ip6tables stop
chkconfig --list ip6tables
chkconfig ip6tables off
chkconfig --list ip6tables


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