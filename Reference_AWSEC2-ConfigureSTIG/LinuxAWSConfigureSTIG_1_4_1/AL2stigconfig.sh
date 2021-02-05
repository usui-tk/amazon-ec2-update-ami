#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# This script is intended to be ran on RHEL 7 and distros that were based off it.  Other distros of Linux have different sets of STIGs.

#Backup previous config files and save them to /etc/stigbackup
function Backup () {
    echo
    echo "Backing up current configuration files."

    if [ ! -d "$BackupDIR" ]
    then
        mkdir "$BackupDIR"
    fi

    cp /etc/yum.conf "$BackupDIR"/yum.conf.old
    cp /etc/sysctl.conf "$BackupDIR"/sysctl.conf.old
    authconfig --savebackup="$BackupDIR"/authbackup
}

#Restore backups
function Restore () {
    echo
    echo "Restoring previous file backups"

    if [ -d "$BackupDIR" ]
    then
        authconfig --restorebackup="$BackupDIR"
        cp "$BackupDIR"/yum.conf.old /etc/yum.conf
        cp "$BackupDIR"/audit/rules.d/audit.rules.old /etc/audit/rules.d/audit.rules
        cp "$BackupDIR"/sysctl.conf.old /etc/sysctl.conf
        authconfig --restorebackup="$BackupDIR"/authbackup
    fi
}

#--------------------------------------------
#STIGS
#STIGs for Red Hat 7, Version 3 Release 1.
#--------------------------------------------

#--------------
#CAT III\Low
#--------------

#Set yum to remove unneeded packages, V-204452
function V204452 () {
    local Regex1="^(\s*)#clean_requirements_on_remove=\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#clean_requirements_on_remove=\S+(\s*#.*)?\s*$/clean_requirements_on_remove=1\2/"
    local Regex3="^(\s*)clean_requirements_on_remove=\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)clean_requirements_on_remove=\S+(\s*#.*)?\s*$/clean_requirements_on_remove=1\2/"
    local Regex5="^(\s*)clean_requirements_on_remove=1?\s*$"
    local Success="Yum set to remove unneeded packages, per V-204452."
    local Failure="Failed to set yum to remove unneeded packages, not in compliance V-204452."

    echo
    ( (grep -E -q "$Regex1" /etc/yum.conf && sed -ri "$Regex2" /etc/yum.conf) || (grep -E -q "$Regex3" /etc/yum.conf && sed -ri "$Regex4" /etc/yum.conf) ) || echo "clean_requirements_on_remove=1" >> /etc/yum.conf
    (grep -E -q "$Regex5" /etc/yum.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Verify system is using tmp mount service, V-204496
function V204496 () {
    local Regex1="^(\s*)enabled\s*$"
    local Success="System is set to create a separate file system for /tmp, per V-204496."
    local Failure="Failed to set the system to create a separate file system for /tmp, not in compliance V-204496."

    echo
    systemctl enable tmp.mount > /dev/null
    (systemctl is-enabled tmp.mount | grep -E -q "$Regex1" && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set mx concurrent sessions to 10, V-204576
function V204576 () {
    local Regex1="^(\s*)#*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$/\* hard maxlogins 10\2/"
    local Regex3="^(\s*)\*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)\*\s*hard\s*maxlogins\s+\S+(\s*#.*)?\s*$/\* hard maxlogins 10\2/"
    local Regex5="^(\s*)\*\s*hard\s*maxlogins\s*10?\s*$"
    local Success="Set max concurrent sessions to 10, per V-204576."
    local Failure="Failed to set max concurrent sessions to 10, not in compliance V-204576."

    echo
    ( (grep -E -q "$Regex1" /etc/security/limits.conf && sed -ri "$Regex2" /etc/security/limits.conf) || (grep -E -q "$Regex3" /etc/security/limits.conf && sed -ri "$Regex4" /etc/security/limits.conf) ) || echo "* hard maxlogins 10" >> /etc/security/limits.conf
    (grep -E -q "$Regex5" /etc/security/limits.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to display the date and time of the last successful logon upon logon., V-204605
function V204605 () {
    local Regex1="^\s*session\s+required\s+pam_lastlog.so\s*"
    local Regex2="s/^\s*session\s+required\s+pam_lastlog.so\s*showfailed\s*"
    local Regex3="session     required      pam_lastlog.so showfailed"
    local Regex4="^(\s*)session\s+required\s+\s*pam_lastlog.so\s*showfailed\s*$"
    local Success="System set to display the date and time of the last successful logon upon logon, per V-204605."
    local Failure="Failed to set the system to display the date and time of the last successful logon upon logon, not in compliance with V-204605."

    echo
    (grep -E -q "$Regex1" /etc/pam.d/postlogin && sed -ri  "$Regex2.*$/$Regex3/" /etc/pam.d/postlogin) || echo "$Regex3" >> /etc/pam.d/postlogin
    (grep -E -q "$Regex4" /etc/pam.d/postlogin && echo "$Success") || { echo "$Failure" ; exit 1; }
}

##Apply all compatible CATIII
function Low () {
    echo
    echo "Applying all compatible CAT IIIs"
    V204452
    #V204496, disabled currently due to causing issues with EC2IB
    V204576
    V204605
}

#--------------
#CAT II\Medium
#--------------

#Set 15 min timeout period, V-204402  Not applied due to can cause issue if GNOME is installed after
function V204402 () {
    local Regex1="^(\s*)#idle-activation-enabled=\S+?\s*$"
    local Regex2="s/^(\s*)#idle-activation-enabled=\S+(\s*#.*)?\s*$/\idle-activation-enabled=true\2/"
    local Regex3="^(\s*)idle-activation-enabled=\S+?\s*$"
    local Regex4="s/^(\s*)idle-activation-enabled=\S+(\s*#.*)?\s*$/\idle-activation-enabled=true\2/"
    local Regex5="^(\s*)idle-activation-enabled=true\s*$"
    local Success="15 min timeout for the screen saver is set, per V-204402."
    local Failure="15 min timeout for the screen saver has not been set, not in compliance with V-204402."

    echo
    if [ -f "/etc/dconf/db/local.d/00-screensaver" ]
    then
        ( (grep -E -q "$Regex1" /etc/dconf/db/local.d/00-screensaver && sed -ri "$Regex2" /etc/dconf/db/local.d/00-screensaver) || (grep -E -q "$Regex3" /etc/dconf/db/local.d/00-screensaver && sed -ri "$Regex4" /etc/dconf/db/local.d/00-screensaver) ) ||echo "idle-activation-enabled=true" >> /etc/dconf/db/local.d/00-screensaver
    else
        mkdir -p /etc/dconf/db/local.d/
        echo "idle-activation-enabled=true" >> /etc/dconf/db/local.d/00-screensaver
    fi
    (grep -E -q "$Regex5" /etc/dconf/db/local.d/00-screensaver && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set passwords to require a number of uppercase characters, V-204407
function V204407 () {
    local Regex1="^(\s*)#\s*ucredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*ucredit\s*=\s*\S+(\s*#.*)?\s*$/ucredit = -1\2/"
    local Regex3="^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)ucredit\s*=\s*\S+(\s*#.*)?\s*$/ucredit = -1\2/"
    local Regex5="^(\s*)ucredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of uppercase characters, per V-204407"
    local Failure="Password isn't set to require a number of uppercase characters, not in compliance with V-204407."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "ucredit = -1" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password to require a number of lowercase characters, V-204408
function V204408 () {
    local Regex1="^(\s*)#\s*lcredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*lcredit\s*=\s*\S+(\s*#.*)?\s*$/lcredit = -1\2/"
    local Regex3="^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)lcredit\s*=\s*\S+(\s*#.*)?\s*$/lcredit = -1\2/"
    local Regex5="^(\s*)lcredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of lowercase characters, per V-204408"
    local Failure="Password isn't set to require a number of lowercase characters, not in compliance with V-204408."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "ucredit = -1" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password to require a number of numerical characters, V-204409
function V204409 () {
    local Regex1="^(\s*)#\s*dcredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*dcredit\s*=\s*\S+(\s*#.*)?\s*$/dcredit = -1\2/"
    local Regex3="^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)dcredit\s*=\s*\S+(\s*#.*)?\s*$/dcredit = -1\2/"
    local Regex5="^(\s*)dcredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of numerical characters, per V-204409"
    local Failure="Password isn't set to require a number of numerical characters, not in compliance with V-204409."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "ucredit = -1" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password to require a number of special characters, V-204410
function V204410 () {
    local Regex1="^(\s*)#\s*ocredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*ocredit\s*=\s*\S+(\s*#.*)?\s*$/ocredit = -1\2/"
    local Regex3="^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)ocredit\s*=\s*\S+(\s*#.*)?\s*$/ocredit = -1\2/"
    local Regex5="^(\s*)ocredit\s*=\s*-1\s*$"
    local Success="Password is set to require a number of special characters, per V-204410"
    local Failure="Password isn't set to require a number of special characters, not in compliance with V-204410."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "ucredit = -1" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set min number of characters changed from old password, V-204411
function V204411 () {
    local Regex1="^(\s*)#\s*difok\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*difok\s*=\s*\S+(\s*#.*)?\s*$/\difok = 8\2/"
    local Regex3="^(\s*)difok\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)difok\s*=\s*\S+(\s*#.*)?\s*$/\difok = 8\2/"
    local Regex5="^(\s*)difok\s*=\s*8\s*$"
    local Success="Set so a min number of 8 characters are changed from the old password, per V-204411"
    local Failure="Failed to set the password to use a min number of 8 characters are changed from the old password, not in compliance with V-204411"

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "difok = 8" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set min required classes of characters for a new password, V-204412
function V204412 () {
    local Regex1="^(\s*)#\s*minclass\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*minclass\s*=\s*\S+(\s*#.*)?\s*$/\minclass = 4\2/"
    local Regex3="^(\s*)minclass\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)minclass\s*=\s*\S+(\s*#.*)?\s*$/\minclass = 4\2/"
    local Regex5="^(\s*)minclass\s*=\s*4\s*$"
    local Success="Password set to use a min number of 4 character classes in a new password, per V-204412."
    local Failure="Failed to set password to use a min number of 4 character classes in a new password, not in compliance with V-204412."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "minclass = 4" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set max number of characters that can repeat, V-204413
function V204413 () {
    local Regex1="^(\s*)#\s*maxrepeat\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*maxrepeat\s*=\s*\S+(\s*#.*)?\s*$/\maxrepeat = 3\2/"
    local Regex3="^(\s*)maxrepeat\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)maxrepeat\s*=\s*\S+(\s*#.*)?\s*$/\maxrepeat = 3\2/"
    local Regex5="^(\s*)maxrepeat\s*=\s*3\s*$"
    local Success="Passwords are set to only allow 3 repeat characters in a new password, per V-204413."
    local Failure="Failed to set passwords to only allow 3 repeat characters in a new password, not in compliance with V-204413."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "maxrepeat = 3" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set max number of characters of the same class that can repeat, V-204414
function V204414 () {
    local Regex1="^(\s*)#\s*maxclassrepeat\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*maxclassrepeat\s*=\s*\S+(\s*#.*)?\s*$/\maxclassrepeat = 4\2/"
    local Regex3="^(\s*)maxclassrepeat\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)maxclassrepeat\s*=\s*\S+(\s*#.*)?\s*$/\maxclassrepeat = 4\2/"
    local Regex5="^(\s*)maxclassrepeat\s*=\s*4\s*$"
    local Success="Passwords are set to only allow 4 characters of the same class to repeat in a new password, per V-204414."
    local Failure="Failed to set passwords only allow 4 repeat characters of the same class in a new password, not in compliance with V-204414."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "maxclassrepeat = 4" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set passwords to use SHA512, V-204415
function V204415 () {
    local Regex1="^\s*password\s+sufficient\s+pam_unix.so\s+"
    local Regex2="/^\s*password\s+sufficient\s+pam_unix.so\s+/ { /^\s*password\s+sufficient\s+pam_unix.so(\s+\S+)*(\s+sha512)(\s+.*)?$/! s/^(\s*password\s+sufficient\s+pam_unix.so\s+)(.*)$/\1sha512 \2/ }"
    local Regex3="^\s*password\s+sufficient\s+pam_unix.so\s+.*sha512\s*.*$"
    local Success="Passwords are set to use SHA512 encryption, per V-204415."
    local Failure="Failed to set passwords to use SHA512 encryption, not in compliance with V-204415."

    echo
    (grep -E -q "$Regex1" /etc/pam.d/system-auth && sed -ri  "$Regex2" /etc/pam.d/system-auth)
    (grep -E -q "$Regex1" /etc/pam.d/password-auth && sed -ri  "$Regex2" /etc/pam.d/password-auth)
    ( (grep -E -q "$Regex3" /etc/pam.d/password-auth && grep -E -q "$Regex3" /etc/pam.d/system-auth) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to create SHA512 hashed passwords, V-204416
function V204416 () {
    local Regex1="^(\s*)ENCRYPT_METHOD\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)ENCRYPT_METHOD\s*\S+(\s*#.*)?\s*$/ENCRYPT_METHOD SHA512\2/"
    local Regex3="^\s*ENCRYPT_METHOD\s*SHA512\s*.*$"
    local Success="Passwords are set to be created with SHA512 hash, per V-204416."
    local Failure="Failed to set passwords to be created with SHA512 hash, not in compliance with V-204416."

    echo
    (grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs) || echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
    (grep -E -q "$Regex3" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to store only encrypted representations of passwords in SHA512, V-204417
function V204417 () {
    local Regex1="^(\s*)#\s*crypt_style\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*crypt_style\s*=\s*\S+(\s*#.*)?\s*$/crypt_style = sha512\2/"
    local Regex3="^(\s*)crypt_style\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)crypt_style\s*=\s*\S+(\s*#.*)?\s*$/crypt_style = sha512\2/"
    local Regex5="^(\s*)crypt_style\s*=\s*sha512\s*$"
    local Success="Admin utilities are configured to store only encrypted SHA512 passwords, per V-204417."
    local Failure="Failed to set admin utilities are configured to store only encrypted SHA512 passwords, not in compliance with V-204417."

    echo
    ( (grep -E -q "$Regex1" /etc/libuser.conf && sed -ri "$Regex2" /etc/libuser.conf) || (grep -E -q "$Regex3" /etc/libuser.conf && sed -ri "$Regex4" /etc/libuser.conf) ) || echo "crypt_style = sha512" >> /etc/libuser.conf
    (grep -E -q "$Regex5" /etc/libuser.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password min lifetome to 1 day, V-204418
function V204418 () {
    local Regex1="^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)PASS_MIN_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MIN_DAYS 1\2/"
    local Regex3="^(\s*)PASS_MIN_DAYS\s*1\s*$"
    local Success="Passwords are set to have a minimum lifetime of 1 day, per V-204418."
    local Failure="Failed to set passwords to have a minimum lifetime of 1 day, not in compliance with V-204418."

    echo
    (grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs) || echo "PASS_MIN_DAYS 1" >> /etc/login.defs
    getent passwd | cut -d ':' -f 1 | xargs -n1 chage --mindays 1
    (grep -E -q "$Regex3" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set password max lifetime to 60 days, V-204420, disabled due to able to break some build automaiton.
function V204420 () {
    local Regex1="^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)PASS_MAX_DAYS\s+\S+(\s*#.*)?\s*$/\PASS_MAX_DAYS 60\2/"
    local Regex3="^(\s*)PASS_MAX_DAYS\s*60\s*$"
    local Success="Passwords are set to have a maximum lifetime to 60 days, per V-204420."
    local Failure="Failed to set passwords to have a maximum lifetime to 60 days, not in compliance with V-204420."

    echo
    grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs || echo "PASS_MAX_DAYS 60" >> /etc/login.defs
    getent passwd | cut -d ':' -f 1 | xargs -n1 chage --maxdays 60
    grep -E -q "$Regex3" /etc/login.defs && echo "$Success" || { echo "$Failure" ; exit 1; }
}

#Limit password reuse to 5, V-204422
function V204422 () {
    local Regex1="^\s*password\s+requisite\s+\s*pam_pwhistory.so\s*use_authtok\s*remember=\S+(\s*#.*)?(\s+.*)$"
    local Regex2="s/^(\s*)password\s+requisite\s+\s*pam_pwhistory.so\s*use_authtok\s*remember=\S+(\s*#.*)\s*retry=\S+(\s*#.*)?\s*S/\password\s+requisite\s+\s*pam_pwhistory.so\s*use_authtok\s*remember=5\s*retry=3\2/"
    local Regex3="^(\s*)password\s+requisite\s+\s*pam_pwhistory.so\s*use_authtok\s*remember=5\s*retry=3\s*$"
    local Success="System is set to keep password history of the last 5 passwords, per V-204422."
    local Failure="Failed to set the system to keep password history of the last 5 passwords, not in compliance with V-204422."

    echo
    (grep -E -q "$Regex1" /etc/pam.d/system-auth && sed -ri  "$Regex2" /etc/pam.d/system-auth) || echo "password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3" >> /etc/pam.d/system-auth
    (grep -E -q "$Regex1" /etc/pam.d/password-auth && sed -ri  "$Regex2" /etc/pam.d/password-auth) || echo "password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3" >> /etc/pam.d/password-auth
    ( (grep -E -q "$Regex3" /etc/pam.d/password-auth && grep -E -q "$Regex3" /etc/pam.d/system-auth) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set min 15 character password length, V-204423
function V204423 () {
    local Regex1="^(\s*)#\s*minlen\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#\s*minlen\s*=\s*\S+(\s*#.*)?\s*$/\minlen = 15\2/"
    local Regex3="^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)minlen\s*=\s*\S+(\s*#.*)?\s*$/\minlen = 15\2/"
    local Regex5="^(\s*)minlen\s*=\s*15\s*$"
    local Success="Passwords are set to have a min of 15 characters, per V-204423."
    local Failure="Failed to set passwords to use a min of 15 characters, not in compliance with V-204423."

    echo
    ( (grep -E -q "$Regex1" /etc/security/pwquality.conf && sed -ri "$Regex2" /etc/security/pwquality.conf) || (grep -E -q "$Regex3" /etc/security/pwquality.conf && sed -ri "$Regex4" /etc/security/pwquality.conf) ) || echo "crypt_style = sha512" >> /etc/security/pwquality.conf
    (grep -E -q "$Regex5" /etc/security/pwquality.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable account identifiers, V-204426
function V204426 () {
    local Regex1="^(\s*)INACTIVE=\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)INACTIVE=\S+(\s*#.*)?\s*$/\INACTIVE=0\2/"
    local Regex3="^(\s*)INACTIVE=0\s*$"
    local Success="Account identifiers are disabled once the password expires, per V-204426."
    local Failure="Failed to set account identifiers are disabled once the password expires, not in compliance with V-204426."

    echo
    (grep -E -q "$Regex1" /etc/default/useradd && sed -ri "$Regex2" /etc/default/useradd) || echo "INACTIVE=0" >> /etc/default/useradd
    (grep -E -q "$Regex3" /etc/default/useradd && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to lock account after 3 failed logon attempts within 15 mins even deny root, V-204427 & V-204428
function V204427 () {
    local Regex1="^\s*auth\s+required\s+pam_faillock.so\s*"
    local Regex2="s/^\s*auth\s+\s*\s*\s*required\s+pam_faillock.so\s*"
    local Regex3="auth        required      pam_faillock.so preauth audit deny=3 even_deny_root fail_interval=900 unlock_time=900"
    local Regex4="^\s*auth\s+sufficient\s+pam_unix.so\s*"
    local Regex5="s/^\s*auth\s+\s*\s*\s*sufficient\s+pam_unix.so\s*"
    local Regex6="auth        sufficient    pam_unix.so try_first_pass"
    local Regex7="^\s*auth\s+\[default=die\]\s+pam_faillock.so\s*"
    local Regex8="s/^\s*auth\s+\s*\s*\s*\[default=die\]\s+pam_faillock.so\s*"
    local Regex9="auth        [default=die] pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=900"
    local Regex10="^\s*account\s+required\s+pam_faillock.so\s*"
    local Regex11="s/^\s*account\s+\s*\s*\s*required\s+pam_faillock.so\s*"
    local Regex12="account     required      pam_faillock.so"
    local Regex13="^(\s*)auth\s+required\s+\s*pam_faillock.so\s*preauth\s*audit\s*deny=3\s*even_deny_root\s*fail_interval=900\s*unlock_time=900\s*$"
    local Regex14="^(\s*)auth\s+sufficient\s+\s*pam_unix.so\s*try_first_pass\s*$"
    local Regex15="^(\s*)auth\s+\[default=die\]\s+pam_faillock.so\s*authfail\s*audit\s*deny=3\s*even_deny_root\s*fail_interval=900\s*unlock_time=900\s*$"
    local Regex16="^(\s*)account\s+required\s+\s*pam_faillock.so\s*$"
    local Success="Account lockout time after 3 failed logon attempts set to 15 mins even deny root, per V-204427 & V-204428."
    local Failure="Failed to set account lockout time after 3 failed logon attempts set to 15 mins even deny root, not in compliance with V-204427 & V-204428."

    echo
    (grep -E -q "$Regex1" /etc/pam.d/system-auth && sed -ri  "$Regex2.*$/$Regex3/" /etc/pam.d/system-auth) || echo "$Regex3" >> /etc/pam.d/system-auth
    (grep -E -q "$Regex1" /etc/pam.d/password-auth && sed -ri  "$Regex2.*$/$Regex3/" /etc/pam.d/password-auth) || echo "$Regex3" >> /etc/pam.d/password-auth
    (grep -E -q "$Regex4" /etc/pam.d/system-auth && sed -ri  "$Regex5.*$/$Regex6/" /etc/pam.d/system-auth) || echo "$Regex6" >> /etc/pam.d/system-auth
    (grep -E -q "$Regex4" /etc/pam.d/password-auth && sed -ri  "$Regex5.*$/$Regex6/" /etc/pam.d/password-auth) || echo "$Regex6" >> /etc/pam.d/password-auth
    (grep -E -q "$Regex7" /etc/pam.d/system-auth && sed -ri  "$Regex8.*$/$Regex9/" /etc/pam.d/system-auth) || echo "$Regex9" >> /etc/pam.d/system-auth
    (grep -E -q "$Regex7" /etc/pam.d/password-auth && sed -ri  "$Regex8.*$/$Regex9/" /etc/pam.d/password-auth) || echo "$Regex9" >> /etc/pam.d/password-auth
    (grep -E -q "$Regex10" /etc/pam.d/system-auth && sed -ri  "$Regex11.*$/$Regex12/" /etc/pam.d/system-auth) || echo "$Regex12" >> /etc/pam.d/system-auth
    (grep -E -q "$Regex10" /etc/pam.d/password-auth && sed -ri  "$Regex11.*$/$Regex12/" /etc/pam.d/password-auth) || echo "$Regex12" >> /etc/pam.d/password-auth

    ( (grep -E -q "$Regex13" /etc/pam.d/password-auth && grep -E -q "$Regex13" /etc/pam.d/system-auth) && echo "$Success") || { echo "$Failure" ; exit 1; }
    ( (grep -E -q "$Regex14" /etc/pam.d/password-auth && grep -E -q "$Regex14" /etc/pam.d/system-auth) && echo "$Success") || { echo "$Failure" ; exit 1; }
    ( (grep -E -q "$Regex15" /etc/pam.d/password-auth && grep -E -q "$Regex15" /etc/pam.d/system-auth) && echo "$Success") || { echo "$Failure" ; exit 1; }
    ( (grep -E -q "$Regex16" /etc/pam.d/password-auth && grep -E -q "$Regex16" /etc/pam.d/system-auth) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set delay between failed logon attenpts, V-204431
function V204431 () {
    local Regex1="^(\s*)FAIL_DELAY\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)FAIL_DELAY\s+\S+(\s*#.*)?\s*$/\FAIL_DELAY 4\2/"
    local Regex3="^(\s*)FAIL_DELAY\s*4\s*$"
    local Success="Set a 4 sec delay between failed logon attempts, per V-204431."
    local Failure="Failed to set a 4 sec delay between failed logon attempts, not in compliance with V-204431."

    echo
    (grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs) || echo "FAIL_DELAY 4" >> /etc/login.defs
    (grep -E -q "$Regex3" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
}

# Set SSH HostbasedAuthentication to no, V-204435
function V204435 () {
    local Regex1="^(\s*)#HostbasedAuthentication\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\HostbasedAuthentication no\2/"
    local Regex3="^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)HostbasedAuthentication\s+\S+(\s*#.*)?\s*$/\HostbasedAuthentication no\2/"
    local Regex5="^(\s*)HostbasedAuthentication\s*no\s*$"
    local Success="Set OS to not allow non-certificate trusted host SSH to log onto the system, per V-204435."
    local Failure="Failed to set OS to not allow non-certificate trusted host SSH to log onto the system, not in compliance with V-204435."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) )|| echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable USB mass storage, V-204449
function V204449 () {
    local Regex1="^\s*install\s*usb-storage\s*/bin/true\s*"
    local Regex2="s/^\s*install\s*usb-storage\s*.*$/install usb-storage \/bin\/true/"
    local Regex3="install usb-storage /bin/true"
    local Regex4="^\s*blacklist\s*usb-storage\s*"
    local Regex5="s/^\s*blacklist\s*usb-storage\s*"
    local Regex6="blacklist usb-storage"
    local Success="Configured to disable USB mass storage, per V-204449."
    local Failure="Failed to configure system to disable USB mass storage, not in compliance with V-204449."

    echo
    if [ ! -d "/etc/modprobe.d/" ]
    then
        mkdir -p /etc/modprobe.d/
    fi

    if [ -f "/etc/modprobe.d/usb-storage.conf" ]
    then
        (grep -E -q "$Regex1" /etc/modprobe.d/usb-storage.conf && sed -ri "$Regex2" /etc/modprobe.d/usb-storage.conf) || echo "$Regex3" >> /etc/modprobe.d/usb-storage.conf
    else
        echo "$Regex3" >> /etc/modprobe.d/usb-storage.conf
    fi

    if [ -f "/etc/modprobe.d/blacklist.conf" ]
    then
        (grep -E -q "$Regex4" /etc/modprobe.d/blacklist.conf && sed -ri "$Regex5.*$/$Regex6/" /etc/modprobe.d/blacklist.conf) || echo "$Regex6" >> /etc/modprobe.d/blacklist.conf
    else
        echo "$Regex6" >> /etc/modprobe.d/blacklist.conf
    fi

    ( (grep -E -q "$Regex1" /etc/modprobe.d/usb-storage.conf && grep -E -q "$Regex4" /etc/modprobe.d/blacklist.conf) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable system automounter, V-204451
function V204451 () {
    local Success="Disabled AUTOFS on the system, per V-204451."
    local Failure="Failed to disabled AUTOFS on the system, not in compliance with V-204451."
    local Unneeded="AUTOFS was not installed on the system.  Disabled by default, per V-204451."

    echo
    if systemctl list-unit-files --full -all | grep -Fq 'autofs'
    then
        systemctl stop autofs
        systemctl disable autofs
        ( (systemctl status autofs | grep -E -q "dead") && echo "$Success") || { echo "$Failure" ; exit 1; }
    else
        echo "$Unneeded"
    fi
}

#Set system to apply the most restricted default permissions for all authenticated users, V-204457
function V204457 () {
    local Regex1="^(\s*)UMASK\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)UMASK\s+\S+(\s*#.*)?\s*$/\1UMASK           077\2/"
    local Regex3="^(\s*)UMASK\s*077\s*$"
    local Success="Set system to apply the most restricted default permissions for all authenticated users, per V-204457."
    local Failure="Failed to set the system to apply the most restricted default permissions for all authenticated users, not in compliance with V-204457."

    echo
    (grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs) || echo "UMASK           077" >> /etc/login.defs
    (grep -E -q "$Regex3" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system create a home directory on login, V-204466
function V204466 () {
    local Regex1="^(\s*)CREATE_HOME\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)CREATE_HOME\s+\S+(\s*#.*)?\s*$/\CREATE_HOME     yes\2/"
    local Regex3="^(\s*)CREATE_HOME\s*yes\s*$"
    local Success="Set system create a home directory on login, per V-204466."
    local Failure="Failed to set the system create a home directory on login, not in compliance with V-204466."

    echo
    (grep -E -q "$Regex1" /etc/login.defs && sed -ri "$Regex2" /etc/login.defs) || echo "CREATE_HOME     yes" >> /etc/login.defs
    (grep -E -q "$Regex3" /etc/login.defs && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit of privileged functions, V-204516
function V204516 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-k\s+setuid\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+execve\s+-C\s+uid!=euid\s+-F\s+euid=0\s+-k\s+setuid\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+execve\s+-C\s+gid!=egid\s+-F\s+egid=0\s+-k\s+setgid\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+execve\s+-C\s+gid!=egid\s+-F\s+egid=0\s+-k\s+setgid\s*(#.*)?$"
    local Success32="Auditing of privileged functions is enabled on 32bit systems, per V-204516."
    local Success64="Auditing of privileged functions is enabled on 64bit systems, per V-204516."
    local Failure32="Failed to set auditing of privileged functions on 32bit systems, not in compliance with V-204516."
    local Failure64="Failed to set auditing of privileged functions on 64bit systems, not in compliance with V-204516."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { ( (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use chown, V-204517
function V204517 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+chown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+chown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use chown is enabled on 32bit systems, per V-204517."
    local Success64="Auditing of successful/unsuccessful attempts to use chown is enabled on 64bit systems, per V-204517."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use chown on 32bit systems, not in compliance with V-204517."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use chown on 64bit systems, not in compliance with V-204517."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use fchown, V-204518
function V204518 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use fchown is enabled on 32bit systems, per V-204518."
    local Success64="Auditing of successful/unsuccessful attempts to use fchown is enabled on 64bit systems, per V-204518."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchown on 32bit systems, not in compliance with V-204518."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchown on 64bit systems, not in compliance with V-204518."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use lchown, V-204519
function V204519 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use lchown is enabled on 32bit systems, per V-204519."
    local Success64="Auditing of successful/unsuccessful attempts to use lchown is enabled on 64bit systems, per V-204519."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use lchown on 32bit systems, not in compliance with V-204519."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use lchown on 64bit systems, not in compliance with V-204519."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use fchownat, V-204520
function V204520 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchownat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchownat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use fchownat is enabled on 32bit systems, per V-204520."
    local Success64="Auditing of successful/unsuccessful attempts to use fchownat is enabled on 64bit systems, per V-204520."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchownat on 32bit systems, not in compliance with V-204520."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchownat on 64bit systems, not in compliance with V-204520."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use chmod, V-204521
function V204521 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+chmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+chmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use chmod is enabled on 32bit systems, per V-204521."
    local Success64="Auditing of successful/unsuccessful attempts to use chmod is enabled on 64bit systems, per V-204521."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use chmod on 32bit systems, not in compliance with V-204521."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use chmod on 64bit systems, not in compliance with V-204521."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use fchmod, V-204522
function V204522 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchmod\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use fchmod is enabled on 32bit systems, per V-204522."
    local Success64="Auditing of successful/unsuccessful attempts to use fchmod is enabled on 64bit systems, per V-204522."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchmod on 32bit systems, not in compliance with V-204522."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchmod on 64bit systems, not in compliance with V-204522."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use fchmodat, V-204523
function V204523 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use fchmodat is enabled on 32bit systems, per V-204523."
    local Success64="Auditing of successful/unsuccessful attempts to use fchmodat is enabled on 64bit systems, per V-204523."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fchmodat on 32bit systems, not in compliance with V-204523."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fchmodat on 64bit systems, not in compliance with V-204523."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use setxattr, V-204524
function V204524 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+setxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+setxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use setxattr is enabled on 32bit systems, per V-204524."
    local Success64="Auditing of successful/unsuccessful attempts to use setxattr is enabled on 64bit systems, per V-204524."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use setxattr on 32bit systems, not in compliance with V-204524."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use setxattr on 64bit systems, not in compliance with V-204524."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use fsetxattr, V-204525
function V204525 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use fsetxattr is enabled on 32bit systems, per V-204525."
    local Success64="Auditing of successful/unsuccessful attempts to use fsetxattr is enabled on 64bit systems, per V-204525."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fsetxattr on 32bit systems, not in compliance with V-204525."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fsetxattr on 64bit systems, not in compliance with V-204525."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use lsetxattr, V-204526
function V204526 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+lsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+lsetxattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use lsetxattr is enabled on 32bit systems, per V-72215."
    local Success64="Auditing of successful/unsuccessful attempts to use lsetxattr is enabled on 64bit systems, per V-72215."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use lsetxattr on 32bit systems, not in compliance with V-72215."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use lsetxattr on 64bit systems, not in compliance with V-72215."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use removexattr, V-204527
function V204527 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+removexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+removexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use removexattr is enabled on 32bit systems, per V-204527."
    local Success64="Auditing of successful/unsuccessful attempts to use removexattr is enabled on 64bit systems, per V-204527."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use removexattr on 32bit systems, not in compliance with V-204527."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use removexattr on 64bit systems, not in compliance with V-204527."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use fremovexattr, V-204528
function V204528 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use fremovexattr is enabled on 32bit systems, per V-204528."
    local Success64="Auditing of successful/unsuccessful attempts to use fremovexattr is enabled on 64bit systems, per V-204528."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use fremovexattr on 32bit systems, not in compliance with V-204528."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use fremovexattr on 64bit systems, not in compliance with V-204528."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use lremovexattr, V-204529
function V204529 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+lremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+lremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use lremovexattr is enabled on 32bit systems, per V-204529."
    local Success64="Auditing of successful/unsuccessful attempts to use lremovexattr is enabled on 64bit systems, per V-204529."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use lremovexattr on 32bit systems, not in compliance with V-204529."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use lremovexattr on 64bit systems, not in compliance with V-204529."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use creat, V-204530
function V204530 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+creat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+creat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+creat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+creat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use creat is enabled on 32bit systems, per V-204530."
    local Success64="Auditing of successful/unsuccessful attempts to use creat is enabled on 64bit systems, per V-204530."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use creat on 32bit systems, not in compliance with V-204530."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use creat on 64bit systems, not in compliance with V-204530."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use open, V-204531
function V204531 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use open is enabled on 32bit systems, per V-204531."
    local Success64="Auditing of successful/unsuccessful attempts to use open is enabled on 64bit systems, per V-204531."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use open on 32bit systems, not in compliance with V-204531."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use open on 64bit systems, not in compliance with V-204531."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use openat, V-204532
function V204532 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+openat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+openat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+openat\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+openat\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use openat is enabled on 32bit systems, per V-204532."
    local Success64="Auditing of successful/unsuccessful attempts to use openat is enabled on 64bit systems, per V-204532."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use openat on 32bit systems, not in compliance with V-204532."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use openat on 64bit systems, not in compliance with V-204532."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use open_by_handle_at, V-204533
function V204533 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open_by_handle_at\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+open_by_handle_at\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open_by_handle_at\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+open_by_handle_at\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use open_by_handle_at is enabled on 32bit systems, per V-204533."
    local Success64="Auditing of successful/unsuccessful attempts to use open_by_handle_at is enabled on 64bit systems, per V-204533."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use open_by_handle_at on 32bit systems, not in compliance with V-204533."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use open_by_handle_at on 64bit systems, not in compliance with V-204533."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use truncate, V-204534
function V204534 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+truncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+truncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+truncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+truncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use truncate is enabled on 32bit systems, per V-204534."
    local Success64="Auditing of successful/unsuccessful attempts to use truncate is enabled on 64bit systems, per V-204534."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use truncate on 32bit systems, not in compliance with V-204534."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use truncate on 64bit systems, not in compliance with V-204534."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use ftruncate, V-204535
function V204535 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Regex4="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*(#.*)?$"
    local Success32="Auditing of successful/unsuccessful attempts to use ftruncate is enabled on 32bit systems, per V-204535."
    local Success64="Auditing of successful/unsuccessful attempts to use ftruncate is enabled on 64bit systems, per V-204535."
    local Failure32="Failed to set auditing of successful/unsuccessful attempts to use ftruncate on 32bit systems, not in compliance with V-204535."
    local Failure64="Failed to set auditing of successful/unsuccessful attempts to use ftruncate on 64bit systems, not in compliance with V-204535."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { ( (grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex4" /etc/audit/rules.d/audit.rules) && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use semanage, V-204536
function V204536 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/semanage\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use semanage is enabled, per V-204536."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use semanage, not in compliance with V-204536."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/semanage -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use setsebool, V-204537
function V204537 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/setsebool\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use setsebool is enabled, per V-204537."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use setsebool, not in compliance with V-204537."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/setsebool -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use chcon, V-204538
function V204538 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/chcon\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use chcon is enabled, per V-204538."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use chcon, not in compliance with V-204538."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/chcon -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use setfiles, V-204539
function V204539 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/setfiles\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use setfiles is enabled, per V-204539."
    local Failure="Failed to set auditing of successful/unsuccessful attempts to use setfiles, not in compliance with V-204539."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/setfiles -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit when unsuccessful account access events occur, V-204540
function V204540 () {
    local Regex1="^\s*-w\s+/var/run/faillock\s+-p\s+wa\s+-k\s+logins\s*(#.*)?$"
    local Success="Auditing of unsuccessful account access events occur is enabled, per V-204540."
    local Failure="Failed to set auditing of when unsuccessful account access events occur, not in compliance with V-204540."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit when successful account access events occur, V-204541
function V204541 () {
    local Regex1="^\s*-w\s+/var/log/lastlog\s+-p\s+wa\s+-k\s+logins\s*(#.*)?$"
    local Success="Auditing of successful account access events occur is enabled, per V-204541."
    local Failure="Failed to set auditing of when successful account access events occur, not in compliance with V-204541."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use passwd, V-204542
function V204542 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/passwd\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use passwd is enabled, per V-204542."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use passwd occur, not in compliance with V-204542."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/passwd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use unix_chkpwd, V-204543
function V204543 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/unix_chkpwd\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use unix_chkpwd is enabled, per V-204543."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use unix_chkpwd occur, not in compliance with V-204543."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/unix_chkpwd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use gpasswd, V-204544
function V204544 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/gpasswd\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use gpasswd is enabled, per V-204544."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use gpasswd occur, not in compliance with V-204544."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/gpasswd -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use chage, V-204545
function V204545 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/chage\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use chage is enabled, per V-204545."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use chage occur, not in compliance with V-204545."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/chage -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use userhelper, V-204546
function V204546 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/userhelper\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use userhelper, per V-204546."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use userhelper occur, not in compliance with V-204546."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/userhelper -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use su, V-204547
function V204547 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/su\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use su, per V-204547."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use su occur, not in compliance with V-204547."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/su -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use sudo, V-204548
function V204548 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/sudo\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-passwd\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use sudo, per V-204548."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use sudo occur, not in compliance with V-204548."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful access attempts to /etc/sudoers and /etc/sudoers.d, V-204549
function V204549 () {
    local Regex1="^\s*-w\s+/etc/sudoers\s+-p\s+wa\s+-k\s+privileged-actions\s*(#.*)?$"
    local Regex2="^\s*-w\s+/etc/sudoers.d/\s+-p\s+wa\s+-k\s+privileged-actions\s*(#.*)?$"
    local Success="Auditing of the successful/unsuccessful access attempts to /etc/sudoers and /etc/sudoers.d, per V-204549."
    local Failure="Failed to set the auditing of successful/unsuccessful attempts to access /etc/sudoers and /etc/sudoers.d, not in compliance with V-204549."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers.d/ -p wa -k privileged-actions" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use newgrp, V-204550
function V204550 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/newgrp\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use newgrp, per V-204550."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use newgrp occur, not in compliance with V-204550."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/newgrp -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use chsh, V-204551
function V204551 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/chsh\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-priv_change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use chsh, per V-204551."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use chsh occur, not in compliance with V-204551."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/chsh -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use mount, V-204552
function V204552 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use mount on 32bit systems, per V-204552."
    local Success64="Auditing of the successful/unsuccessful access attempts to use mount on 64bit systems, per V-204552."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use mount on 32bit systems, not in compliance with V-204552."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use mount on 64bit systems, not in compliance with V-204552."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    ( (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && grep -E -q "$Regex3" /etc/audit/rules.d/audit.rules) && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use umount, V-204553
function V204553 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/umount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use umount, per V-204553."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use umount occur, not in compliance with V-204553."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/umount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use postdrop, V-204554
function V204554 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/postdrop\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-postfix\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use postdrop, per V-204554."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use postdrop occur, not in compliance with V-204554."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/postdrop -F auid>=1000 -F auid!=4294967295 -k privileged-postfix" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use postqueue, V-204555
function V204555 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/postqueue\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-postfix\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use postqueue, per V-204555."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use postqueue occur, not in compliance with V-204555."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/postqueue -F auid>=1000 -F auid!=4294967295 -k privileged-postfix" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use ssh-keysign, V-204556
function V204556 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/libexec/openssh/ssh-keysign\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-ssh\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use ssh-keysign, per V-204556."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use ssh-keysign occur, not in compliance with V-204556."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use crontab, V-204557
function V204557 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/crontab\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-cron\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use crontab, per V-204557."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use crontab occur, not in compliance with V-204557."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/bin/crontab -F auid>=1000 -F auid!=4294967295 -k privileged-cron" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use pam_timestamp_check, V-204558
function V204558 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+path=/usr/sbin/pam_timestamp_check\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-pam\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use pam_timestamp_check, per V-204558."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use pam_timestamp_check occur, not in compliance with V-204558."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F auid>=1000 -F auid!=4294967295 -k privileged-pam" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use init_module, V-204560
function V204560 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+init_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+init_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex3="^\s*-a\s+always,exit\s+-F\s+path=/usr/bin/mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged-mount\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use init_module on 32bit systems, per V-204560."
    local Success64="Auditing of the successful/unsuccessful access attempts to use init_module on 64bit systems, per V-204560."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use init_module on 32bit systems, not in compliance with V-204560."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use init_module on 64bit systems, not in compliance with V-204560."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S init_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S init_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use delete_module, V-204562
function V204562 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+delete_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+delete_module\s+-k\s+module-change\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use delete_module on 32bit systems, per V-204562."
    local Success64="Auditing of the successful/unsuccessful access attempts to use delete_module on 64bit systems, per V-204562."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use delete_module on 32bit systems, not in compliance V-204562."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use delete_module on 64bit systems, not in compliance V-204562."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S delete_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S delete_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use kmod, V-204563
function V204563 () {
    local Regex1="^\s*-w\s+/usr/bin/kmod\s+-p\s+x\s+-F\s+auid!=4294967295\s+-k\s+module-change\s*(#.*)?$"
    local Success="Auditing of successful/unsuccessful attempts to use kmod, per V-204563."
    local Failure="Failed to set auditing of when successful/unsuccessful attempts to use kmod occur , not in compliance V-204563."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /usr/bin/kmod -p x -F auid!=4294967295 -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/passwd", V-204564
function V204564 () {
    local Regex1="^\s*-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
    local Success="Auditing of all account creations, modifications, disabling, and termination events that affect '/etc/passwd', per V-204564."
    local Failure="Failed to set auditing of all account creations, modifications, disabling, and termination events that affect '/etc/passwd', not in compliance V-204564."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit of successful/unsuccessful attempts to use rename, V-204569
function V204569 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+rename\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+rename\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use rename on 32bit systems, per V-204569."
    local Success64="Auditing of the successful/unsuccessful access attempts to use rename on 64bit systems, per V-204569."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use rename on 32bit systems, not in compliance V-204569."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use rename on 64bit systems, not in compliance V-204569."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use renameat, V-204570
function V204570 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use renameat on 32bit systems, per V-204570."
    local Success64="Auditing of the successful/unsuccessful access attempts to use renameat on 64bit systems, per V-204570."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use renameat on 32bit systems, not in compliance V-204570."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use renameat on 32bit systems, not in compliance V-204570."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use rmdir, V-204571
function V204571 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+rmdir\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+rmdir\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use rmdir on 32bit systems, per V-204571."
    local Success64="Auditing of the successful/unsuccessful access attempts to use rmdir on 64bit systems, per V-204571."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use rmdir on 32bit systems, not in compliance V-204571."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use rmdir on 64bit systems, not in compliance V-204571."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S rmdir -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use unlink, V-204572
function V204572 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+unlink\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+unlink\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use unlink on 32bit systems, per V-204572."
    local Success64="Auditing of the successful/unsuccessful access attempts to use unlink on 64bit systems, per V-204572."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 32bit systems, not in compliance V-204572."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 64bit systems, not in compliance V-204572."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use unlinkat, V-204573
function V204573 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+unlinkat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+unlinkat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use unlink on 32bit systems, per V-204573."
    local Success64="Auditing of the successful/unsuccessful access attempts to use unlink on 64bit systems, per V-204573."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 32bit systems, not in compliance V-204573."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use unlink on 64bit systems, not in compliance V-204573."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set SSH to use FIPS, V-204578
function V204578 () {
    local Regex1="^(\s*)Ciphers\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)Ciphers\s+\S+(\s*#.*)?\s*$/\Ciphers aes128-ctr,aes192-ctr,aes256-ctr\2/"
    local Regex3="^(\s*)Ciphers\s*aes128-ctr,aes192-ctr,aes256-ctr\s*$"
    local Success="Set SSH to use FIPS, per V-204578."
    local Failure="Failed to set SSH to use FIPS, not in compliance V-204578."

    echo
    (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex3" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set timeout to 600sec, V-204579
function V204579 () {
    local Success="Set terminal timeout period to 600secs, per V-204579."
    local Failure="Failed to set terminal timeout period to 600secs, not in compliance V-204579."

    echo
    if [ -f "/etc/profile.d/tmout.sh" ]
    then
        grep -E -q "^\s*TMOUT=600\s*(#.*)?$" /etc/profile.d/tmout.sh || echo "TMOUT=600" >> /etc/profile.d/tmout.sh
        grep -E -q "^\s*readonly\s*TMOUT\s*(#.*)?$" /etc/profile.d/tmout.sh || echo "readonly TMOUT" >> /etc/profile.d/tmout.sh
        grep -E -q "^\s*export\s*TMOUT\s*(#.*)?$" /etc/profile.d/tmout.sh || echo "export TMOUT" >> /etc/profile.d/tmout.sh
    else
        echo -e "#!/bin/bash\n\nTMOUT=600\nreadonly TMOUT\nexport TMOUT" >> /etc/profile.d/tmout.sh
    fi
    ( (grep -E -q "^\s*TMOUT=600?\s*$" /etc/profile.d/tmout.sh && grep -E -q "^\s*readonly\s*TMOUT?\s*$" /etc/profile.d/tmout.sh && grep -E -q "^\s*export\s*TMOUT\s*$" /etc/profile.d/tmout.sh) && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set timeout period, V-204587
function V204587 () {
    local Regex1="^(\s*)#ClientAliveInterval\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\ClientAliveInterval 600\2/"
    local Regex3="^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)ClientAliveInterval\s+\S+(\s*#.*)?\s*$/\ClientAliveInterval 600\2/"
    local Regex5="^(\s*)ClientAliveInterval\s*600?\s*$"
    local Success="Set SSH user timeout period to 600secs, per V-204587."
    local Failure="Failed to set SSH user timeout period to 600secs, not in compliance V-204587."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set terminate user session after timeout, V-204589
function V204589 () {
    local Regex1="^(\s*)#ClientAliveCountMax\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\ClientAliveCountMax 0\2/"
    local Regex3="s/^(\s*)ClientAliveCountMax\s+\S+(\s*#.*)?\s*$/\ClientAliveCountMax 0\2/"
    local Regex4="^(\s*)ClientAliveCountMax\s*0?\s*$"
    local Success="Set SSH user sesstions to terminate after session timeout, per V-204589."
    local Failure="Failed to set SSH user sesstions to terminate after session timeout, not in compliance V-204589."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex4" /etc/ssh/sshd_config && sed -ri "$Regex3" /etc/ssh/sshd_config) ) || echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex4" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set to not allow authentication using known host, V-204590
function V204590 () {
    local Regex1="^(\s*)#IgnoreRhosts\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\IgnoreRhosts yes\2/"
    local Regex3="^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)IgnoreRhosts\s+\S+(\s*#.*)?\s*$/\IgnoreRhosts yes\2/"
    local Regex5="^(\s*)IgnoreRhosts\s*yes?\s*$"
    local Success="Set SSH to not allow rhosts authentication, per V-204590."
    local Failure="Failed to set SSH to not allow rhosts authentication, not in compliance V-204590."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set to provide feedback on last account access, V-204591
function V204591 () {
    local Regex1="^(\s*)#PrintLastLog\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#PrintLastLog\s+\S+(\s*#.*)?\s*$/\PrintLastLog yes\2/"
    local Regex3="^(\s*)PrintLastLog\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)PrintLastLog\s+\S+(\s*#.*)?\s*$/\PrintLastLog yes\2/"
    local Regex5="^(\s*)PrintLastLog\s*yes?\s*$"
    local Success="Set SSH to inform users of when the last time their account connected, per V-204591."
    local Failure="Failed to set SSH to inform users of when the last time their account connected, not in compliance V-204591."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "PrintLastLog yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set SSH to prevent root logon, V-204592
function V204592 () {
    local Regex1="^(\s*)#PermitRootLogin\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#PermitRootLogin\s+\S+(\s*#.*)?\s*$/\PermitRootLogin no\2/"
    local Regex3="^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)PermitRootLogin\s+\S+(\s*#.*)?\s*$/\PermitRootLogin no\2/"
    local Regex5="^(\s*)PermitRootLogin\s*no?\s*$"
    local Success="Set SSH to not allow connections from root, per V-204592."
    local Failure="Failed to set SSH to not allow connections from root, not in compliance V-204592."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set to not allow authentication using known host, V-204593
function V204593 {
    local Regex1="^(\s*)#IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$/\IgnoreUserKnownHosts yes\2/"
    local Regex3="^(\s*)IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)IgnoreUserKnownHosts\s+\S+(\s*#.*)?\s*$/\IgnoreUserKnownHosts yes\2/"
    local Regex5="^(\s*)IgnoreUserKnownHosts\s*yes?\s*$"
    local Success="Set SSH to not allow authentication using known host authentication, per V-204593."
    local Failure="Failed to set SSH to not allow authentication using known host authentication, not in compliance V-204593."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "IgnoreUserKnownHosts yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set SSH to only use MACs using FIPS, V-204595
function V204595 () {
    local Regex1="^(\s*)MACs\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)MACs\s+\S+(\s*#.*)?\s*$/\MACs hmac-sha2-256,hmac-sha2-512\2/"
    local Regex3="^(\s*)MACs\s*hmac-sha2-256,hmac-sha2-512\s*$"
    local Success="Set SSH to only use MACs using FIPS, per V-204595."
    local Failure="Failed to set SSH only use MACs using FIPS, not in compliance V-204595."

    echo
    (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || echo "MACs hmac-sha2-256,hmac-sha2-512" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex3" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Do not permit GSSAPI auth, V-204598
function V204598 () {
    local Regex1="^(\s*)GSSAPIAuthentication\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)GSSAPIAuthentication\s+\S+(\s*#.*)?\s*$/\GSSAPIAuthentication no\2/"
    local Regex3="^(\s*)GSSAPIAuthentication\s*no?\s*$"
    local Success="Set SSH to not allow authentication using GSSAPI authentication, per V-204598."
    local Failure="Failed to set SSH to not allow authentication using GSSAPI authentication, not in compliance V-204598."

    echo
    (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex3" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable Kerberos over SSH, V-204599
function V204599 () {
    local Regex1="^(\s*)#KerberosAuthentication\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#KerberosAuthentication\s+\S+(\s*#.*)?\s*$/\KerberosAuthentication no\2/"
    local Regex3="^(\s*)KerberosAuthentication\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)KerberosAuthentication\s+\S+(\s*#.*)?\s*$/\KerberosAuthentication no\2/"
    local Regex5="^(\s*)KerberosAuthentication\s*no?\s*$"
    local Success="Set SSH to not allow authentication using KerberosAuthentication authentication, per V-204599."
    local Failure="Failed to set SSH to not allow authentication using KerberosAuthentication authentication, not in compliance V-204599."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "KerberosAuthentication no" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set SSH to perform strict mode checking of home dir configuraiton files, V-204600
function V204600 () {
    local Regex1="^(\s*)#StrictModes\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#StrictModes\s+\S+(\s*#.*)?\s*$/\StrictModes yes\2/"
    local Regex3="^(\s*)StrictModes\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)StrictModes\s+\S+(\s*#.*)?\s*$/\StrictModes yes\2/"
    local Regex5="^(\s*)StrictModes\s*yes?\s*$"
    local Success="Set SSH to perform strict mode checking of the home directory configuration files, per V-204600."
    local Failure="Failed to set SSH to perform strict mode checking of the home directory configuration files, not in compliance V-204600."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "StrictModes yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set SSH to perform privilege separation, V-204602
function V204602 () {
    local Regex1="^(\s*)#Compression\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#Compression\s+\S+(\s*#.*)?\s*$/\Compression delayed\2/"
    local Regex3="^(\s*)Compression\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)Compression\s+\S+(\s*#.*)?\s*$/\Compression delayed\2/"
    local Regex5="^(\s*)Compression\s*delayed?\s*$"
    local Success="Set SSH to only allow compression after successful authentication, per V-204602."
    local Failure="Failed to set SSH to only allow compression after successful authentication, not in compliance V-204602."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) ) || echo "Compression delayed" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not accept IPv4 source-routed packets, V-204609
function V204609 () {
    local Regex1="^(\s*)#net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_source_route = 0\2/"
    local Regex3="^(\s*)net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_source_route = 0\2/"
    local Regex5="^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*0?\s*$"
    local Success="Set system to not accept IPv4 source-routed packets, per V-204609."
    local Failure="Failed to set the system to not accept IPv4 source-routed packets, not in compliance V-204609."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not accept IPv4 source-routed packets by default, V-204612
function V204612 () {
    local Regex1="^(\s*)#net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_source_route = 0\2/"
    local Regex3="^(\s*)net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.default.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_source_route = 0\2/"
    local Regex5="^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*0?\s*$"
    local Success="Set system to not accept IPv4 source-routed packets by default, per V-204612."
    local Failure="Failed to set the system to not accept IPv4 source-routed packets by default, not in compliance V-204612."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not respond to ICMP, V-204613
function V204613 () {
    local Regex1="^(\s*)#net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$/\net.ipv4.icmp_echo_ignore_broadcasts = 1\2/"
    local Regex3="^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s+\S+(\s*#.*)?\s*$/\net.ipv4.icmp_echo_ignore_broadcasts = 1\2/"
    local Regex5="^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*1?\s*$"
    local Success="Set system to not respond to ICMP on IPv4, per V-204613."
    local Failure="Failed to set the system to not respond to ICMP on IPv4, not in compliance V-204613."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not accept ICMP redirects, V-204614
function V204614 () {
    local Regex1="^(\s*)#net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_redirects = 0\2/"
    local Regex3="^(\s*)net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.default.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.accept_redirects = 0\2/"
    local Regex5="^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*0?\s*$"
    local Success="Set system to not accept ICMP redirects on IPv4, per V-204614."
    local Failure="Failed to set the system to not accept ICMP redirects on IPv4, not in compliance V-204614."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not allow interfaces to perform ICMP redirects, V-204616
function V204616 () {
    local Regex1="^(\s*)#net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.send_redirects = 0\2/"
    local Regex3="^(\s*)net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.default.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.send_redirects = 0\2/"
    local Regex5="^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*0?\s*$"
    local Success="Set system to not peform ICMP redirects on IPv4 by default, per V-204616."
    local Failure="Failed to set the system to not peform ICMP redirects on IPv4 by default, not in compliance V-204616."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not allow sending ICMP redirects, V-204617
function V204617 () {
    local Regex1="^(\s*)#net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.send_redirects = 0\2/"
    local Regex3="^(\s*)net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.all.send_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.send_redirects = 0\2/"
    local Regex5="^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*0?\s*$"
    local Success="Set system to not send ICMP redirects on IPv4, per V-204617."
    local Failure="Failed to set the system to not send ICMP redirects on IPv4, not in compliance V-204617."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Prevent unrestricted mail relaying, V-204619
function V204619 () {
    local Regex1="^(\s*)smtpd_client_restrictions\s*=\s*permit_mynetworks,reject\s*$"
    local Success="Set postfix from being used as an unrestricted mail relay, per V-204619."
    local Failure="Failed to set postfix from being used as an unrestricted mail relay, not in compliance V-204619."

    echo
    postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'
    (postconf -n smtpd_client_restrictions | grep -E -q "$Regex1" && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not perform packet forwarding unless system is a router, V-204625
function V204625 () {
    local Regex1="^(\s*)#net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$/\net.ipv4.ip_forward = 0\2/"
    local Regex3="^(\s*)net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.ip_forward\s+\S+(\s*#.*)?\s*$/\net.ipv4.ip_forward = 0\2/"
    local Regex5="^(\s*)net.ipv4.ip_forward\s*=\s*0?\s*$"
    local Success="Set system to not perform package forwarding, per V-204625."
    local Failure="Failed to set the system to not perform package forwarding, not in compliance V-204625."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to not perform packet forwarding unless system is a router, V-204630
function V204630 () {
    local Regex1="^(\s*)#net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv6.conf.all.accept_source_route = 0\2/"
    local Regex3="^(\s*)net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv6.conf.all.accept_source_route\s+\S+(\s*#.*)?\s*$/\net.ipv6.conf.all.accept_source_route = 0\2/"
    local Regex5="^(\s*)net.ipv6.conf.all.accept_source_route\s*=\s*0?\s*$"
    local Success="Set system to not accept IPv6 source-routed packets, per V-204630."
    local Failure="Failed to set the system to not accept IPv6 source-routed packets, not in compliance V-204630."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Install pam_pkcs11, V-204631
function V204631 () {
    local Success="pam_pkcs11 is installed, per V-204631."
    local Failure="Failed to install pam_pkcs11, not in compliance with V-204631."

    echo
    if yum -q list installed pam_pkcs11 &>/dev/null
    then
        echo "$Success"
    else
        yum install -q -y pam_pkcs11
        ( (yum -q list installed pam_pkcs11 &>/dev/null ) && echo "$Success") || { echo "$Failure" ; exit 1; }
    fi
}

#Enable OCSP for PKI authentication, V-204633
function V204633 () {
    local Regex1="^(\s*)cert_policy\s*=\s*"
    local Regex2="s/^(\s*)cert_policy\s*=\s*"
    local Regex3="    cert_policy = ca, ocsp_on, signature\;"
    local Regex4="^(\s*)cert_policy\s*=\s*ca, ocsp_on, signature\;\s*$"
    local Success="OCSP is enabled on system, per V-204633."
    local Failure="Failed to enable OCSP on the system, not in compliance V-204633."

    echo
    (grep -E -q "$Regex1" /etc/pam_pkcs11/pam_pkcs11.conf && sed -ri "$Regex2.*$/$Regex3/g" /etc/pam_pkcs11/pam_pkcs11.conf)
    (grep -E -q "$Regex4" /etc/pam_pkcs11/pam_pkcs11.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to require pwquality when passwords are changed or created, V-204406
function V204406 () {
    local Regex1="^\s*password\s+required\s+pam_pwquality.so\s+"
    local Regex2="/^\s*password\s+required\s+pam_pwquality.so\s+/ { /^\s*password\s+required\s+pam_pwquality.so(\s+\S+)*(\s+retry=[0-9]+)(\s+.*)?$/! s/^(\s*password\s+required\s+pam_pwquality.so\s+)(.*)$/\1retry=3 \2/ }"
    local Regex3="^(\s*)password\s+required\s+\s*pam_pwquality.so\s*retry=3\s*$"
    local Success="Set system to require pwquality when passwords are changed or created, per V-204406."
    local Failure="Failed to set the system to require pwquality when passwords are changed or created, not in compliance V-204406."

    echo
    (grep -E -q "$Regex1" /etc/pam.d/system-auth && sed -ri  "$Regex2" /etc/pam.d/system-auth) || echo "password    required      pam_pwquality.so retry=3" >> /etc/pam.d/system-auth
    (grep -E -q "$Regex3" /etc/pam.d/system-auth && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/group", V-204565
function V204565 () {
    local Regex1="^\s*-w\s+/etc/group\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
    local Success="Set to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/group', per V-204565."
    local Failure="Failed to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/group', not in compliance V-204565."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/shadow", V-204566
function V204566 () {
    local Regex1="^\s*-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
    local Success="Set to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/shadow', per V-204566."
    local Failure="Failed to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/shadow', not in compliance V-204566."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set audit to audit all account creations, modifications, disabling, and termination events that affect "/etc/opasswd", V-204568
function V204568 () {
    local Regex1="^\s*-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+identity\s*(#.*)?$"
    local Success="Set to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/opasswd', per V-204568."
    local Failure="Failed to enable auditing of all account creations, modifications, disabling, and termination events the affect '/etc/opasswd', not in compliance V-204568."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to generate audit logs for all account creations, modifications, disabling, and termination events that affect /etc/shadow, per V-204567
function V204567 () {
    local Regex1="^-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity\s*$"
    local Success="Set system to generate audit logs for all account creations, modifications, disabling, and termination events that affect /etc/shadow, per V-204567."
    local Failure="Failed to set the system to generate audit logs for all account creations, modifications, disabling, and termination events that affect /etc/shadow, not in compliance with V-204567."

    echo
    grep -E -q "$Regex1" /etc/audit/audit.rules || echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
    (grep -E -q "$Regex1" /etc/audit/audit.rules && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to ignore ICMP redirects, V-204615
function V204615 () {
    local Regex1="^(\s*)#net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_redirects = 0\2/"
    local Regex3="^(\s*)net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.all.accept_redirects\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.accept_redirects = 0\2/"
    local Regex5="^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*0?\s*$"
    local Success="Set system to ignore IPv4 ICMP redirect messages, per V-204615."
    local Failure="Failed to set the system to ignore IPv4 ICMP redirect messages, not in compliance V-204615."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable DCCP kernel module, V-204450.
function V204450 () {
    local Regex1="^(\s*)#install dccp /bin/true\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#install dccp /bin/true\s+\S+(\s*#.*)?\s*$/\install dccp /bin/true\2/"
    local Regex3="^(\s*)#blacklist dccp\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)#blacklist dccp\s+\S+(\s*#.*)?\s*$/\blacklist dccp\2/"
    local Regex5="^(\s*)install\s*dccp\s*/bin/true?\s*$"
    local Regex6="^(\s*)blacklist\s*dccp?\s*$"
    local Success="Disabled DCCP on the system, per V-204450."
    local Failure="Failed to disable DCCP on the system, not in compliance V-204450."

    if [ ! -d "/etc/modprobe.d/" ]
    then
        mkdir -p /etc/modprobe.d/
    fi

    if [ -f "/etc/modprobe.d/dccp.conf" ]
    then
        (grep -E -q "$Regex1" /etc/modprobe.d/dccp.conf && sed -ri "$Regex2" /etc/modprobe.d/dccp.conf) || echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
    else
        echo -e "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
    fi

    if [ -f "/etc/modprobe.d/blacklist.conf" ]
    then
        (grep -E -q "$Regex3" /etc/modprobe.d/blacklist.conf && sed -ri "$Regex4" /etc/modprobe.d/blacklist.conf) || echo "blacklist dccp" >> /etc/modprobe.d/blacklist.conf
    else
        echo -e "blacklist dccp" >> /etc/modprobe.d/blacklist.conf
    fi

    echo
    (grep -E -q "$Regex5" /etc/modprobe.d/dccp.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
    echo
    (grep -E -q "$Regex6" /etc/modprobe.d/blacklist.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to require authentication upon booting into single-user and maintenance modes, V-204437
function V204437 () {
    local Regex1="^\s*ExecStart"
    local Regex2="s/(^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*).*$/\1-\/bin\/sh -c \"\/usr\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default\"/"
    local Regex3="^\s*ExecStart=-\/bin\/sh\s*-c\s*\"\/usr\/sbin\/sulogin;\s*\/usr\/bin\/systemctl\s*--fail\s*--no-block\s*default\""
    local Success="Set system to require authentication upon booting into single-user and maintenance modes, per V-204437."
    local Failure="Failed to set the system to require authentication upon booting into single-user and maintenance modes, not in compliance V-204437."

    echo
    (grep -E -q "$Regex1" /etc/pam.d/system-auth && sed -ri  "$Regex2" /etc/pam.d/system-auth) || echo "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" >> /etc/pam.d/system-auth
    (grep -E -q "$Regex3" /etc/pam.d/system-auth && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to use virtual address randomization, V-204584
function V204584 () {
    local Regex1="^(\s*)#kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$/\kernel.randomize_va_space = 2\2/"
    local Regex3="^(\s*)kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)kernel.randomize_va_space\s+\S+(\s*#.*)?\s*$/\kernel.randomize_va_space = 2\2/"
    local Regex5="^(\s*)kernel.randomize_va_space\s*=\s*2?\s*$"
    local Success="Set system to use virtual address space randomization, per V-204584."
    local Failure="Failed to set the system to use virtual address space randomization, not in compliance V-204584."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set system to utilize PAM when changing passwords, V-204405
function V204405 () {
    local Regex1="^\s*password\s+substack\s+system-auth\s*"
    local Success="Set system to utilize PAM when changing passwords, per V-204405."
    local Failure="Failed to set the system to utilize PAM when changing passwords, not in compliance with V-204405."

    echo
    grep -E -q "$Regex1" /etc/pam.d/passwd || echo "password   substack     system-auth" >> /etc/pam.d/passwd
    (grep -E -q "$Regex1" /etc/pam.d/passwd && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set the auditd service is active, V-204503
function V204503 () {
    local Success="Set the auditd service is active, per V-204503."
    local Failure="Failed to set the auditd service to active, not in compliance with V-204503."

    echo

    if systemctl is-active auditd.service | grep -F -q "active"
    then
        echo "$Success"
    else
        systemctl start auditd.service
        ( (systemctl is-active auditd.service | grep -F -q "active") && echo "$Success") || { echo "$Failure" ; exit 1; }
    fi
}

#Set audit to audit of successful/unsuccessful attempts to use create_module, V-204559
function V204559 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+create_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+create_module\s+-k\s+module-change\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use create_module on 32bit systems, per V-204559."
    local Success64="Auditing of the successful/unsuccessful access attempts to use create_module on 64bit systems, per V-204559."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use create_module on 32bit systems, not in compliance V-204559."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use create_module on 64bit systems, not in compliance V-204559."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S create_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S create_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64" || { echo "$Failure64" ; exit 1; } }
}

#Set audit to audit of successful/unsuccessful attempts to use finit_module, V-204561
function V204561 () {
    local Regex1="^\s*-a\s+always,exit\s+-F\s+arch=b32\s+-S\s+finit_module\s+-k\s+module-change\s*(#.*)?$"
    local Regex2="^\s*-a\s+always,exit\s+-F\s+arch=b64\s+-S\s+finit_module\s+-k\s+module-change\s*(#.*)?$"
    local Success32="Auditing of the successful/unsuccessful access attempts to use finit_module on 32bit systems, per V-204561."
    local Success64="Auditing of the successful/unsuccessful access attempts to use finit_module on 64bit systems, per V-204561."
    local Failure32="Failed to set the auditing of successful/unsuccessful attempts to use finit_module on 32bit systems, not in compliance V-204561."
    local Failure64="Failed to set the auditing of successful/unsuccessful attempts to use finit_module on 64bit systems, not in compliance V-204561."

    echo
    grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S finit_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (uname -p | grep -q 'x86_64' && grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules) || echo "-a always,exit -F arch=b64 -S finit_module -k module-change" >> /etc/audit/rules.d/audit.rules
    (grep -E -q "$Regex1" /etc/audit/rules.d/audit.rules && echo "$Success32") || { echo "$Failure32" ; exit 1; }
    echo
    uname -p | grep -q 'x86_64' && { (grep -E -q "$Regex2" /etc/audit/rules.d/audit.rules && echo "$Success64") || { echo "$Failure64" ; exit 1; } }
}

#Set OS to use a reverse-path filter, V-204610
function V204610 () {
    local Regex1="^(\s*)#net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.rp_filter = 1\2/"
    local Regex3="^(\s*)net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.all.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.all.rp_filter = 1\2/"
    local Regex5="^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*1?\s*$"
    local Success="Set system to use reverse-path filter on IPv4, per V-204610."
    local Failure="Failed to set the system to use reverse-path filter on IPv4, not in compliance V-204610."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Set OS to use a reverse-path filter, V-204611
function V204611 () {
    local Regex1="^(\s*)#net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.rp_filter = 1\2/"
    local Regex3="^(\s*)net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)net.ipv4.conf.default.rp_filter\s+\S+(\s*#.*)?\s*$/\net.ipv4.conf.default.rp_filter = 1\2/"
    local Regex5="^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*1?\s*$"
    local Success="Set system to use reverse-path filter on IPv4 by default, per V-204610."
    local Failure="Failed to set the system to use reverse-path filter on IPv4 by default, not in compliance V-204610."

    echo
    ( (grep -E -q "$Regex1" /etc/sysctl.conf && sed -ri "$Regex2" /etc/sysctl.conf) || (grep -E -q "$Regex3" /etc/sysctl.conf && sed -ri "$Regex4" /etc/sysctl.conf) ) || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
    (grep -E -q "$Regex5" /etc/sysctl.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Apply all CATIIs
function Medium () {
    echo
    echo "Applying all compatible CAT IIs"
    #V204402, disabled due to causing issues if GNOME is installed after
    V204405
    V204406
    V204407
    V204408
    V204409
    V204410
    V204411
    V204412
    V204413
    V204414
    V204415
    V204416
    V204417
    V204418
    #V204420, causes issues with EC2 IB
    V204422
    V204423
    V204426
    V204427
    V204431
    V204435
    #V204437, causes system to get into a state that ec2-user can not use sudo
    V204449
    V204450
    V204451
    V204457
    V204466
    V204503
    V204516
    V204517
    V204518
    V204519
    V204520
    V204521
    V204522
    V204523
    V204524
    V204525
    V204526
    V204527
    V204528
    V204529
    V204530
    V204531
    V204532
    V204533
    V204534
    V204535
    V204536
    V204537
    V204538
    V204539
    V204540
    V204541
    V204542
    V204543
    V204544
    V204545
    V204546
    V204547
    V204548
    V204549
    V204550
    V204551
    V204552
    V204553
    V204554
    V204555
    V204556
    V204557
    V204558
    V204559
    V204560
    V204561
    V204562
    V204563
    V204564
    V204565
    V204566
    V204567
    V204568
    V204569
    V204570
    V204571
    V204572
    V204573
    V204578
    V204579
    V204584
    V204587
    V204589
    V204590
    V204591
    V204592
    V204593
    V204595
    V204598
    V204599
    V204600
    V204602
    V204609
    V204610
    V204611
    V204612
    V204613
    V204614
    V204615
    V204616
    V204617
    V204619
    V204625
    V204630
    V204631
    V204633
}

#------------------
#CAT I STIGS\High
#------------------

#Set SSH to not allow authentication using empty passwords, V-204425.
function V204425 () {
    local Regex1="^(\s*)#PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\PermitEmptyPasswords no\2/"
    local Regex3="^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)PermitEmptyPasswords\s+\S+(\s*#.*)?\s*$/\PermitEmptyPasswords no\2/"
    local Regex5="^(\s*)PermitEmptyPasswords\s*no\s*$"
    local Success="Set SSH to not allow authentication using empty passwords, per V-204425."
    local Failure="Failed to set SSH to not allow authentication using empty passwords, not in compliance with V-204425."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) )|| echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Remove rsh-server if installed, V-204442
function V204442 () {
    local Success="rsh-server has been removed, per V-204442."
    local Failure="Failed to remove rsh-server, not in compliance with V-204442."

    echo

    if yum -q list installed rsh-server &>/dev/null
    then
        yum remove -q -y rsh-server
        { (yum -q list installed rsh-server &>/dev/null ) && { echo "$Failure" ; exit 1; } } || echo "$Success"
    else
        echo "$Success"
    fi
}

#Remove ypserv if installed, V-204443
function V204443 () {
    local Success="ypserv has been removed, per V-204443."
    local Failure="Failed to remove ypserv, not in compliance with V-204443."

    echo

    if yum -q list installed ypserv &>/dev/null
    then
        yum remove -q -y ypserv
        { (yum -q list installed ypserv &>/dev/null ) && { echo "$Failure" ; exit 1; } } || echo "$Success"
    else
        echo "$Success"
    fi
}

#Verify that gpgcheck is Globally Activated, V-204447
function V204447 () {
    local Regex1="^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/gpgcheck=1\2/"
    local Regex3="^(\s*)gpgcheck\s*=\s*1\s*$"
    local Success="Yum is now set to require certificates for installations, per V-204447"
    local Failure="Yum was not properly set to use certificates for installations, not in compliance with V-204447"

    echo
    (grep -E -q "$Regex1" /etc/yum.conf && sed -ri "$Regex2" /etc/yum.conf) || echo "gpgcheck=1" >> /etc/yum.conf
    (grep -E -q "$Regex3" /etc/yum.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Verify that local gpgcheck is Globally Activated, V-204448
function V204448 () {
    local Regex1="^(\s*)localpkg_gpgcheck\s*=\s*\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)localpkg_gpgcheck\s*=\s*\S+(\s*#.*)?\s*$/localpkg_gpgcheck=1\2/"
    local Regex3="^(\s*)localpkg_gpgcheck\s*=\s*1\s*$"
    local Success="Yum is now set to require certificates for local installs, per V-204448"
    local Failure="Yum was not properly set to use certificates for local installs, not in compliance with V-204448"

    echo
    (grep -E -q "$Regex1" /etc/yum.conf && sed -ri "$Regex2" /etc/yum.conf) || echo "localpkg_gpgcheck=1" >> /etc/yum.conf
    (grep -E -q "$Regex3" /etc/yum.conf && echo "$Success") || { echo "$Failure" ; exit 1; }
}

#Disable and mask  Ctrl-Alt-Delete, V-204455
function V204455 () {
    local Success="Ctrl-Alt-Delete is disabled, per V-204455"
    local Failure="Ctrl-Alt-Delete hasn't been disabled, not in compliance with per V-204455"

    echo
    systemctl mask ctrl-alt-del.target > /dev/null
    ( (systemctl status ctrl-alt-del.target | grep -q "Loaded: masked" && systemctl status ctrl-alt-del.target | grep -q "Active: inactive") && echo "$Success")  || { echo "$Failure" ; exit 1; }
}

#Remove telnet-server if installed, V-204502
function V204502 () {
    local Success="telnet-server has been removed, per V-204502."
    local Failure="Failed to remove telnet-server, not in compliance with V-204502."

    echo

    if yum -q list installed telnet-server &>/dev/null
    then
        yum remove -q -y telnet-server
        { (yum -q list installed telnet-server &>/dev/null ) && { echo "$Failure" ; exit 1; } } || echo "$Success"
    else
        echo "$Success"
    fi
}

#Remove vsftpd if installed, V-204620
function V204620 () {
    local Success="vsftpd has been removed, per V-204620."
    local Failure="Failed to remove vsftpd, not in compliance with V-204620."

    echo

    if yum -q list installed vsftpd &>/dev/null
    then
        yum remove -q -y vsftpd
        { (yum -q list installed vsftpd &>/dev/null ) && { echo "$Failure" ; exit 1; } } || echo "$Success"
    else
        echo "$Success"
    fi
}

#Remove tftp-server if installed, V-204621
function V204621 () {
    local Success="tftp-server has been removed, per V-204621."
    local Failure="Failed to remove tftp-server, not in compliance with V-204621."

    echo

    if yum -q list installed tftp-server &>/dev/null
    then
        yum remove -q -y tftp-server
        { (yum -q list installed tftp-server &>/dev/null ) && { echo "$Failure" ; exit 1; } } || echo "$Success"
    else
        echo "$Success"
    fi
}

#Set SSH X11 forwarding ensabled, V-204622
function V204622 () {
    local Regex1="^(\s*)#X11Forwarding\s+\S+(\s*#.*)?\s*$"
    local Regex2="s/^(\s*)#X11Forwarding\s+\S+(\s*#.*)?\s*$/\X11Forwarding yes\2/"
    local Regex3="^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$"
    local Regex4="s/^(\s*)X11Forwarding\s+\S+(\s*#.*)?\s*$/\X11Forwarding yes\2/"
    local Regex5="^(\s*)X11Forwarding\s*yes\s*$"
    local Success="Set SSH X11 forwarding ensabled, per V-204622."
    local Failure="Failed to set SSH X11 forwarding ensabled, not in compliance with V-204622."

    echo
    ( (grep -E -q "$Regex1" /etc/ssh/sshd_config && sed -ri "$Regex2" /etc/ssh/sshd_config) || (grep -E -q "$Regex3" /etc/ssh/sshd_config && sed -ri "$Regex4" /etc/ssh/sshd_config) )|| echo "X11Forwarding yes" >> /etc/ssh/sshd_config
    (grep -E -q "$Regex5" /etc/ssh/sshd_config && echo "$Success") || { echo "$Failure" ; exit 1; }
    systemctl restart sshd
}

function High () {
    echo
    echo "Applying all compatible CAT Is"
    V204425
    V204442
    V204443
    V204447
    V204448
    V204455
    V204502
    V204620
    V204621
    V204622
}

#------------------
#Clean up
#------------------

function Cleanup () {
    echo
    (rm -rf "$StagingPath" && echo "Staging directory has been cleaned.") || echo "Failed to clean up the staging directory."
}

#Set default backup location that can be modified via argument.
BackupDIR="/etc/stigbackup"

#Setting variable for default input
Level=${1:-"High"}
StagingPath=${2:-"/var/tmp/STIG"}

Backup

#Setting script to run through all stigs if no input is detected.
if [ "$Level" =  "High" ]
then
    High
    Medium
    Low
elif [ "$Level" = "Medium" ]
then
    Medium
    Low
elif [ "$Level" = "Low" ]
then
    Low
else
    for Level in "$@"
    do
    "$Level"
    done
fi

Cleanup
echo
service auditd restart
echo
sysctl --system > /dev/null
exit 0