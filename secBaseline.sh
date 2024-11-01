#!/bin/bash

#################################
#Author: TarikLau
#Version: V1.0
#################################

#Delete useless special accounts
del_sepc_useless_account(){
　　#backup file
　　cp /etc/passwd /etc/passwd.bak-$(date +"%F")
　　echo "The users are as follows: "
　　awk -F : '!/^#/{print $1}' /etc/passwd
　　read -p "make sure which user you want to delete: " user1
　　if [ -z $user1 ] ; then
　　　　echo "Please enter the right user!" && exit 1
　　else
　　　　sed -i "s/^$user1/#$user1/g" /etc/passwd && echo $(grep "$user1" /etc/passwd)
　　fi
}

#Set password policy
set_pass_policy(){
　　#backup file
　　cp /etc/login.defs /etc/login.defs.bak-$(date +"%F")
　　
　　#Change params value
　　sed -i 's/^PASS_MAX_DAYS[[:space:]]*[0-9]*$/PASS_MAX_DAYS   90/g' /etc/login.defs && echo $(grep "^PASS_MAX_DAYS" /etc/login.defs)

　　sed -i 's/^PASS_MIN_DAYS[[:space:]]*[0-9]*$/PASS_MIN_DAYS   90/g' /etc/login.defs && echo $(grep "^PASS_MIN_DAYS" /etc/login.defs)
　　
　　sed -i 's/^PASS_MIN_LEN[[:space:]]*[0-9]*$/PASS_MIN_LEN   90/g' /etc/login.defs && echo $(grep "^PASS_MIN_LEN" /etc/login.defs)

　　sed -i 's/^PASS_WARN_AGE[[:space:]]*[0-9]*$/PASS_WARN_AGE   90/g' /etc/login.defs && echo $(grep "^PASS_WARN_AGE" /etc/login.defs)
}

#Delete accounts with empty passwords and weak passwords
del_weak_pass(){
　　#backup file
　　cp /etc/shadow /etc/shadow.bak-$(date +"%F")
　　#delete weak pass user
　　del_users=$(awk -F: '($3 == ""){print $1}' /etc/shadow)
　　for deluser in $del_users ; do
　　　　if [ $deluser = 'root' ]; then
　　　　　　continue
　　　　else
　　　　　　echo "The following user should be deleted: "
　　　　　　awk -F: '($3 == ""){print $1}' /etc/shadow
　　　　　　read -p "Do you really want to delete $deluser(Y/N)? " answer
　　　　　　case $answer in
　　　　　　　　y|Y)
　　　　　　　　　　userdel -rf $del_user && echo "${del_user} has been deleted"
　　　　　　　　　　;;
　　　　　　　　*)
　　　　　　　　　　echo "The $del_user is reversed"
　　　　　　　　　　;;
　　　　　　esac
　　　　fi
　　done
　　#chmod 700 /etc/shadow
　　#chage_users=$(awk -F : '!/^#/{print $1}'  /etc/shadow)
　　#for chageuser in $chage_user ; do
　　#　　chage -m 1 -M 180 $chageuser && echo "$chageuser it's shadow file has been changed"
　　#done
　　chmod 400 /etc/shadow
}

#Detect automatic login scripts
del_auto_login_scripts(){
　　echo "finding *.netrc files ..."
　　if [ ! $(find / -iname *.netrc) ]; then
　　　　echo "No .netrc file could be found"
　　else
　　　　find / -iname *.netrc
　　　　read -p "Do you want to delete .netrc files?: (Y/N) " ans
　　　　case $ans in
　　　　　　y|Y|yes|YES)
　　　　　　　　find / -iname *.netrc | xargs rm -f
　　　　　　　　;;
　　　　　　*)
　　　　　　　　echo "file is reversed"
　　　　　　　　;;
　　　　esac
　　fi

　　echo "finding *.rhosts files ..."
　　if [ ! $(find / -iname *.rhosts) ]; then
　　　　echo "No .rhosts file could be found"
　　else
　　　　find / -iname *.rhosts
　　　　read -p "Do you want to delete .rhosts files?: (Y/N) " ans2
　　　　case $ans2 in
　　　　　　y|Y|yes|YES)
　　　　　　　　find / -iname *.rhosts | xargs rm -f
　　　　　　　　;;
　　　　　　*)
　　　　　　　　echo "file is reversed"
　　　　　　　　;;
　　　　esac
　　fi
}　　

#set screen saver
set_scree_protect(){
　　#backup file
　　cp /etc/profile  /etc/profile.bak-$(date +"%F")
　　
　　if [ ! TIMEOUT ]; then
　　　　echo "export TIMEOUT=600" >> /etc/profile && source /etc/profile
　　else
　　　　TIMEOUT=""
　　　　sed -i 's/export[[:space:]]*TIMEOUT=[0-9]*$//g' /etc/profile && source /etc/profile
　　　　echo "export   TIMEOUT=600" >> /etc/profile && source /etc/profile
　　fi
　　env | grep TIMEOUT
}

#Security of root user environment variables[**Unclear demand**]
chk_root_env(){
　　echo $PATH | egrep '(^|:)(\.|:|$)'
　　find `echo $PATH | tr ':' ' '`  -type d \( -perm -002 -o -perm 020 \) -ls
}

#rsyslog log event logging
set_syslog_event(){
　　#backup file
　　cp /etc/rsyslog.conf /etc/rsyslog.conf.bak-$(date +"%F")
　　if [[ -z $(grep "^authpriv.*" /etc/rsyslog.conf) ]]; then
　　　　echo "authpriv.*    /var/log/secure" >> /etc/rsyslog.conf && echo "authpriv.* set successfully"
　　else
　　　　echo "The authpriv.*  already sets in  /etc/rsyslog.conf"
　　fi
}
#System core dump status
set_coredump_status(){
　　#backup file
　　cp /etc/security/limits.conf  /etc/security/limits.conf.bak-$(date +"%F")
　　
　　if [[ -z $(grep ^\*[[:space:]]*soft[[:space:]]*core[[:space:]]*[0-9]*$ /etc/security/limits.conf) ]]; then
　　　　echo "*   soft   core   0" >> /etc/security/limits.conf && echo "* soft core 0 sets successfully"
　　else
　　　　echo "*  soft  core 0 has already set in /etc/security/limits.conf"
　　fi

　　if [[ -z $(grep ^\*[[:space:]]*hard[[:space:]]*core[[:space:]]*[0-9]*$ /etc/security/limits.conf) ]]; then
　　　　echo "*   hard   core   0" >> /etc/security/limits.conf && echo "* hard core 0 sets successfully"
　　else
　　　　echo "*  hard  core 0 has already set in /etc/security/limits.conf"
　　fi
}

#passwd,shadow,group file's privilege
set_passfile_rights(){
　　chown root:root /etc/passwd /etc/shadow /etc/group && chmod 644 /etc/passwd /etc/shadow && chmo 400 /etc/shadow
　　if [ $? -eq 0 ]; then
　　　　echo "passwd,shadow,group file's rights has been changed"
　　else
　　　　echo "please check the right fo passwd,shadow,group"
　　fi
}

#Find unauthorized SUID/SGID files
set_unauth_SXID(){
　　result=$(find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm /6000 2> /dev/null)
　　if [[ -z $result ]]; then
　　　　echo "No file need to change privilege"
　　else
　　　　for specfile in $result; do
　　　　　　chmod 755 $specfile && chmod a-s $specfile
　　　　　　echo "$specfile has SUID/SGID privilege and it's privilege has been changed"
　　　　done
　　fi
}

#Check history command settings
set_histfile_size(){
　　if [ ! $HISTFILESIZE ]; then
　　　　echo "HISTFILESIZE=0" >> /etc/profile && source /etc/profile
　　else
　　　　HISTFILESIZE=""
　　　　sed -i 's/^HISTFILESIZE=[0-9]*$//g' /etc/profile && source /etc/profile
　　　　echo "HISTFILESIZE=0" >> /etc/profile && source /etc/profile
　　fi
　　env | grep HISTFILESIZE
}

echo "This scripts for fixing the Linux OS Security Baseline"
read -p "please select one of [31,1234,5,28,8,7,35,12,1134,47,18]; your operation is: " ops
case $ops in
　　"31")
　　　　echo "This operation for delete useless special account"
　　　　del_spec_useless_account
　　　　;;
　　"1234")
　　　　echo "This operation for set password policy"
　　　　set_pass_policy
　　　　;;
　　"5")
　　　　echo "This operation for delete weak password"
　　　　del_weak_pass
　　　　;;
　　"28")
　　　　echo "This operation for auto login scripts"
　　　　del_auto_login_scripts
　　　　;;
　　"8")
　　　　echo "This operation for set screen protect"
　　　　set_screen_protect
　　　　;;
　　"7")
　　　　echo "This operation for check root env"
　　　　chk_root_env
　　　　;;
　　"35")
　　　　echo "This operation for set rsyslog event"
　　　　set_syslog_event
　　　　;;
　　"12")
　　　　echo "This operation for set core dump status"
　　　　set_coredump_status
　　　　;;
　　"1134")
　　　　echo "This operation for set passfile rights"
　　　　set_passfile_rights
　　　　;;
　　"47")
　　　　echo "This operation for unauth SUID/SGID file"
　　　　set_unauth_SXID
　　　　;;
　　"18")
　　　　echo "This operation for check HISTFILESIZE"
　　　　set_histfile_size
　　　　;;
　　"QUIT"|"quit")
　　　　exit
　　　　;;
　　*)
　　　　echo "Invalid Operation!!!" && exit 1
　　　　;;
esac
