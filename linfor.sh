#!/bin/bash

# Redirecting output to IRLinux.txt in /tmp/ directory
exec > /tmp/Forensics4Linux.txt 2>&1

echo "Incident Response Linux Investigation"
echo "--------------------------------------"
echo "Date and Time of Report: $(date)"
echo "--------------------------------------"

# Function to print section headers
print_section() {
    echo ""
    echo "======================================"
    echo "$1"
    echo "======================================"
}

# User Accounts
print_section "User Accounts Information"
echo "Listing user accounts..."
cat /etc/passwd
echo "Checking password status for a user (Placeholder)..."
passwd -S [User_Name]
echo "Showing the most recent logins..."
lastlog
echo "Showing last logged in users..."
last
echo "Showing who is logged on..."
who
echo "Showing who is logged on and what they are doing..."
w

# Additional User Account Commands
print_section "Additional User Account Commands"
echo "Finding root accounts..."
grep :0: /etc/passwd
echo "Finding files with no user..."
find / -nouser -print
echo "Viewing encrypted passwords and account expiration information..."
cat /etc/shadow
echo "Viewing group information..."
cat /etc/group
echo "Viewing sudoers file..."
cat /etc/sudoers

# Log Entries
print_section "Log Entries"
echo "Showing system messages..."
cat /var/log/messages
echo "Showing user authentication logs..."
cat /var/log/auth.log
echo "Showing authentication log for Red Hat based systems..."
cat /var/log/secure
echo "Showing system boot log..."
cat /var/log/boot.log
echo "Showing kernel ring buffer log..."
cat /var/log/dmesg
echo "Showing kernel log..."
cat /var/log/kern.log
echo "Viewing the last few entries in the authentication log..."
tail /var/log/auth.log
echo "Viewing command history..."
history | less

# System Resources
print_section "System Resources"
echo "Displaying Linux tasks..."
top -b -n 1
echo "Interactive process viewer..."
htop -n 1
echo "Showing system uptime..."
uptime
echo "Showing currently running processes..."
ps aux
echo "Showing running processes as a tree..."
pstree
echo "Displaying memory usage..."
free -m
echo "Displaying memory information..."
cat /proc/meminfo
echo "Displaying mounted filesystems..."
cat /proc/mounts

# Processes
print_section "Processes"
echo "Displaying all the currently running processes on the system..."
ps -ef
echo "Displaying processes in a tree format with PIDs..."
pstree -p
echo "Displaying top processes..."
top -b -n 1
echo "Showing processes in custom format..."
ps -eo pid,tt,user,fname,rsz
echo "Listing open files associated with network connections..."
lsof -i
echo "Listing open files for a process (Placeholder)..."
lsof -p [pid]

# Services
print_section "Services"
echo "Listing all services and their current states..."
chkconfig --list
echo "Showing status of all services..."
service --status-all
echo "Listing running services (systemd)..."
systemctl list-units --type=service
echo "Listing all services and their status..."
service --status-all

# Files
print_section "Files"
echo "Showing all files in human-readable format..."
ls -alh
echo "Finding a specific file (Placeholder)..."
find / -name [filename]
echo "Finding files modified in the last N days (Placeholder)..."
find / -mtime -[N]
echo "Finding files accessed in the last N days (Placeholder)..."
find / -atime -[N]
echo "Finding files larger than N bytes (Placeholder)..."
find / -size +[N]c

# Network Settings
print_section "Network Settings"
echo "Showing all network interfaces..."
ifconfig -a
echo "Showing active network connections..."
netstat -antup
echo "Showing all iptables rules..."
iptables -L -n -v
echo "Showing routing table..."
route -n
echo "Showing listening ports and established connections..."
ss -tuln

# Additional Commands
print_section "Additional Investigation Commands"
echo "Viewing the cron table for scheduled tasks..."
cat /etc/crontab
echo "Viewing DNS settings..."
more /etc/resolv.conf
echo "Viewing host file entries..."
more /etc/hosts
echo "Listing all iptables rules without resolving IP addresses..."
iptables -L -n
echo "Finding files larger than 512KB in home directories..."
find /home/ -type f -size +512k -exec ls -lh {} \;
echo "Finding readable files in the etc directory..."
find /etc/ -readable -type f 2>/dev/null
echo "Finding files modified in the last 2 days..."
find / -mtime -2 -ls
echo "Showing network connections and associated programs..."
netstat -nap
echo "Viewing the ARP table..."
arp -a
echo "Displaying the PATH environment variable..."
echo $PATH

echo "--------------------------------------"
echo "Script execution completed."





#########################################################################################3
#!/bin/#!/usr/bin/env bash

# Last user login
$ lastlog
$ last

# Users with login shells
$ cat /etc/passwd | grep sh$

# List users’ cron
$ for user in $(cat /etc/passwd | cut -f1 -d: ); do echo $user; crontab -u $user -l; done

# users with shells only
$ for user in $(cat /etc/passwd | grep sh$ | cut -f1 -d: ); do echo $user; crontab -u $user -l; done

# SSH authorized keys
$ find / -type f -name authorized_keys

# Show process tree with username, TTY, and wide output.
$ ps auxfww

# Process details
$ lsof -p [pid]

# Show all connections don’t resolve names (IP only)
$ lsof -i -n
$ netstat -anp

# Look for tcp only
$ netstat -antp
$ ss -antp

# List all services
$ service --status-all

# List firewall rules
$ iptables --list-rules

# List all timers
$ systemctl list-timers --all

# Look to these file to see if the DNS has been poisoned.
/etc/hosts
/etc/resolv.conf

# Files and Folders
Show list files and folder with nano timestamp, sort by modification time (newest).
$ ls --full-time -lt

# List all files that were modified on a specific date/time. List files which were modified on 2021-06-16 (YYYY-MM-DD)
$ find / -newermt "2021-06-16" -ls 2>/dev/null

# List files which were modified on 2021-05-01 until 2021-05-09 (9 days ago)
$ find / -newermt "2021-05-01" ! -newermt "2021-05-10" -ls 2>/dev/null

# List files which were modified on 2021-05-01 until 2021-05-09 (9 days ago) + add filter
$ find / -newermt "2021-05-01" ! -newermt "2021-05-10" -ls 2>/dev/null | grep -v 'filterone\|filtertwo'

# List files modified between 01:00 and 07:00 on June 16 2021.
$ find / -newermt "2021-06-16 01:00:00" ! -newermt "2021-06-16 07:00:00" -ls 2>/dev/null

# List files that were accessed exactly 2 days ago.
$ find / -atime 2 -ls 2>/dev/null

# List files that were modified in the last 2 days.
$ find / -mtime -2 -ls 2>/dev/null

# File inspection
$ stat [file]
$ exiftool [file]

# Observe changes in files
$ find . -type f -exec md5sum {} \; | awk '{print $1}' | sort | uniq -c | grep ' 1 ' | awk '{print $2	}'

# Look for cap_setuid+ep in binary capabilities
$ getcap -r /usr/bin/
$ getcap -r /bin/
$ getcap -r / 2>/dev/null

# SUID
$ find / -type f -perm -u=s 2>/dev/null

# Log auditing
# 3rd party
$ aureport --tty

#Persistence areas Directories and Files
/etc/cron*/
/etc/incron.d/*
/etc/init.d/*
/etc/rc*.d/*
/etc/systemd/system/*
/etc/update.d/*
/var/spool/cron/*
/var/spool/incron/*
/var/run/motd.d/*
#Files:
/etc/passwd
/etc/sudoers
/home/<user>/.ssh/authorized_keys
/home/<user>/.bashrc
#
# https://sechive1.wixsite.com/security-hive/post/linux-forensics-the-complete-cheatsheet
# PHASE 0 Risk Audit
#Password hunting
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
#search for possible Privilege Escalation Paths
wget "https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh" -O linpeas.sh
./linpeas.sh -a #all checks - deeper system enumeration, but it takes longer to complete.
./linpeas.sh -s #superfast & stealth - This will bypass some time consuming checks. In stealth mode Nothing will be written to the disk.
./linpeas.sh -P #Password - Pass a password that will be used with sudo -l and bruteforcing other users
# This shell script will show relevant information about the security of the local Linux system, helping to escalate privileges.
wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh
./lse.sh -l1 # shows interesting information that should help you to privesc
./lse.sh -l2 # dump all the information it gathers about the system
#
PHASE 1 Users and Groups
user List
cat /etc/passwd
# user creation
passwd -S [USER_NAME]
# UID users
grep :0: /etc/passwd
# temp users
find / -nouser -print
# Groups
cat /etc/group
cat /etc/sudoers

#PHASE 2 system Config
# network
cat /etc/network/interfaces
cat /etc/resolve.conf
cat /etc/dnsmasq.conf
# OS
cat /etc/os-release
# hostnAME
cat /etc/hostname
# TIMEZONE
cat /etc/timezone

# Phase 3 uSERS aCTIVITIES
# RECENT ACCESS
find . -type f -atime -7 -printf “%AY%Am%Ad%AH%AM%AS %h/%s/%f\n” -user |sort -n
find . -type f -mtime -7 -printf “%TY%Tm%Td%TH%TM%TS %h — %s — %f\n” -user |sort -n
find . -type f -ctime -7 -printf “%CY%Cm%Cd%CH%CM%CS %h — %s — %f\n” -user |sort -n
# basH HISTORY
cat .bash_history
cat .bashrc
# mOUNT pOINTS
cat /proc/mounts

# PHASE 4 Log Analysis
# Log entries
lastlog
# Auth.Log
cat /var/log/auth.log
# Deamon.log
cat var/log/deamon.log
# SysLog
cat var/log/syslog
# WTMP
cat /var/log/btmp
# Appication Logs ????
 Some of those logs to name are apache2, httpd, samba, MySQL etc.

#PHASE 5 Persistance
# Services
services –status-all
# Processes
top
ps aux
lsof -p [pid]
# Scheduled Jobs
cat /etc/crontab
# DNS Resolves
cat /etc/resolve.conf
# Firewall Rules
cat /etc/resolve.conf
# Network Connections
netstat -nap

# IMAGE TOOLS
fmem

# Memoery
Lime (http://code.google.com/p/lime-forensics/)
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"

# format txt file
cd /tmp
sed li1 /! " Forensics4Linux Output _____________________ " > Forensics4Linux.txt
