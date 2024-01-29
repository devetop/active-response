#!/bin/bash
# Adds an IP to the iptables drop list (if linux)
# Adds an IP to the ipfilter drop list (if solaris, freebsd or netbsd)
# Adds an IP to the ipsec drop list (if aix)
# Requirements: Linux with iptables, Solaris/FreeBSD/NetBSD with ipfilter or AIX with IPSec
# Expect: srcip
# Author: Ahmet Ozturk (ipfilter and IPSec)
# Author: Daniel B. Cid (iptables)
# Author: cgzones
# Last modified: Oct 04, 2012

UNAME=`uname`
ECHO="/bin/echo"
GREP="/bin/grep"
IPTABLES=""
IP4TABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
IPFILTER="/sbin/ipf"
if [ "X$UNAME" = "XSunOS" ]; then
    IPFILTER="/usr/sbin/ipf"
fi
GENFILT="/usr/sbin/genfilt"
LSFILT="/usr/sbin/lsfilt"
MKFILT="/usr/sbin/mkfilt"
RMFILT="/usr/sbin/rmfilt"
ACTION=$1
USER=$2
IP=$3
DT=$4
RULE_ID=$5
PWD=`pwd`
LOCK="${PWD}/fw-drop"
LOCK_PID="${PWD}/fw-drop/pid"
IPV4F="/proc/sys/net/ipv4/ip_forward"
IPV6F="/proc/sys/net/ipv6/conf/all/forwarding"

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
filename=$(basename "$0")

LOG_FILE="${PWD}/../logs/active-responses.log"
CHECK_PORT=`lsof -n -P -iTCP |grep ssh|grep LISTEN|head -n1|awk '{split($0,a,":"); split(a[2],b); print b[1]}'`
SSH_PORT=${CHECK_PORT:-22}

echo "`date` $0 $1 $2 $3 $4 $5" >> ${LOG_FILE}


# Checking for an IP
if [ "x${IP}" = "x" ]; then
   echo "$0: <action> <username> <ip>"
   exit 1;
fi

case "${IP}" in
    *:* ) IPTABLES=$IP6TABLES;;
    *.* ) IPTABLES=$IP4TABLES;;
    * ) echo "`date` Unable to run active response (invalid IP: '${IP}')." >> ${LOG_FILE} && exit 1;;
esac

# This number should be more than enough (even if a hundred
# instances of this script is ran together). If you have
# a really loaded env, you can increase it to 75 or 100.
MAX_ITERATION="50"

# Lock function
lock()
{
    i=0;
    # Providing a lock.
    while [ 1 ]; do
        mkdir ${LOCK} > /dev/null 2>&1
        MSL=$?
        if [ "${MSL}" = "0" ]; then
            # Lock acquired (setting the pid)
            echo "$$" > ${LOCK_PID}
            return;
        fi

        # Getting currently/saved PID locking the file
        C_PID=`cat ${LOCK_PID} 2>/dev/null`
        if [ "x" = "x${S_PID}" ]; then
            S_PID=${C_PID}
        fi

        # Breaking out of the loop after X attempts
        if [ "x${C_PID}" = "x${S_PID}" ]; then
            i=`expr $i + 1`;
        fi

        sleep $i;

        i=`expr $i + 1`;

        # So i increments 2 by 2 if the pid does not change.
        # If the pid keeps changing, we will increments one
        # by one and fail after MAX_ITERACTION

        if [ "$i" = "${MAX_ITERATION}" ]; then
            kill="false"
            for pid in `pgrep -f "${filename}"`; do
                if [ "x${pid}" = "x${C_PID}" ]; then
                    # Unlocking and exiting
                    kill -9 ${C_PID}
                    echo "`date` Killed process ${C_PID} holding lock." >> ${LOG_FILE}
                    kill="true"
                    unlock;
                    i=0;
                    S_PID="";
                    break;
                fi
            done

            if [ "x${kill}" = "xfalse" ]; then
                echo "`date` Unable kill process ${C_PID} holding lock." >> ${LOG_FILE}
                # Unlocking and exiting
                unlock;
                exit 1;
            fi
        fi
    done
}

# Unlock function
unlock()
{
   rm -rf ${LOCK}
}



# Blocking IP
if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
   echo "$0: invalid action: ${ACTION}"
   exit 1;
fi



# We should run on linux
config="/etc/sysconfig/imunify360/imunify360-merged.config"
value="true"
config_value=$( cat "${config}" | grep active_response | grep true )

ipset_active_ban() {
        $(iptables -C INPUT_imunify360 -m set --match-set ossec.ipv4.blacklist_SSH src -p tcp --dport $SSH_PORT -j DROP)
        if [ $? -eq 0 ]
        then
          $(ipset test ossec.ipv4.blacklist_SSH $IP -exist > /dev/null 2>&1)
          [ $? -ne 0 ] && ipset add ossec.ipv4.blacklist_SSH ${IP}
        else
          ipset create ossec.ipv4.blacklist_SSH hash:net timeout 600 maxelem 100000 -exist
          iptables -A INPUT_imunify360 -m set --match-set ossec.ipv4.blacklist_SSH src -p tcp --dport ${SSH_PORT} -j DROP
          ipset add ossec.ipv4.blacklist_SSH ${IP} -exist
        fi
}

if [ "X${UNAME}" = "XLinux" ] && [[ " $config_value " =~ $value ]]; then
   if [ "x${ACTION}" = "xadd" ]; then
      ipset_active_ban
   elif [ "x${ACTION}" = "xdelete" ]; then
      ipset del ossec.ipv4.blacklist_SSH ${IP} -exist
   else
      :
   fi

  exit 0;

else
   pam_ssh_state=$( cat "${config}" | grep -A2 PAM | grep enable | grep false )
   
   if [ "x${ACTION}" = "xadd" ] && [[ "$pam_ssh_state" =~ "false" ]]; then
     # note, that RULE_ID become 200000+RULE_ID because we increasing severity
     echo '{"severity": 7, "name": "Preventing SSH brute force attempt.", "timestamp": '$DT', "attackers_ip": "'$IP'", "plugin_id": "ossec", "method": "INCIDENT", "message": "[Active Response] is disabled for rule '$RULE_ID'. Greylisting '$IP'", "rule": '$(($RULE_ID+200000))' }' | nc -w1 -U /var/run/defence360agent/generic_sensor.sock.2
     echo "$(date '+%b %d %T') [INFO] AR is disabled, sent alert for ssh brute force greylisting: $IP" >>${LOG_FILE}
   else
     echo "$(date '+%b %d %T') [INFO] AR is disabled, bypass processing $IP" >>${LOG_FILE}
     exit 0;
   fi
fi
