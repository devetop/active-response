#!/bin/sh
# Atomic Secured Linux 
# Copyright Atomicorp, 2007-2014
# License: Commercial, unauthorized redistribution or duplication is prohibited
# ASL database configuration script

source /etc/asl/config
DEBUG=0
LOG=/dev/null

if [ "$HIDS_SHUN_TRACKING" != "yes" ]; then
        exit;
fi

if  [ $DEBUG -ge 1 ]; then
        LOG=/var/ossec/logs/ar-tracking-debug.log
        echo "`date` $0 $1 $2 $3 $4 $5" >> $LOG
 
fi

MYSQL="/usr/bin/mysql -h $OSSEC_DATABASE_SERVER -u $OSSEC_DATABASE_USERNAME -p$OSSEC_DATABASE_PASSWORD $OSSEC_DATABASE"

ACTION=$1
IP=$3
ALERT=$4
RULE=$5

if [ "x${IP}" = "x" ]; then
        exit 1
fi

if [ "x${ACTION}" != "xadd" -a "x${ACTION}" != "xdelete" ]; then
        exit 1
fi

if [ "x${ACTION}" = "xadd" ]; then
        $MYSQL -e "INSERT INTO aslw_blocklist (rule_id, src_ip, alertid, is_blocked) VALUES ('$RULE',inet_aton('$IP'),'$ALERT','1');" >> $LOG 2>&1
else
        $MYSQL -e "UPDATE aslw_blocklist set is_blocked=0 where src_ip=inet_aton('$IP');" >> $LOG 2>&1
fi

