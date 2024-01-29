#!/bin/bash
#  Imunify360 script for cleaning infectected cron jobs

USER=$2
TIMESTAMP=$4
PWD="$(pwd)"
CRONDIR="/var/ossec/active-response/quarantine"
CRONFILE=$CRONDIR/crontab-$USER-$TIMESTAMP
LOG_FILE="/var/ossec/logs/active-responses.log"
SIGS="/var/ossec/etc/decoders.d/signatures.txt"
CRONTAB_BIN="$(command -v crontab)"
LOGBADGE="$(date '+%b %d %T') $HOSTNAME im360ar: Active Response."
FIND="/usr/bin/find"
CONFIG="/etc/sysconfig/imunify360/imunify360-merged.config"
VALUE="false"
CONFIG_VALUE=$( cat "${CONFIG}" | grep crontabs | grep false )


LOCAL="$(dirname "$0")";
cd "$LOCAL" || exit
cd ../


# Checking for an args
 if [ $# -lt 4 ]; then
    echo "$0: <add> <USER> - <TIMESTAMP>" 
    exit 1;
 fi

test -f $SIGS || (echo "$LOGBADGE Crontab cleanup signatures $SIGS not found"; exit 1;)

backup()
{
 if [[ " $CONFIG_VALUE " =~ $VALUE ]]; then
   if $CRONTAB_BIN -l -u "$USER" > "$CRONFILE"; then
     echo "$LOGBADGE Crontab backup successful for user $USER" >> ${LOG_FILE};
   else
     echo "$LOGBADGE Crontab backup failed for user $USER" >> ${LOG_FILE};
     rm "$CRONFILE";
     exit 1;
   fi
 else 
  exit 1;
 fi
}

cleanup()
{
   if $CRONTAB_BIN  -l -u "$USER"  | grep -v "$regex"  | $CRONTAB_BIN -u "$USER" -; then
     echo "$LOGBADGE Crontab cleanup successful for user $USER" >> ${LOG_FILE};
   else
     echo "$LOGBADGE Crontab cleanup failed for user $USER" >> ${LOG_FILE};
     exit 1;
   fi
}

detect2cleanup()
{
 while IFS= read -r cronline; do
   while IFS=$'\n' read -r regex; do
     if [[ $cronline =~ $regex ]]; then
       echo "$LOGBADGE Found regex <$regex> for user <$USER>" >> ${LOG_FILE};
       cleanup;
     fi
   done < "$SIGS"
 done < "$CRONFILE"
}

wipe_old_backup()
{
  $FIND $CRONDIR/ -name 'crontab-*' -type f -mtime +7  -print0 | xargs -r0  rm --;
}


if backup; then
  detect2cleanup;
  wipe_old_backup;
fi


