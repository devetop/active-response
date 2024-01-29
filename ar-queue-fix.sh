#!/usr/bin/bash
# service script to check and fix Active Response functionality in OSSEC
# will only run if corresponding errors are detected in logs

AGENTS='/var/ossec/etc/agents'
CLKEYS='/var/ossec/etc/client.keys'
chmod=`which chmod`
chown=`which chown`


if [[ ! -s $AGENTS ]]; then
  echo "file $AGENTS is broken, fixing..."
  echo '127.0.0.1,localhost' > $AGENTS
  chmod 400 $AGENTS
  chown root:root $AGENTS
else
 echo "file exist $AGENTS"
fi


if [[ ! -s $CLKEYS ]]; then
  echo "file $CLKEYS is broken, fixing..."
  /var/ossec/bin/manage_agents -f $AGENTS || exit 1 
  /sbin/service ossec-hids restart
else
  echo "file $CLKEYS exists, checking permissions"
  USER=$(stat -c '%U' $CLKEYS )
  GROUP=$(stat -c '%G' $CLKEYS)
  if [ "$USER" != "root" ] || [ "$GROUP" != "ossec"  ]; then 
    chown root:ossec $CLKEYS
    chmod 440 $CLKEYS
    /sbin/service ossec-hids restart
  fi
fi



