#!/bin/sh

### BEGIN INIT INFO
# Provides: certmgr
# Required-Start: $remote_fs
# Required-Stop: $remote_fs
# Default-Start:  2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: start and stop certmgr daemon
# Description:  CertMgr is an X509 Certificate Management Service
### END INIT INFO

. /lib/lsb/init-functions

NAME="certmgr"
DAEMON=/usr/bin/${NAME}
DESC="CertMgr X509 Certificate Management Service"
PIDFILE=/var/run/${NAME}.pid

set -e

test -x ${DAEMON} || exit 0


[ -z "$SERVER_USER" ] && SERVER_USER=certmgr
[ -z "$SERVER_GROUP" ] && SERVER_GROUP=certmgr

if ! getent passwd | grep -q "^${SERVER_USER}:"; then
log_daemon_msg "Server user does not exist!"
log_end_msg 0
exit 1
fi
if ! getent group | grep -q "^${SERVER_GROUP}:" ; then
log_daemon_msg "Server group does not exist!"
log_end_msg =
exit 1
fi

PARAMS="--daemon"
START="--start --chuid ${SERVER_USER} --quiet --exec ${DAEMON} --pidfile ${PIDFILE} -- ${PARAMS}"

case "$1" in
  start)
	log_daemon_msg "Starting ${NAME}..."
	if [ -s ${PIDFILE} ] && kill -0 $(cat ${PIDFILE}) >/dev/null 2>&1; then
	                log_daemon_msg "${NAME} already running"
			log_end_msg 0
			exit 0
	fi

	if start-stop-daemon ${START} >/dev/null; then
		log_end_msg 0
	else
		log_end_msg 1
		exit 1
	fi
	;;
  stop)
	log_begin_msg "Stopping ${NAME}..."
	if start-stop-daemon --stop --quiet --oknodo --pidfile ${PIDFILE} --retry 10 ; then
		/bin/rm -f ${PIDFILE}
		log_end_msg 0
	else
		log_end_msg 1
		exit 1
	fi
	;;
  restart|force-reload)
  	$0 stop
	exec $0 start
  	;;
  status)
	status_of_proc $DAEMON $NAME
	;;
  *)
    echo "Usage: $0 {start|stop|restart|force-reload|status}" >&2
    exit 1
esac
 
exit 0
