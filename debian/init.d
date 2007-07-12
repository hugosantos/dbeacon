#! /bin/sh

### BEGIN INIT INFO
# Provides:		dbeacon
# Required-Start:	$network
# Required-Stop:	$network
# Should-Start:		$local_fs
# Should-Stop:		$local_fs
# Default-Start:	2 3 4 5
# Default-Stop:		0 1 6
# Short-Description:	Multicast Beacon
# Description:		Multicast Beacon supporting both IPv4 and IPv6 multicast, collecting information using
#			both Any Source Multicast (ASM) and Source-Specific Multicast (SSM).
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/bin/dbeacon
NAME=dbeacon
DESC="Multicast Beacon"
CONFIG=/etc/dbeacon/dbeacon.conf 
PIDFILE=/var/run/dbeacon.pid

test -x $DAEMON || exit 0

# add daemonize and configuration file support
DAEMON_OPTS="-D -c $CONFIG -p $PIDFILE"

. /lib/lsb/init-functions

case "$1" in
  start)
	log_daemon_msg "Starting $DESC"
        if [ ! -s $CONFIG ]; then
		log_progress_msg "disabled; missing configuration file"
		log_end_msg 0
		exit 0
	else
		log_progress_msg "$NAME"
		start-stop-daemon --start --quiet \
			--exec $DAEMON --pidfile $PIDFILE -- $DAEMON_OPTS
		log_end_msg "$?"
	fi
	;;
  stop)
        log_daemon_msg "Stopping $DESC"
	log_progress_msg "$NAME"
	start-stop-daemon --stop --oknodo --quiet \
		--exec $DAEMON --pidfile $PIDFILE
	log_end_msg "$?"
	;;
  force-reload|restart)
	log_daemon_msg "Restarting $DESC"
	log_progress_msg "$NAME"
	start-stop-daemon --stop --quiet \
		--exec $DAEMON || true
	sleep 1
	start-stop-daemon --start --quiet \
		--exec $DAEMON --pidfile $PIDFILE -- $DAEMON_OPTS
	log_end_msg "$?"
	;;
  *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
