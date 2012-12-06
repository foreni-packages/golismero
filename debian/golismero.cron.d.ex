#
# Regular cron jobs for the golismero package
#
0 4	* * *	root	[ -x /usr/bin/golismero_maintenance ] && /usr/bin/golismero_maintenance
