man_MANS = log-user-session.8

EXTRA_DIST = log-user-session.8 log-user-session.pod 

log-user-session.8: log-user-session.pod
	pod2man -c "" -s 8 -r "log-user-session" $< >$@

