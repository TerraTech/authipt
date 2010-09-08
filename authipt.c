/*
 * Copyright (C) 1998 - 2007 Bob Beck (beck@openbsd.org).
 * 			2010 Andreas Bertheussen (andreas@elektronisk.org) 
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <pwd.h>

#include <sys/param.h>

#include <signal.h>

#include "pathnames.h"

size_t cplen = 0;
char pidfile[MAXPATHLEN];

FILE	*pidfp;
int	pidfd = -1;

char ipsrc[128]; /* xxx.xxx.xxx.xxx\0 */ 
char luser[32];
char proctitle[128];

static int	change_filter(int, const char *, const char *);
static int	change_table(int, const char *);
static void	do_death(int);
static void	need_death(int signo); /* signal handler */
volatile sig_atomic_t	want_death;

int main(int argc, char *argv[]) {
	int lockcnt = 0,n = 0;
	char *cp, *shell;
	struct in6_addr	 ina;
	uid_t uid;
	gid_t gid;
	struct passwd *pw;
	openlog("authipd",LOG_PID|LOG_NDELAY,LOG_DAEMON);
	
	if ((cp = getenv("SSH_TTY")) == NULL) {
		syslog(LOG_ERR, "non-interactive session connection for authpf");
		exit(1);
	}
	
	if ((cp = getenv("SSH_CLIENT")) == NULL) {
		syslog(LOG_ERR, "cannot determine connection source");
		exit(1);
	}
	strncpy(ipsrc, cp, sizeof(ipsrc)); /* fit the stirng into ipsrc */
	if (strlen(ipsrc) < strlen(cp)){
		syslog(LOG_ERR, "SSH_CLIENT variable too long");
		exit(1);
	}

	cp = strchr(ipsrc, ' '); /* Look for the space delimiter after IP address */
	if (cp == NULL) {
		syslog(LOG_ERR, "corrupt SSH_CLIENT variable %s", ipsrc);
		exit(1);
	}
	*cp = '\0';
	
	if (inet_pton(AF_INET, ipsrc, &ina) != 1 &&
		inet_pton(AF_INET6, ipsrc, &ina) != 1) {
		syslog(LOG_ERR, "cannot determine IP from SSH_CLIENT %s", ipsrc);
		exit(1);
	}
	uid = getuid();
	pw = getpwuid(uid);
	if (pw == NULL) {
		syslog(LOG_ERR, "cannot find user for uid %u", uid);
		exit(1);	
	}
	shell = pw->pw_shell; /* Make sure the users shell is set to authipf (user is allowed to run authipf) */
	if (strcmp(shell, PATH_AUTHIPT_SHELL)) {
		//syslog(LOG_ERR, "wrong shell for user %s, uid %u", pw->pw_name, pw->pw_uid);
		// exit(1);  /* TODO: ENABLE THIS */
	}
	
	strncpy(luser, pw->pw_name, sizeof(luser));
	if (strlen(pw->pw_name) > strlen(luser)) {
		syslog(LOG_ERR, "username too long: %s", pw->pw_name);
		exit(1);
	}
	/* The filename to the file for the users IP, e.g. /var/authipt/192.168.2.44 */
	n = snprintf(pidfile, sizeof(pidfile),"%s/%s",
		PATH_PIDFILE,
		ipsrc
		);
	/* a return value of /size/ (sizeof(pidfile)) or more means output was truncated */
	if (n < 0 || (u_int)n >= sizeof(pidfile)) {
		syslog(LOG_ERR, "path to pidfile too long");
		exit(1);
	}
	
	signal(SIGTERM, need_death);
	signal(SIGINT, need_death);
	signal(SIGALRM, need_death);
	signal(SIGPIPE, need_death);
	signal(SIGHUP, need_death);
	signal(SIGQUIT, need_death);
	signal(SIGTSTP, need_death);

	/*
	 * If someone else is already using this ip, then this person
	 * wants to switch users - so kill the old process and exit
	 * as well.
	 *
	 * Note, we could print a message and tell them to log out, but the
	 * usual case of this is that someone has left themselves logged in,
	 * with the authenticated connection iconized and someone else walks
	 * up to use and automatically logs in before using. If this just
	 * gets rid of the old one silently, the new user never knows they
	 * could have used someone else's old authentication. If we
	 * tell them to log out before switching users it is an invitation
	 * for abuse.
	 */
	
	do {
		int save_errno, otherpid = -1;
		char otherluser[32];
		if ((pidfd = open(pidfile, O_RDWR|O_CREAT, 0664)) == -1 ||
		    (pidfp = fdopen(pidfd, "r+")) == NULL) {
			if (pidfd != -1)
				close(pidfd);
			syslog(LOG_ERR, "cannot open or create %s: %s", pidfile, strerror(errno));
			goto die;
		}
		fchmod(pidfd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
		if (flock(fileno(pidfp), LOCK_EX|LOCK_NB) == 0)
			break;
		save_errno = errno;
		rewind(pidfp);
		if (fscanf(pidfp, "%d\n%31s\n", &otherpid, otherluser) != 2)
			otherpid = -1;
		syslog(LOG_DEBUG, "tried to lock %s, in use by pid %d: %s",
			pidfile, otherpid, strerror(save_errno));

		if (otherpid > 0) {
			syslog(LOG_INFO, "killing prior auth (pid %d) of %s by user %s",
				otherpid, ipsrc, otherluser);
			if (kill((pid_t) otherpid, SIGTERM) == -1) {
				syslog(LOG_INFO, "could not kill process %d: (%m)", otherpid);
			}
		}
		/*
		 * We try to kill the previous process and acquire the lock
 		 * for 10 seconds, trying once a second. if we can't after
 		 * 10 attempts we log an error and give up.
 		 */
 		if (want_death || ++lockcnt > 10) {
			if (!want_death)
				syslog(LOG_ERR, "cannot kill previous authpf (pid %d)", otherpid);
			fclose(pidfp);
			pidfp = NULL;
			pidfd = -1;
			goto dogdeath;
			
		}
		sleep(1);
		/* re-open, and try again. The previous authpf process
		 * we killed above should unlink the file and release
 		 * it's lock, giving us a chance to get it now
		 */
		fclose(pidfp);
		pidfp = NULL;
		pidfd = -1;
	} while (1);

	/* whack the group list */
	gid = getegid();
	if (setgroups(1, &gid) == -1) {
		syslog(LOG_INFO, "setgroups: %s", strerror(errno));
		do_death(0);
	}

	/* TODO: CHECK IF USER IS BANNED */
	/* TODO: CONFIG FILE */

	/* TODO: remove stale rulesets */

	rewind(pidfp);
	fprintf(pidfp, "%ld\n%s\n", (long)getpid(), luser);
	fflush(pidfp);
	(void) ftruncate(fileno(pidfp),ftello(pidfp));

	//syslog(LOG_ERR, "Adding IP address %s", ipsrc);
	if (change_filter(1,luser,ipsrc) == -1) {
		printf("Unable to modify filters\n");
		do_death(0);
	}
	if (change_table(1, ipsrc) == -1){
		printf("Unable to modify table\n");
		change_filter(0,luser,ipsrc);
		do_death(0);
	}
	
	/* revoke privs */

	/*uid = getuid();
	if (setresuid(uid, uid, uid) == -1) {
		syslog(LOG_INFO, "setresuid: %s", strerror(errno));
		do_death(1);
	}*/


	while (1) {
		struct stat sb;
		char *path_message;
		printf("Hello %s.\n", luser);
		printf("You are authenticated from host %s\n.", ipsrc);
		snprintf(proctitle, sizeof(proctitle), "%s@%s", luser, ipsrc);
		prctl(PR_SET_NAME, proctitle, NULL, NULL, NULL);
		/* TODO: rename the process better than this - prctl has a limit of 15 letters */	

		/* TODO: print custom message from file*/
		while(1) {
			sleep(10);
			if (want_death)
				do_death(1);
		}
	}

	return 0;
dogdeath:
	printf("\n\nSorry, this service is currently unavailable due to ");
	printf("technical difficulties\n");
	printf("Your authentication process (pid %ld) was unable to run\n", (long)getpid());
	sleep(180);
die:
	do_death(0);
	return 0;
}

static int change_filter(int add, const char *luser, const char *ipsrc) {
	if (add) {
		//printf("[+] Adding user-specific rules for %s@%s\n", luser, ipsrc);
	} else {
		//printf("[+] Removing user-specific rules for %s@%s\n", luser, ipsrc);

	}
	return(0);
}

static int change_table(int add, const char *ipsrc) {
	/* make sure the table exists */
	pid_t pid;
	gid_t gid;
	int s;
	char *ipstr = NULL;
	char *pargv[5] = {PATH_IPSET, "-N", "authipt", "iphash", NULL};
	
	if (luser == NULL || !luser[0] || ipsrc ==NULL || !ipsrc[0]) {
		syslog(LOG_ERR, "invalid luser/ipsrc");
		goto error;
	}
	
	switch(pid = fork()) {
		case -1: syslog(LOG_ERR, "fork failed");
			goto error;
		case 0: gid = getgid();
			if (setregid(gid,gid) == -1) {
				syslog(LOG_ERR, "setregid: %s", strerror(errno));
			}
			execvp(PATH_IPSET, pargv);
			syslog(LOG_ERR, "exec of %s failed", PATH_IPSET);
			_exit(1); /* abort the child process */
		default: break;/* this is the parent process, continue */
	}
	
	waitpid(pid, &s, 0);

	pargv[3] = ipsrc;
	if (add) {
		//printf("[+] Adding %s to set of authenticated users\n", ipsrc);
		pargv[1] = "-A";
	} else {
		//printf("[-] Removing %s from set of authenticated users\n", ipsrc);
		pargv[1] = "-D";
	}
	switch(pid = fork()) {
		case -1:
			syslog(LOG_ERR, "fork failed");
			goto error;
		case 0: /* This is the child process - execute command */
			gid = getgid();
			if (setregid(gid, gid) == -1) {
				syslog(LOG_ERR, "setregid: %s", strerror(errno));
			}
			execvp(PATH_IPSET, pargv);
			syslog(LOG_ERR, "exec of %s failed", PATH_IPSET);
			_exit(1);
		default: break; /* this is the parent process, continue */
	}
	waitpid(pid, &s, 0);

	return(0);
error:
	return(-1);

}

static void need_death(int signo) {
	want_death = 1; /* Signal through a variable */
}

static void do_death(int active) {
	int ret = 0;
	if (active) {
		change_filter(0, luser, ipsrc);
		change_table(0, ipsrc);
		/* TODO: kill states */

	}

	if (pidfile[0] && pidfd != -1)
		if (unlink(pidfile) == -1)
			syslog(LOG_ERR, "cannot unlink (%s) (%m)",pidfile);
	exit(0);

}
