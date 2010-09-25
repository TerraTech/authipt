import os, sys, ConfigParser, socket
import time, signal, grp, pwd
from datetime import timedelta, datetime


if not os.getuid() == 0:
	# not root
	print 'You are not root.'
	sys.exit()
try:
	conf = ConfigParser.RawConfigParser()
	conf.readfp(open('/etc/authipt/authipt.conf'))
except:
	print 'Warning: Could not open or parse config file in /etc/authipt/authipt.conf'
	print 'Default paths will be used'

def printusage():
	print 'Usage: authipt-admin subject'
	print 'Subjects and their options;'
	print '  session [list]'
	print '    Prints a list of active sessions.'
	print '  session list [ip|pid|user <value>]'
	print '    Limits the session listing to entries with a specified ip, pid or user'
	print ''
	print '  user [list [all|banned]]'
	print '    Prints a list of users that are set up for authipt. If "banned" is'
	print '    specified, only banned users will be listed'

def getpidfilelist():
	global piddir
	if not os.path.isdir(piddir):
		print 'Could not find the PID directory %s' % piddir
		sys.exit()

	# get a list of the pidfiles. Only the ones that have a valid name (ip address).
	pidlist = os.listdir(piddir)
	pidfilelist = []
	for idx in range(len(pidlist)):
		if os.path.isfile('%s/%s' % (piddir, pidlist[idx])) and isipaddress(pidlist[idx]):
			pidfilelist.append(pidlist[idx])
	
	return pidfilelist

def getpiddata():
	pidfilelist = getpidfilelist()
	piddata = []
	for idx in range(len(pidfilelist)):
		pidfilename = '%s/%s' % (piddir, pidfilelist[idx])
		ip = pidfilelist[idx]

		try:
			f = open(pidfilename)
			lines = f.readlines()
		except OSError, (errno, strerror):
			print 'Could not read pidfile %s: %s' % (pidfilename, strerror)
			f.close()
			sys.exit()
		
		initiated = datetime.fromtimestamp(os.stat(pidfilename).st_mtime).replace(microsecond = 0)
		duration = datetime.today().replace(microsecond=0) - initiated
		pid = lines[0].strip('\n')
		user = lines[1].strip('\n')
		if not len(lines) == 2:
			print 'PID file %s did not contain two lines.' % (pidfilename)
			f.close()
			sys.exit()
		f.close()
		piddata.append((ip, user, pid, initiated, duration))
	return piddata

def getuserdata():
	global groupname
	global confdir
	userdata = []
	groupmembers = grp.getgrnam(groupname).gr_mem
	for member in groupmembers:
		shell = pwd.getpwnam(member).pw_shell	# get shell details

		banned = 'No'
		if os.path.isfile('%s/users/%s/banned' % (confdir, member)):
			banned = 'Yes'
		userdata.append((member, banned, shell))
	return userdata

def isipaddress(string):
	try:
		socket.inet_pton(socket.AF_INET, string)
	except:
		return False
	return True


try:    piddir = conf.get('authipt', 'piddir')
except: piddir = '/var/authipt'

try:	subject = sys.argv[1]
except:
	printusage()
	sys.exit()

if subject == 'session':
	try:	action = sys.argv[2]
	except:	action = 'list'		# default action
	if action == 'list':
		# traverse the ok PID files, and print out details from them
		print 'Current local time:\t%s' % datetime.today().replace(microsecond = 0)
		print 'Current UTC time:\t%s' % datetime.utcnow().replace(microsecond = 0)
		print '\nIP address\tUser   \t\tPID\tInitiated (local time)\tDuration'
	
		piddata = getpiddata()	# get array of "pid-tuples"
		what = None
		which = None
		try:
			what = sys.argv[3]	# "ip"/"user"/"pid" ...
			which = sys.argv[4]	# actual address username or pid
		except:
			what = None
			which = None
		for pid in piddata:
			ip, user, pid, start, dur = pid	# unpack the pid tuple, and print it
			# skip entry if not the user/ip we are looking for
			if what:	# if a filter is specified, aply it
				if what == 'user':
					if user != which:
						continue
				elif what == 'ip':
					if ip != which:
						continue
				elif what == 'pid':
					if pid != which:
						continue
				else:	
					print '%s is not a criteria' % what
					printusage()
					sys.exit()
			print '%s\t%s%s\t%s\t%s' % (ip, user.ljust(16), pid, start, dur)
	elif action == 'kill':
		piddata = getpiddata()
		qualifier = None #'ip', 'pid', 'user', 'all'
		argument = None	# actual ip, pid or username
		try:
			qualifier = sys.argv[3]
			if qualifier != 'all':
				argument = sys.argv[4]
		except:
			print 'No kill target specified'
			printusage()
			sys.exit()
		
		for pid in piddata:
			ip, user, pid, start, dur = pid
			if qualifier == 'all':
				pass
			elif qualifier == 'user':
				if argument != user:
					continue
			elif qualifier == 'ip':
				if argument != ip:
					continue
			elif qualifier == 'pid':
				if argument != pid:
					continue
			else:
				print 'Unknown qualifier %s' % qualifier
				printusage()
				sys.exit()

			print 'Killing session for %s@%s, pid %s... ' % (user, ip, pid),
			try:	pass#os.kill(int(pid), signal.SIGTERM)	#TODO fix
			except OSError, (errno, strerror):
				print 'Failed: %s' % strerror
				continue
			print 'OK'
	else:
		print 'Unknown action %s' % action
		printusage()
		sys.exit()
elif subject == 'user':
	try:	action = sys.argv[2]
	except:	action = 'list'		# default action
	try:    groupname = conf.get('authipt', 'group')
	except: groupname = 'authipt'
	try:    confdir = conf.get('authipt', 'confdir')
	except: confdir = '/etc/authipt'
	try:    shellname = conf.get('authipt', 'shell')
	except: shellname = '/bin/authipt'

	if action == 'list':
		badshells = False
		try:	who = sys.argv[3]
		except:	who = 'all'
		userdata = getuserdata()
		print 'Configuration directory: %s' % confdir
		print 'Authipt user group:      %s' % groupname
		print 'Correct shell for users: %s' % shellname
		
		print '\nUser\t\tBanned\tShell'
		for user in userdata:
			name, banned, shell = user	# unpack
			if shell != shellname:		# highlight wrong shell
				badshells = True
				color = '\033[91m'
			else:
				color = '\033[92m'
			shell = '%s%s\033[0m' % (color, shell)
			if who == 'all':
				pass
			elif who == 'banned':
				if banned == 'No':
					continue	# skip unbanned users
			else:
				print 'Unknown qualifier %s' % who
				printusage()
				sys.exit()
			print '%s%s\t%s' % (name.ljust(16), banned, shell)
		if badshells:
			print '\nOne or more authipt users had an incorrect shell setting.'
			print 'For authipt to function, the user must have authipt set as shell.'

	else:
		print 'Unknown action %s' % action
		printusage()
		sys.exit()
elif subject == 'help':
	printusage()
	sys.exit()
else:
	printusage()
	sys.exit()
