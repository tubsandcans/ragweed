NULL = nil
module Ragweed; end
module Ragweed::Wraptux;end

module Ragweed::Wraptux::Ptrace
  TRACE_ME = 0
  PEEK_TEXT = 1
  PEEK_DATA = 2
  PEEK_USER = 3
  POKE_TEXT = 4
  POKE_DATA = 5
  POKE_USER = 6
  CONTINUE = 7
  KILL = 8
  STEP = 9
  GETREGS = 12
  SETREGS = 13
  ATTACH = 16
  DETACH = 17
  SYSCALL = 24
end

module Ragweed::Wraptux::Signal
	SIGHUP = 1
	SIGINT = 2
	SIGQUIT =  3
	SIGILL = 4
	SIGTRAP = 5
	SIGABRT = 6
	SIGIOT = 6
	SIGBUS = 7
	SIGFPE = 8
	SIGKILL = 9
	SIGUSR1 = 10
	SIGSEGV = 11
	SIGUSR2 = 12
	SIGPIPE = 13
	SIGALRM = 14
	SIGTERM = 15
	SIGSTKFLT = 16
	SIGCHLD = 17
	SIGCONT = 18
	SIGSTOP = 19
	SIGTSTP = 20
	SIGTTIN = 21
	SIGTTOU = 22
	SIGURG = 23
	SIGXCPU = 24
	SIGXFSZ = 25
	SIGVTALRM = 26
	SIGPROF = 27
	SIGWINCH = 28
	SIGIO = 29
	SIGPOLL = SIGIO
	#SIGLOST = 29
	SIGPWR = 30
	SIGSYS = 31
	SIGUNUSED = 31
end

module Ragweed::Wraptux::Wait
  NOHANG = 1
  UNTRACED = 2
  EXITED = 4
  STOPPED = 8
  CONTINUED = 10
  NOWWAIT = 20
end