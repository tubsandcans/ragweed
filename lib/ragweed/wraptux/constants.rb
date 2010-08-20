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
    GETFPREGS = 14
    SETFPREGS = 15
    ATTACH = 16
    DETACH = 17
    GETFPXREGS = 18
    SETFPXREGS = 19
    SYSCALL = 24
    SETOPTIONS = 0x4200
    GETEVENTMSG = 0x4201
    GETSIGINFO = 0x4202
    SETSIGINFO = 0x4203

    # Alternate names defined for above constants
    TRACEME = TRACE_ME
    PEEKTEXT = READ_I = PEEK_TEXT
    PEEKDATA = READ_D = PEEK_DATA
    PEEKUSER = READ_U = PEEK_USER
    POKETEXT = WRITE_I = POKE_TEXT
    POKEDATA = WRITE_D = POKE_DATA
    POKEUSER = WRITE_U = POKE_USER
    CONT = CONTINUE
    SINGLESTEP = SINGLE_STEP = STEP
    
end

module Ragweed::Wraptux::Ptrace::SetOptions
    TRACESYSGOOD = 0x00000001
    TRACEFORK = 0x00000002
    TRACEVFORK = 0x00000004
    TRACECLONE = 0x00000008
    TRACEEXEC = 0x00000010
    TRACEVFORKDONE = 0x00000020
    TRACEEXIT = 0x00000040
    MASK = 0x0000007f
end

module Ragweed::Wraptux::Ptrace::EventCodes
    FORK = 1
    VFORK = 2
    CLONE = 3
    EXEC = 4
    VFORK_DONE = 5
    EXIT = 6
end

# Use normal Ruby Signal module instead. This may be depricated in the future
module Ragweed::Wraptux::Signal
	SIGHUP = 1
	SIGINT = 2
	SIGQUIT = 3
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
