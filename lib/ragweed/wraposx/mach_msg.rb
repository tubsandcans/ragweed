# mach messaging implementation testing
#

module Ragweed; end
module Ragweed; end
module Ragweed::Wraposx;end

# First, some constants
#

module Ragweed::Wraposx::Mach
  module Port
    module Right
      SEND = 0
      RECEIVE = 1
      SEND_ONCE = 2
      PORT_SET = 3
      DEAD_NAME = 4
      LABELH = 5      
      NUMBER = 6      
    end
    module Type
      NONE = 0
      SEND = 1 << (Ragweed::Wraposx::Mach::Port::Right::SEND + 16)
      RECEIVE = 1 << (Ragweed::Wraposx::Mach::Port::Right::RECEIVE + 16)
      SEND_ONCE = 1 << (Ragweed::Wraposx::Mach::Port::Right::SEND_ONCE + 16)
      PORT_SET = 1 << (Ragweed::Wraposx::Mach::Port::Right::PORT_SET + 16)
      DEAD_NAME = 1 << (Ragweed::Wraposx::Mach::Port::Right::DEAD_NAME + 16)
      LABELH = 1 << (Ragweed::Wraposx::Mach::Port::Right::LABELH + 16)
      SEND_RECIEVE = (SEND | RECEIVE)
      SEND_RIGHTS = (SEND | SEND_ONCE)
      PORT_RIGHTS = (SEND_RIGHTS | RECEIVE)
      PORT_OR_DEAD = (PORT_RIGHTS | DEAD_NAME)
      ALL_RIGHTS = (PORT_OR_DEAD | PORT_SET)
      
      DNREQUEST = 0x80000000
    end
  end
  EXCEPTION_CODES = 0x80000000 # Send 64-bit code and subcode in the exception header
end

# Machine-independent exception behaviors
#
module Ragweed::Wraposx::Exception
  DEFAULT = 1
  # Send a catch_exception_raise message including the identity.

  STATE = 2
  # Send a catch_exception_raise_state message including the
  # thread state.

  STATE_IDENTITY = 3
  # Send a catch_exception_raise_state_identity message including
  # the thread identity and state.
end

# Mostly from exception_types.h
# 
module Ragweed::Wraposx::Exc
  BAD_ACCESS = 1 # Could not access memory
  # Code contains kern_return_t describing error.
  # Subcode contains bad memory address.

  BAD_INSTRUCTION = 2 # Instruction failed
  # Illegal or undefined instruction or operand

  ARITHMETIC = 3 # Arithmetic exception
  # Exact nature of exception is in code field

  EMULATION = 4 # Emulation instruction
  # Emulation support instruction encountered
  # Details in code and subcode fields

  SOFTWARE = 5 # Software generated exception
  # Exact exception is in code field.
  # Codes 0 - 0xFFFF reserved to hardware
  # Codes 0x10000 - 0x1FFFF reserved for OS emulation (Unix)

  BREAKPOINT = 6 # Trace, breakpoint, etc.
  # Details in code field.

  SYSCALL = 7 # System calls.

  MACH_SYSCALL = 8 # Mach system calls.

  RPC_ALERT = 9 # RPC alert

  CRASH = 10 # Abnormal process exit
  
  # Machine independent codes for EXC_SOFTWARE
  # Codes 0x10000 - 0x1FFFF reserved for OS emulation (Unix)
  # 0x10000 - 0x10002 in use for unix signals
  #
  SOFT_SIGNAL = 0x10003 # Unix signal exceptions
  
  TYPES_COUNT = 11 # defined inexception.h
  
  # Masks for exception definitions, above
  # bit zero is unused, therefore 1 word = 31 exception types
  #
  module Mask
    MACHINE = 0 # defined in exception.h
    BAD_ACCESS = (1 << Ragweed::Wraposx::Exc::BAD_ACCESS)
    BAD_INSTRUCTION = (1 << Ragweed::Wraposx::Exc::BAD_INSTRUCTION)
    ARITHMETIC = (1 << Ragweed::Wraposx::Exc::ARITHMETIC)
    EMULATION = (1 << Ragweed::Wraposx::Exc::EMULATION)
    SOFTWARE = (1 << Ragweed::Wraposx::Exc::SOFTWARE)
    BREAKPOINT = (1 << Ragweed::Wraposx::Exc::BREAKPOINT)
    SYSCALL = (1 << Ragweed::Wraposx::Exc::SYSCALL)
    MACH_SYSCALL = (1 << Ragweed::Wraposx::Exc::MACH_SYSCALL)
    RPC_ALERT = (1 << Ragweed::Wraposx::Exc::RPC_ALERT)
    CRASH = (1 << Ragweed::Wraposx::Exc::CRASH)

    ALL = (BAD_ACCESS | BAD_INSTRUCTION | ARITHMETIC |
           EMULATION | SOFTWARE | BREAKPOINT | SYSCALL |
           MACH_SYSCALL | RPC_ALERT |CRASH | MACHINE)
  end
end

module Ragweed::Wraposx
  class << self
    # Set an exception handler for a task on one or more exception types.
    # These handlers are invoked for all threads in the task if there are
    # no thread-specific exception handlers or those handlers returned an
    # error.
    # 
    # kern_return_t task_set_exception_ports
    # (
    #   task_t task,
    #   exception_mask_t exception_mask,
    #   mach_port_t new_port,
    #   exception_behavior_t behavior,
    #   thread_state_flavor_t new_flavor
    # );
    #
    def task_set_exception_ports(task, exc_mask, new_port, behavior, new_flavor)
      r = CALLS["libc!task_set_exception_ports:IIIII=I"].call(task, exc_mask, new_port, behavior, new_flavor).first
      raise KernelCallError.new(:task_set_exception_ports, r) if r !=0
    end
    
    # Allocates the specified kind of object, with the given name.
    # The right must be one of
    #   MACH_PORT_RIGHT_RECEIVE
    #   MACH_PORT_RIGHT_PORT_SET
    #   MACH_PORT_RIGHT_DEAD_NAME
    # New port sets are empty.  New ports don't have any
    # send/send-once rights or queued messages.  The make-send
    # count is zero and their queue limit is MACH_PORT_QLIMIT_DEFAULT.
    # New sets, ports, and dead names have one user reference.
    # 
    # kern_return_t mach_port_allocate
    # (
    #   ipc_space_t task,
    #   mach_port_right_t right,
    #   mach_port_name_t *name
    # );
    #
    def mach_port_allocate(task, right)
      name = ("\x00" * SizeOf::INT).to_ptr
      r = CALLS["libc!mach_port_allocate:IIP=I"].call(task, right, name).first
      raise KernelCallError.new(:mach_port_allocate, r) if r != 0
      name.to_s(SizeOf::INT).unpack("I_").first
    end
    
    # Releases one send/send-once/dead-name user ref.
    # Just like mach_port_mod_refs -1, but deduces the
    # correct type of right.  This allows a user task
    # to release a ref for a port without worrying
    # about whether the port has died or not.
    # 
    # kern_return_t mach_port_deallocate
    # (
    #   ipc_space_t task,
    #   mach_port_name_t name
    # );
    #
    def mach_port_deallocate(task, name)
      r = CALLS["libc!mach_port_deallocate:II=I"].call(task, name).first
      raise KernelCallError.new(:mach_port_deallocate, r) if r != 0
    end
  end
end