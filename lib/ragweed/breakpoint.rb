module Ragweed; end
class Ragweed::Breakpoint32
  INT3 = 0xCC
  attr_accessor :orig
  attr_accessor :bps
  attr_accessor :deferred
  attr_accessor :addr
  def initialize(process, ip, def_status, callable)
    @process = process
    @addr = ip
    @callable = callable
    @deferred = def_status
    @orig = 0
  end

  def addr; @addr; end
  
  def install
      if @addr == 0 or @deferred == true
        return
      end

      o = @process.read8(@addr)

      if(orig != INT3)
        @orig = o
        @process.write8(@addr, INT3) 
        Ragweed::Wrap32::flush_instruction_cache(@process.handle)
      end
  end

  def deferred_install(h, base)
      @addr = @process.get_deferred_proc_remote(@addr, h, base)
      self.install
      return @addr
  end

  def uninstall
    if(@orig != INT3)
      @process.write8(@addr, @orig)
      Ragweed::Wrap32::flush_instruction_cache(@process.handle)
    end
  end

  def call(*args); @callable.call(*args); end    
  def method_missing(meth, *args); @bp.send(meth, *args); end
end

class Ragweed::BreakpointTux
  INT3 = 0xCC ## obviously x86 specific debugger here

  attr_accessor :orig, :bpid, :bppid, :function
  attr_reader :addr

  ## bp: parent for method_missing calls
  ## ip: insertion point
  ## callable: lambda to be called when breakpoint is hit
  ## name: name of breakpoint
  def initialize(bp, ip, callable, p, name = "")
  @bppid = p
    @@bpid ||= 0
    @bp = bp
    @function = name
    @addr = ip
    @callable = callable
    @installed = false
    @orig = 0
    @bpid = (@@bpid += 1)
  end

  ## Install a breakpoint (replace instruction with int3)
  def install
    ## Replace the original instruction with an int3
    @orig = Ragweed::Wraptux::ptrace(Ragweed::Wraptux::Ptrace::PEEK_TEXT, @bppid, @addr, 0)
    if @orig != -1
      n = (@orig & ~0xff) | INT3;
      Ragweed::Wraptux::ptrace(Ragweed::Wraptux::Ptrace::POKE_TEXT, @bppid, @addr, n)
      @installed = true
    else
      @installed = false
    end
  end

  ## Uninstall the breakpoint
  def uninstall
    ## Put back the original instruction
    if @orig != INT3
      Ragweed::Wraptux::ptrace(Ragweed::Wraptux::Ptrace::POKE_TEXT, @bppid, @addr, @orig)
      @installed = false
    end
  end

  def installed?; @installed; end
  def call(*args); @callable.call(*args) if @callable != nil; end
  def method_missing(meth, *args); @bp.send(meth, *args); end
end

class Ragweed::BreakpointOsx
  #    include Ragweed::Wraposx
  INT3 = 0xCC
  attr_accessor :orig
  attr_accessor :bpid
  attr_reader :addr
  attr_accessor :function

  # bp: parent for method_missing calls
  # ip: insertion point
  # callable: lambda to be called when breakpoint is hit
  # name: name of breakpoint
  def initialize(bp, ip, callable, name = "")
    @@bpid ||= 0
    @bp = bp
    @function = name
    @addr = ip
    @callable = callable
    @bpid = (@@bpid += 1)
    @installed = false
  end

  # Install this breakpoint.
  def install
    Ragweed::Wraposx::task_suspend(@bp.task)
    @bp.hook if not @bp.hooked?
    Ragweed::Wraposx::vm_protect(@bp.task,@addr,1,false,Ragweed::Wraposx::Vm::Prot::ALL)
    @orig = Ragweed::Wraposx::vm_read(@bp.task,@addr,1)
    if(@orig != INT3)
      Ragweed::Wraposx::vm_write(@bp.task,@addr, [INT3].pack('C'))
    end
    @installed = true
    Ragweed::Wraposx::task_resume(@bp.task)
  end

  # Uninstall this breakpoint.
  def uninstall
    Ragweed::Wraposx::task_suspend(@bp.task)
    if(@orig != INT3)
      Ragweed::Wraposx::vm_write(@bp.task, @addr, @orig)
    end
    @installed = false
    Ragweed::Wraposx::task_resume(@bp.task)
  end

  def installed?; @installed; end
  def call(*args); @callable.call(*args) if @callable != nil; end
  def method_missing(meth, *args); @bp.send(meth, *args); end
end
