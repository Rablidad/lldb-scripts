import lldb
from utils import *

def onSyscallBreakpointHit(frame, bp_loc, internal_dict):
    oldAsync = lldb.debugger.GetAsync()
    lldb.debugger.SetAsync(False)

    ilog("SYCALL BREAKPOINT HIT")
    ilog("IDENTYFACEEEEEEEEEEEE")

    lldb.debugger.SetAsync(oldAsync)
    get_process().Continue()


def onSysctlBreakpointHit(frame, bp_loc, internal_dict):
    # disable async state
    oldAsync = lldb.debugger.GetAsync()
    lldb.debugger.SetAsync(False)
    
    # get current frame thread
    thread = frame.GetThread()

    name = int(frame.FindRegister("x0").GetValue(), 16)
    nameLen = int(frame.FindRegister("x1").GetValue(), 16)
    oldP = int(frame.FindRegister("x2").GetValue(), 16)
    oldLenP = int(frame.FindRegister("x3").GetValue(), 16)
    newP = int(frame.FindRegister("x4").GetValue(), 16)
    newLenP = int(frame.FindRegister("x5").GetValue(), 16)

    # p_flag to indicate not being traced
    e_ppid_offset = int(0x230)
    p_flag_offset = int(0x20)
    p_flag_value = int(67125254)

    # read the value at the address
    tipo = mem_read_int32(name) # CTL_KERN
    arg0 = mem_read_int32(name + 0x4) # KERN_PROC
    arg1 = mem_read_int32(name + 0x8) # KERN_PROC_PID
    pid = mem_read_int32(name + 0xc) # <PID>

    # if debug detection is found, then evade it
    if tipo == 0x1 and arg0 == 0xE and arg1 == 0x1 and pid == get_process().id:
        if hasInFrame(thread, ["dynatrace", "identyface", "santanderbrasil"]):                
            error = lldb.SBError()
            thread.StepOutOfFrame(frame, error)
            if error.Success():
                clog("Writing flag values")
                mem_write_int32(oldP + p_flag_offset, p_flag_value)
                mem_write_int32(oldP + e_ppid_offset, 1)
                plog("Successfully written flag values")   
                     

    # restore async state
    lldb.debugger.SetAsync(oldAsync)

    # continue after everything is handled properly
    get_process().Continue()

def onTaskExceptionPortsBreakpointHit(frame, bp_loc, internal_dict):
    # disable async state
    oldAsync = lldb.debugger.GetAsync()
    lldb.debugger.SetAsync(False)
    
    clog("task_get_exception_ports HIT!")
    exec_cmd("bt")


    # disable async state
    lldb.debugger.SetAsync(oldAsync)
    get_process().Continue()

def onGetppidBreakpointHit(frame, bp_loc, internal_dict):
    oldAsync = lldb.debugger.GetAsync()
    lldb.debugger.SetAsync(False)

    clog("getppid hit")

    # get the current thread that is stopped on this frame
    thread = frame.GetThread()

    if hasInFrame(thread, ["dynatrace", "identyface", "santanderbrasil"]):
        # step out of the current frame to get to the caller
        # and change the return value
        thread.StepOutOfFrame(frame)

        # change the value in the register
        if not reg_write_int32(frame, "x0", "1"):
            # mlog("Failed to write register x0")
            raise Exception("Failed to write register x0")

    plog("getppid finished")
    # disable async state
    lldb.debugger.SetAsync(oldAsync)
    get_process().Continue()


def main(debugger, arguments, result, internal_dict):

    # create breakpoints on ptrace, sysctl & getppid    
    create_bp_by_name(get_target(), 'sysctl', 'antidebug.onSysctlBreakpointHit', '$x1 == 0x4')
    create_bp_by_name(get_target(), 'getppid', 'antidebug.onGetppidBreakpointHit')
    create_bp_by_name(get_target(), 'task_get_exception_ports', 'antidebug.onTaskExceptionPortsBreakpointHit')

    # continue process
    get_process().Continue()


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f antidebug.main debugbypass')