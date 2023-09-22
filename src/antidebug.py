import lldb
import os
import sys
import struct
import time
from colorama import Fore, Back, Style

process = None
target = None

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f antidebug.main antidebug')

def plog(message):
    print(Fore.GREEN + '[+]: {}'.format(message) + Fore.RESET)

def mlog(message):
    print(Fore.RED + '[-]: {}'.format(message) + Fore.RESET)

def clog(message):
    print(Fore.YELLOW + '[*]: {}'.format(message) + Fore.RESET)

def log(message):
    print(Fore.WHITE + '[.]: {}'.format(message) + Fore.RESET)

def mem_read_int32(address):
    error = lldb.SBError()
    data = process.ReadMemory(address, 4, error)
    if error.Success():
        data = struct.unpack("<I", data)[0]
        return data
    else:
        raise Exception("Failed to read memory at address: " + str(address))
    
def mem_read_int64(address):
    error = lldb.SBError()
    data = process.ReadMemory(address, 8, error)
    if error.Success():
        data = struct.unpack("<Q", data)[0]
        return data
    else:
        raise Exception("Failed to read memory at address: " + str(address))


def mem_write_int32(address, value):
    data = struct.pack("<I", value)
    error = lldb.SBError()
    bytes = process.WriteMemory(address, data, error)
    if error.Success():
        return bytes
    else:
        raise Exception("Failed to write memory at address: " + str(address) + "\ndescription: " + str(error.GetCString()) + "\ntype: " + str(error.GetType()))
         

def exec_cmd(debugger, command):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand(command, res)

    if not res.HasResult():
        # something error
        return res.GetError()

    response = res.GetOutput()
    return response


def onPtraceBreakpointHit(frame, bp_loc, internal_dict):
    plog("ptrace breakpoint hit")


def onSysctlBreakpointHit(frame, bp_loc, internal_dict):

    # disable async state
    oldAsync = lldb.debugger.GetAsync()
    lldb.debugger.SetAsync(False)

    name = int(frame.FindRegister("x0").GetValue(), 16)
    nameLen = int(frame.FindRegister("x1").GetValue(), 16)
    oldP = int(frame.FindRegister("x2").GetValue(), 16)
    oldLenP = int(frame.FindRegister("x3").GetValue(), 16)
    newP = int(frame.FindRegister("x4").GetValue(), 16)
    newLenP = int(frame.FindRegister("x5").GetValue(), 16)

    plog("sysctl breakpoint hit")

    # p_flag to indicate not being traced
    e_ppid_offset = int(0x230)
    p_flag_offset = int(0x20)
    p_flag_value = int(67125254)

    # of nameLen is equal 4, then it is probably a kinfo_proc request
    if nameLen == 4:
        # read the value at the address
        tipo = mem_read_int32(name) # 0x1
        arg0 = mem_read_int32(name + 0x4) # 0xe
        arg1 = mem_read_int32(name + 0x8) # 0x1
        pid = mem_read_int32(name + 0xc) # <pid>

        # if debug detection is found, then evade it
        if tipo == 0x1 and arg0 == 0xE and arg1 == 0x1 and pid == process.id:
            clog("sysctl debug detection found, evading it")

            # run process till return
            thread = frame.GetThread()

            # step until return of function
            error = lldb.SBError()
            thread.StepOutOfFrame(frame, error)

            if error.Success():
                p_flag = mem_read_int32(oldP + 0x20)
                e_ppid = mem_read_int32(oldP + 0x230)

                clog("[BEFORE] p_flag: {}".format(p_flag))
                clog("[BEFORE] e_ppid: {}".format(e_ppid))

                # set the p_flag to indicate not being traced
                mem_write_int32(oldP + p_flag_offset, p_flag_value)
                # set ppid to 1
                mem_write_int32(oldP + e_ppid_offset, 1)

                p_flag = mem_read_int32(oldP + p_flag_offset)
                e_ppid = mem_read_int32(oldP + e_ppid_offset)

                log("==================================")

                clog("[AFTER] p_flag: {}".format(p_flag))
                clog("[AFTER] e_ppid: {}".format(e_ppid))

                plog("Successfully evaded sysctl debug detection")

            else:
                mlog("Failed to step out of current sysctl frame")

    # restore async state
    lldb.debugger.SetAsync(oldAsync)

    # continue after everything is handled properly
    process.Continue()


def onGetppidBreakpointHit(frame, bp_loc, internal_dict):
    plog("getppid breakpoint hit")


def main(debugger, arguments, result, internal_dict):
    global target, process
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()


    # create breakpoints on ptrace, sysctl & getppid
    clog("Creating breakpoints on ptrace, sysctl and getppid")
    ptraceBp = target.BreakpointCreateByName('ptrace')
    sysctlBp = target.BreakpointCreateByName('sysctl')
    getppidBp = target.BreakpointCreateByName('getppid')

    if not ptraceBp.IsValid():
        mlog("ptrace breakpoint is not valid")
        return
    
    if not sysctlBp.IsValid():
        mlog("sysctl breakpoint is not valid")
        return
    
    if not getppidBp.IsValid():
        mlog("getppid breakpoint is not valid")
        return
    
    # set the breakpoint hit event callbacks
    ptraceBp.SetScriptCallbackFunction('antidebug.onPtraceBreakpointHit')
    sysctlBp.SetScriptCallbackFunction('antidebug.onSysctlBreakpointHit')
    getppidBp.SetScriptCallbackFunction('antidebug.onGetppidBreakpointHit')
    plog("Breakpoints set successfully")

    # continue process
    process.Continue()