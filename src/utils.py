import lldb
import shlex
import optparse
import datetime
from colorama import Fore
import struct
from keystone import *


# logging utilities
def plog(message):
    now = datetime.datetime.now()
    print(Fore.GREEN + '{} [+]: {}'.format(now, message) + Fore.RESET)

def mlog(message):
    now = datetime.datetime.now()
    print(Fore.RED + '{} [-]: {}'.format(now, message) + Fore.RESET)

def wlog(message):
    now = datetime.datetime.now()
    print(Fore.YELLOW + '{} [!]: {}'.format(now, message) + Fore.RESET)

def clog(message):
    now = datetime.datetime.now()
    print(Fore.BLUE + '{} [*]: {}'.format(now, message) + Fore.RESET)

def ilog(message):
    now = datetime.datetime.now()
    print(Fore.WHITE + '{} [.]: {}'.format(now, message) + Fore.RESET)

def get_target():
    target = lldb.debugger.GetSelectedTarget()
    if not target:
        raise Exception("[-] error: no target available. please add a target to lldb.")
    return target

def get_process():
    return get_target().process
  
def get_main_module():
  return lldb.debugger.GetSelectedTarget().GetModuleAtIndex(0)

def mem_read_int32(address):
    error = lldb.SBError()
    clog("Reading memory at address: {:x}".format(address))
    data = get_process().ReadMemory(address, 4, error)
    if error.Success():
        plog("Successfully read memory at address: {:x}".format(address))
        data = struct.unpack("<I", data)[0]
        return data
    else:
        mlog("Failed to read memory at address: {}".format(address))
        raise Exception("Failed to read memory at address: " + str(address))
    
def mem_read_int64(address):
    error = lldb.SBError()
    data = get_process().ReadMemory(address, 8, error)
    if error.Success():
        data = struct.unpack("<Q", data)[0]
        return data
    else:
        raise Exception("Failed to read memory at address: " + str(address))

def mem_write_int32(address, value):
    data = value.to_bytes(4, byteorder='little')
    # data = struct.pack("<I", value)
    error = lldb.SBError()
    bytes = get_process().WriteMemory(address, data, error)
    if error.Success():
        return bytes
    else:
        raise Exception("Failed to write memory at address: " + str(address) + "\ndescription: " + str(error.GetCString()) + "\ntype: " + str(error.GetType()))

def reg_write_int32(frame, register, value):
    error = lldb.SBError()
    frame.FindRegister(register).SetValueFromCString(value, error)
    if error.Success():
        return True
    else:
        raise Exception("Failed to write register: " + str(register) + "\ndescription: " + str(error.GetCString()) + "\ntype: " + str(error.GetType()))

# execute debugger command
def exec_cmd(debugger, command):
    res = lldb.SBCommandReturnObject()
    interpreter = debugger.GetCommandInterpreter()
    interpreter.HandleCommand(command, res)

    if not res.HasResult():
        # something error
        return res.GetError()

    response = res.GetOutput()
    return response

# request a memory scan in section for given byte pattern
def scan_memory(pattern, module, sectionName):
  section = module.FindSection(sectionName)
  if not section:
    raise Exception("[-] error: section not found: {}".format(sectionName))
  
  patternBytes = bytes([int(x, base=16) for x in pattern.split(' ')])
  if not patternBytes or len(patternBytes) <= 0:
    raise Exception("[-] error: pattern is invalid")
  
  sectionAddr = section.GetLoadAddress(get_target())
  bytesToRead = section.GetByteSize()
  sectionBlob = get_process().ReadMemory(sectionAddr, bytesToRead, lldb.SBError())
  
  matches = find_pattern(sectionAddr, sectionBlob, patternBytes)
  return matches

# find byte pattern in blob
def find_pattern(baseAddr, blob, sequence):
  if(len(blob) < len(sequence)):
    return

  matches = []
  for i in range(len(blob)):
    if blob[i] == sequence[0]:
      for j in range(1, len(sequence)):
        if sequence[j] == '?':
          continue
        if blob[i+j] != sequence[j]:
          break
      else:
        matches.append(lldb.SBAddress(baseAddr + i, get_target()))

  return matches

def hasInFrame(thread, names):
    # check if names is array
    if not isinstance(names, list):
        raise Exception("[-] error: names must be an array")

    for frame in thread.frames:
        if frame.GetPCAddress().IsValid():
            module = frame.GetModule()
            if module:
                # get module name
                module_name = module.GetFileSpec().GetFilename()
                clog("module name: {}".format(module_name))
                for name in names:
                    if name.lower() in module_name.lower():
                        return True
    return False
  
def assemble_instructions(instructions):
    try:
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        encoding, count = ks.asm(instructions)
        return { encoding, count }
    except KsError as e:
        print("ERROR: %s" %e)
        return None 