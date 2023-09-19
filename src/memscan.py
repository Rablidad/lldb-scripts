import lldb
import shlex
import optparse

def __lldb_init_module(debugger, internal_dict):
  debugger.HandleCommand(
  'command script add -f memscan.scan_memory memscan')


def help(print=True):
  usage = """Usage: memscan -p <ida_pattern> [-s <section>] [-m <module>] [-b]
  Ex: memscan '01 10 00 D4' -s __text -m AppExecutable
  Ex: memscan '04 04 06 10 10' -s __LINKEDIT -m AppLib -b"""
  if print:
    print(usage)
  return usage

def parse_arguments(arguments, result):
  # unpack arguments
  args = shlex.split(arguments)
  parser = generate_option_parser()

  try:
    # parse arguments
    opts, _ = parser.parse_args(args)
  except:
    result.SetError(parser.usage)
    return
  
  if not opts.pattern:
    result.SetError("missing pattern to search.\n{}".format(parser.usage))
    return
  
  return opts

def scan_memory(debugger, arguments, result, internal_dict):
  process = debugger.GetSelectedTarget().GetProcess()
  target = debugger.GetSelectedTarget()
  module = None

  # parse the command line arguments
  opts = parse_arguments(arguments, result)

  # find target module
  for mod in target.module_iter():
    if (mod.file.basename.lower() == opts.module.lower()):
      module = mod
      break

  # `get_values` returns a tuple (pattern_bytes, section) from the command arguments
  # but also makes sure everything is valid
  values = get_values(opts.section, opts.pattern, module, result)
  (pattern_bytes, section) = (None, None)
  if result.Succeeded():
    (pattern_bytes, section) = values
  else:
    return

  start_addr = section.GetLoadAddress(target)
  bytes_to_read = section.GetByteSize()
  section_blob = process.ReadMemory(start_addr, bytes_to_read, lldb.SBError())

  offsets = find_pattern(section_blob, pattern_bytes)
  if len(offsets) <= 0:
    print("Pattern not found")
    return

  # disassemble the found patterns  
  for i in range(len(offsets)):
    if not opts.supress:
      address = lldb.SBAddress(start_addr + offsets[i], target)
      instructions = target.ReadInstructions(address, 1)
      for inst in instructions:
        print("[{}] + Found at ({} = {}): {} {}".format(i, hex(start_addr + offsets[i]), inst.GetAddress(), inst.GetMnemonic(target), inst.GetOperands(target)))
  
  # print the number of found patterns
  print("[+] {} matching patterns found in section '{}' from module: {}".format(len(offsets), section.GetName(), module.file.basename))

  # if we want to set breakpoints on the found patterns
  if opts.breakpoint:
    bp = 0
    print("[*] Writing breakpoints")
    for i in range(len(offsets)):
      address = lldb.SBAddress(start_addr + offsets[i], target)
      target.BreakpointCreateBySBAddress(address)
      bp += 1
    print("[+] Done. Set {} breakpoints".format(bp))



def find_pattern(blob, sequence):
  # check if blob is smaller than sequence
  if(len(blob) < len(sequence)):
    return

  offsets = []

  # find patterns
  for i in range(len(blob)):
    if blob[i] == sequence[0]:
      for j in range(1, len(sequence)):
        #if sequence[j] == '?':
        #  continue
        if blob[i+j] != sequence[j]:
          break
      else:
        offsets.append(i)

  return offsets

def get_values(section, pattern, module, result):
  section = module.FindSection(section)
  print("Section found: " + str(section))
  if not section:
    result.SetError("Couldn't find section: {}".format(section))
    return
  
  # 'little' endian is the default
  pattern_bytes = bytes([int(x, base=16) for x in pattern.split(' ')])
  return (pattern_bytes, section)

def generate_option_parser():
  parser = optparse.OptionParser(usage=help(False))

  parser.add_option("-s", "--section",
           action="store",
           default="__text",
           dest="section",
           help="Define the section to search for pattern")
  
  parser.add_option("-m", "--module",
           action="store",
           dest="module",
           default=get_main_module().file.basename,
           type="string",
           help="Define pattern endianness")
  
  parser.add_option("-b", "--breakpoint",
           action="store_true",
           default=False,
           dest="breakpoint",
           help="Set breakpoints on found patterns")
  
  parser.add_option("-p", "--pattern",
           action="store",
           dest="pattern",
           type="string",
           help="Ida byte pattern to search for")
  
  parser.add_option("-x", "--supress",
           action="store_true",
           dest="supress",
           default=False,
           help="Supress output")
  
  return parser

def get_main_module():
  return lldb.debugger.GetSelectedTarget().GetModuleAtIndex(0)