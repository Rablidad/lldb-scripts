import lldb
import shlex
import optparse
import utils

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
  module = None

  # parse the command line arguments
  opts = parse_arguments(arguments, result)

  # find target module
  for mod in utils.get_target().module_iter():
    if mod.file.basename.lower() == opts.module.lower():
      module = mod
      break

  matches = utils.scan_memory(opts.pattern, opts.section, module)
  if len(matches) <= 0:
    print("Pattern not found")
    return

  # disassemble the found patterns 
  if not opts.supress:
    for i in range(len(matches)):
      instructions = utils.get_target().ReadInstructions(matches[i], 1)
      for inst in instructions:
        print("[{}] + Found at ({} = {}): {} {}".format(i, matches[i]), inst.GetAddress(), inst.GetMnemonic(utils.get_target()), inst.GetOperands(utils.get_target()))
  
  # print the number of found patterns
  print("[+] {} matching patterns found in section '{}' from module: {}".format(len(matches), opts.section, module.file.basename))

  # if we want to set breakpoints on the found patterns
  if opts.breakpoint:
    bp = 0
    print("[*] Writing breakpoints")
    for i in range(len(matches)):
      utils.get_target().BreakpointCreateBySBAddress(matches[i])
      bp += 1
    print("[+] Done. Set {} breakpoints".format(bp))

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
           default=utils.get_main_module().file.basename,
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
  
  parser.add_option('-l', '--lazy', 
           action='store_true', 
           dest='lazy', 
           default=False, 
           help='Lazy search')
  
  return parser