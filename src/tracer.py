import lldb
from utils import *
import json
import time

args = None

def onTargetFunctionHit(frame, bp_loc, internal_dict):
    oldAsync = lldb.debugger.GetAsync()
    lldb.debugger.SetAsync(False)
    output = []
    
    if args:
        thread = frame.GetThread()
        num_frames = thread.GetNumFrames()
        if num_frames > 1:
            target_frame = thread.GetFrameAtIndex(1)
            while target_frame != thread.GetFrameAtIndex(0):
                pc = frame.GetPCAddress()
                if pc.IsValid():
                    inst = get_target().ReadInstructions(pc, 1)
                    if inst:
                        inst = inst[0]
                        if inst.IsValid():
                            current_pc = {
                                "registers": get_registers(frame),
                                "pc": pc.GetLoadAddress(get_target()),
                                "mnemonic": inst.GetMnemonic(get_target()),
                                "operands": inst.GetOperands(get_target())
                            }
                            output.append(current_pc)
                            
                thread.StepInstruction(not args.step_into)
    
    # write result to file 
    with open("lldb_trace.{}.json".format(int(time.time())), "w") as f:
        f.write(json.dumps(output))
        
    lldb.debugger.SetAsync(oldAsync)
    get_process().Continue()


def main(debugger, arguments, result, internal_dict):
    opts = parse_arguments(arguments, result)
    
    global args
    args = opts
    
    if opts.name:
        create_bp_by_name(get_target(), opts.name, 'tracer.onTargetFunctionHit', opts.condition if opts.condition else None)
    else:
        try:
            address = lldb.SBAddress(int(opts.address, 16), get_target())
            create_bp_by_address(get_target(), address, 'tracer.onTargetFunctionHit', opts.condition if opts.condition else None)
        except:
            result.SetError("[-] error: address is invalid")
    
    # continue process
    get_process().Continue()

def parse_arguments(arguments, result):
    # unpack arguments
    args = shlex.split(arguments)
    parser = generate_option_parser()

    try:
        opts, _ = parser.parse_args(args)
    except:
        result.SetError(parser.usage)
        return
    
    if not opts.address and not opts.name:
        result.SetError("missing address or name to set a breakpoint on.\n{}".format(parser.usage))
        return
        
    return opts

def help(output=True):
    usage = "Usage: tracetarget (-n <name> | -a <address>) [-s] [-v] [-c <count>] [-x]"
    if output:
      print(usage)
    return usage

def generate_option_parser():
    parser = optparse.OptionParser(usage=help(False))
    
    parser.add_option("-n", "--name",
        action="store",
        dest="name",
        help="The target function's name to set a breakpoint on")
    
    parser.add_option("-a", "--address",
        action="store",
        dest="address",
        help="The target function's name to set a breakpoint on")
    
    parser.add_option("-x", "--condition",
        action="store",
        dest="condition",
        help="The condition to set on the breakpoint")           
    
    parser.add_option("-s", "--step-into",
        action="store_true",
        dest="step_into",
        default=False,
        help="Step into and trace into function calls")
    
    parser.add_option("-v", "--verbose",
        action="store_true",
        dest="supress",
        default=False,
        help="Verbose output")

    parser.add_option("-c", "--count",
        action="store",
        dest="count",
        default=0,
        help="The max number of instructions to trace")
    
    return parser


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f tracer.main tracetarget')