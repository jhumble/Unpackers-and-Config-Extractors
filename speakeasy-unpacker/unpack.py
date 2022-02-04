#!/usr/bin/env python3

import json
import types
import logging
import argparse
import os
import speakeasy
import pefile
import traceback
import tempfile
import sys
from pathlib import Path
from func_timeout import func_timeout, FunctionTimedOut
from speakeasy.winenv.api import api
import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.common as common
import speakeasy.winenv.arch as e_arch

repo_root = Path(os.path.realpath(__file__)).parent.parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)

from utils import *

def handle_import_func(self, dll, name):
    """
    Patched version of WinEmu.handle_import_func that tries to handle 
    Unsupported windows APIs by just returning NULL and handling stack 
    clean up by parsing a json file with FunctionName: argc mapping

    Forward imported functions to the corresponding handler (if any).
    """
    if not hasattr(self, 'win_functions'): # load the first time
        sys.path.append(os.path.dirname(os.path.realpath(__file__)))
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'winfuncs.json')) as fp:
            self.win_functions = json.load(fp)

    imp_api = '%s.%s' % (dll, name)
    oret = self.get_ret_address()
    mod, func_attrs = self.api.get_export_func_handler(dll, name)
    if not func_attrs:
        mod, func_attrs = self.normalize_import_miss(dll, name)

    if func_attrs:
        handler_name, func, argc, conv, ordinal = func_attrs

        if name.startswith('ordinal_'):
            name = handler_name

        argv = self.get_func_argv(conv, argc)
        imp_api = '%s.%s' % (dll, name)
        default_ctx = {'func_name': imp_api}

        self.hammer.handle_import_func(imp_api, conv, argc)
        hooks = self.get_api_hooks(dll, name)
        if hooks:
            from types import MethodType
            hooked_func = MethodType(func, mod)
            orig = lambda args: hooked_func(self, args, default_ctx) # noqa
            for hook in hooks:
                # each hook is called with the arguments, and only the last return value is
                # considered
                rv = hook.cb(self, imp_api, orig, argv)
        else:
            try:
                rv = self.api.call_api_func(mod, func, argv, ctx=default_ctx)
            except Exception as e:
                self.log_exception('0x%x: Error while calling API handler for %s:' %
                                   (oret, imp_api))
                error = self.get_error_info(str(e), self.get_pc(),
                                            traceback=traceback.format_exc())
                self.curr_run.error = error
                self.on_run_complete()
                return

        ret = self.get_ret_address()
        mm = self.get_address_map(ret)

        # Is this function being called from a dynamcially allocated memory segment?
        if mm and 'virtualalloc' in mm.get_tag().lower():
            self._dynamic_code_cb(self, ret, 0, {})

        # Log the API args and return value
        self.log_api(oret, imp_api, rv, argv)

        if not self.run_complete and ret == oret:
            self.do_call_return(argc, ret, rv, conv=conv)

    else:
        # See if a user defined a hook for this unsupported function
        hooks = self.get_api_hooks(dll, name)
        if hooks:
            # Since the function is unsupported, just call the most accurate defined hook
            hook = hooks[0]
            imp_api = '%s.%s' % (dll, name)

            if hook.call_conv is None:
                hook.call_conv = e_arch.CALL_CONV_STDCALL

            argv = self.get_func_argv(hook.call_conv, hook.argc)
            self.hammer.handle_import_func(imp_api, hook.call_conv, hook.argc)
            rv = hook.cb(self, imp_api, None, argv)
            ret = self.get_ret_address()
            self.log_api(ret, imp_api, rv, argv)
            self.do_call_return(hook.argc, ret, rv, conv=hook.call_conv)
            return
        else: #elif self.functions_always_exist:
            imp_api = '%s.%s' % (dll, name)
            try:
                argc = self.win_functions[name]
                self.logger.debug(f'Emulating unimplemented API: {imp_api}')
                conv = e_arch.CALL_CONV_STDCALL
                argv = self.get_func_argv(conv, argc)
                rv = 0
                ret = self.get_ret_address()
                self.log_api(ret, imp_api, rv, argv)
                self.do_call_return(argc, ret, rv, conv=conv)
                return
            except KeyError:
                self.logger.error(f'Unsupported API: {imp_api} without definition in winfuncs.json')
                #Let execution fall to the original unsupported api code below

    run = self.get_current_run()
    if run and run.get_api_count() > self.max_api_count:
        self.log_info("* Maximum number of API calls reached. Stopping current run.")
        run.error['type'] = 'max_api_count'
        run.error['count'] = self.max_api_count
        run.error['pc'] = hex(self.get_pc())
        run.error['last_api'] = imp_api
        self.on_run_complete()

class MonitoredSection:
    def __init__(self, section_type, start, size):
        self.section_type = section_type
        self.start = start
        self.size = size
        self.end = start+size
        self.written = 0
    def __repr__(self):
        return 'MonitoredSection: Type: {}, range: 0x{:08X}-0x{:08X} Bytes Written: 0x{:08X}'.format(self.section_type, self.start, self.start+self.size, self.written)
    def __str__(self):
        return self.__repr__()


class Unpacker(speakeasy.Speakeasy):

    def __init__(self, path, trace=False, trace_regs=False, dump_dir=None, monitor_execs=False, 
                 monitor_writes=False, output='debug', libcache=True, shellcode=False, 
                 function=None, carve=False, arch='x86', timeout=30):

        super(Unpacker, self).__init__(debug=False)
        self.path = path
        self.trace = trace
        self.trace_regs = trace_regs
        self.exec_sections = {}
        self.write_sections = {}
        self.monitor_writes = monitor_writes
        self.monitor_execs = monitor_execs
        self.tracing = False
        self.hooks = {}
        self.function = function
        self.carve = carve
        self.timeout = timeout



        if arch == 'x86':
            self.arch = e_arch.ARCH_X86
        elif arch in ('x64', 'amd64'):
            self.arch = e_arch.ARCH_AMD64
        else:
            raise Exception('Unsupported architecture: %s' % arch)

        if not dump_dir:
            self.dump_dir = tempfile.mkdtemp()
        else:
            self.dump_dir = dump_dir

        self.logger = logging.getLogger('Unpacker')
        handler = logging.FileHandler(os.path.join(self.dump_dir, 'unpacker.log'))
        handler.setLevel(logging.DEBUG)
        self.logger.addHandler(handler)

        
        try:
            self.pe = pefile.PE(self.path)
        except Exception as e:
            self.logger.info(f'{self.path} is not a PE file, assuming shellcode')
            self.pe = None


        if self.trace:
            self.start_trace()

    def hooked_mem_map(self, size, base=None, perms=common.PERM_MEM_RWX,
                tag=None, flags=0, shared=False, process=None):
        #Call the original to map the memory
        addr = self.original_mem_map(size, base, perms, tag, flags, shared, process)

        #bitwise AND fails /w None
        if not perms:
            perms = 0
        

        if self.monitor_writes and (perms & common.PERM_MEM_WRITE):
            self.watch_writes(addr, size)
        elif self.monitor_execs and (perms & common.PERM_MEM_EXEC):
            self.watch_execs(addr, size)

        if base:
            basestr = f'0x{base:08X}'
        else:
            basestr = 'NULL'

        #self.logger.debug(f'Memory Allocation - size: 0x{size:08X}, base: {basestr}, perms: {perms} => {addr:08X}')
        #print('\n'.join(traceback.format_stack()))
        return addr

    def hooked_mem_unmap(self, base, size):
        free = []
        for addr, section in self.write_sections.items():
            if base >= section.start and base < section.end and section.written >= 100: #TODO Make config item
                self.logger.info(f'Program attempting to free monitored and written-to section {section}. Dumping...')
                self.dump_section(section)
                free.append(addr)

        for addr in free:
            del self.write_sections[addr]
        print(self.write_sections[addr])

        return self.original_mem_unmap(base, size)
        
    """

    def start_trace(self):
        if not self.tracing:
            self.tracing = True
            count = [0]
            self.hook_code(Unpacker.trace_cb, count)
    """



    def trace_cb(self, address, size, count):
        rtn = '{:120s}'.format(disasm(self, self.disassembler, address, size, count))
        if self.trace_regs:
            try:
                if self.pointersize == 8:
                    rtn += dump_regs_x64(self, address, size)
                else:
                    rtn += dump_regs(self, address, size)
            except:
                self.logger.error(traceback.format_exc())
        self.logger.debug(rtn)
        count[0] += 1

    def dump(self):
        if self.dump_dir: 
            all_sections = list(self.exec_sections.values()) + list(self.write_sections.values())
            all_sections = [section for section in all_sections if section.written >= 10] # TODO make config item
            if len(all_sections) > 0:
                self.logger.info('Dumping monitored sections...')
                for section in all_sections:
                    self.logger.info(section)
                    self.dump_section(section)

    def dump_section(self, section, addr=None):
        try:
            os.makedirs(self.dump_dir, exist_ok=True)
            data = self.mem_read(section.start, section.size)
            if addr:
                path = os.path.join(self.dump_dir, '%s_%X-%X_%X' % (os.path.basename(self.path), section.start, section.end, addr))
            else:
                path = os.path.join(self.dump_dir, '%s_%X-%X_%X' % (os.path.basename(self.path), section.start, section.end, section.written))
            with open(path, 'wb') as fp:
                self.logger.info('Dumping 0x%X bytes to %s' % (section.size, path))
                fp.write(data)
            if self.carve:
                carved_pes = carve(data)
                if carved_pes:
                    self.logger.info(f'Found {len(carved_pes)} PE files in {section}')
                for pe in carved_pes:
                    path = os.path.join(self.dump_dir, f'{os.path.basename(self.path)}_{section.start+pe["offset"]:X}-{section.start+pe["offset"]+len(pe["data"]):X}.{pe["ext"]}')
                    self.logger.info(f'[!]\tDumping carved PE file to {path}')
                    with open(path, 'wb') as fp:
                        fp.write(pe["data"])
        except Exception as e:
            self.logger.error(traceback.format_exc())

    def monitor_section_execute(self, emu, address, size, ctx):
        # Watch address EIP in watched memory regions
        free = []
        for addr, section in self.exec_sections.items():
            try:
                if address >= section.start and address <= section.end:
                    self.logger.debug('Caught execution in monitored memory section 0x%X-0x%X. Current Instruction: %s' % 
                        (section.start, section.end, disasm(self, self.disassembler, address, size, instr_bytes=False)))
                    if self.dump_dir:
                        self.dump_section(section, address)
                    free.append(addr)
            except Exception as e:
                self.logger.info(traceback.format_exc())
                exit()
        for addr in free:
            del self.exec_sections[addr]
        return True

    def monitor_section_write(self, emu, access, address, size, value, ctx):
        #print(f'monitor_section_write({str(type(self))}, {access}, {address}, {size:08X}, {value}')
        for addr, section in self.write_sections.items():
            try:
                if address >= section.start and address <= section.end:
                    if section.written == 0:
                        self.logger.debug('Caught write to monitored memory section 0x%X-0x%X. Value: 0x%X' % 
                            (section.start, section.end, value))
                    section.written += size
            except Exception as e:
                self.logger.error(traceback.format_exc())
                exit()

    def watch_writes(self, addr, size):
        self.logger.debug('Watching 0x{:08X}-0x{:08X} for Write/Free'.format(addr, addr+size))
        section = MonitoredSection('write', addr, size)
        self.write_sections[addr] = section
        self.add_mem_write_hook(self.monitor_section_write, begin=section.start, end=section.end)

    def watch_execs(self, addr, size):
        self.logger.debug('Watching 0x{:08X}-0x{:08X} for Exec'.format(addr, addr+size))
        section = MonitoredSection('execution', addr, size)
        self.exec_sections[addr] = section
        if 'monitor_section_execute' not in self.hooks:
            self.hooks['monitor_section_execute'] = True
            self.add_code_hook(self.monitor_section_execute)

        
    # Emulate the binary from begin until @end, with timeout in @timeout and
    # number of emulated instructions in @count
    def run(self, begin=None, end=None, timeout=0, count=0):

        if self.pe:
            module = self.load_module(self.path)
        else:
            sc_addr = self.load_shellcode(self.path, self.arch)
            self.logger.info(f'Loaded shellcode at 0x{sc_addr:08X}')
        self.emu.timeout = self.timeout
        self.emu.max_api_count = 10**6

        #Hook the memory mapper so we can set up watches
        self.original_mem_map = self.emu.mem_map
        self.emu.mem_map = self.hooked_mem_map
        #TODO hook mem unmapper for dumping
        self.original_mem_unmap = self.emu.mem_unmap
        self.emu.mem_unmap = self.hooked_mem_unmap

        #self.emu.handle_import_func = handle_import_func
        self.emu.handle_import_func = types.MethodType(handle_import_func, self.emu)

        try:
            if self.pe and self.pe.is_dll():
                #DllMain should be called first
                try:
                    self.logger.info('Calling DllMain')
                    self.run_module(module)
                except Exception as e:
                    self.logger.error('DllMain crashed: {}'.format(e))
                    self.logger.warning(traceback.format_exc())
                # Set up some args for the export
                arg0 = 0x0
                arg1 = 0x1
                if self.function:
                    exports = [exp for exp in module.get_exports() if exp.name == self.function]
                else:
                    exports = module.get_exports()

                if not exports:
                    self.logger.error(f'Unable to find export {self.function}')
                    return
                for exp in exports:
                    try:
                        self.logger.info('Calling Export {}: {:08X}'.format(exp.name, exp.address))
                        self.call(exp.address, [arg0, arg1])
                    except Exception as e:
                        self.logger.error('Program Crashed: {}'.format(e))
                        self.logger.warning(traceback.format_exc())
                        continue
            elif self.pe:
                self.run_module(module)
            else: # assume shellcode
                # get size of shellcode rounded up to nearest 0x1000 bytes
                size = ((os.stat(self.path).st_size - 1) // 0x1000) + 0x1000
                self.watch_writes(sc_addr, size)
                self.run_shellcode(sc_addr, offset=0)

        except Exception as e:
            self.logger.error('Program Crashed: {}'.format(e))
            self.logger.error(traceback.format_exc())



def parse_args():
    usage = "unpack.py [OPTION]... [FILES]..."
    parser = argparse.ArgumentParser(description=usage)
    parser.add_argument("-r", "--reg", help="Dump register values with trace option", action='store_true', default=False)
    parser.add_argument("-t", "--trace", help="Enable full trace", action='store_true', default=False)
    parser.add_argument("-T", "--timeout", help="timeout", default=60, type=int)
    parser.add_argument("-d", "--dump", help="directory to dump memory regions and logs to", default=None)
    parser.add_argument("-e", "--dump-exec", help="dump dynamically allocated sections if code is executed from them", action='store_true', default=False)
    parser.add_argument("-w", "--dump-write", help="dump dynamically allocated sections if data is written to them", action='store_true', default=False)
    parser.add_argument("-E", "--export", help="If file is a dll run only dllmain and specified export, otherwise default to all exports", action='store', default=None)
    parser.add_argument("-S", "--strings", help="Report new strings from dumped files", default=False, action="store_true")
    parser.add_argument("-y", "--yara", help="Report new yara results from dumped files", default=False, action="store_true")
    parser.add_argument("-c", "--carve", help="Attempt to carve PE files from dumped sections", default=False, action="store_true")
    parser.add_argument("-a", "--arch", help="If input is shellcode, define architechture x86 or x64", default='x86', action="store")
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    parser.add_argument('files', nargs='*')
    return parser.parse_args()


if __name__ == "__main__":
    options = parse_args()
    configure_logger(options.verbose)

    for arg in options.files:
        for path in recursive_all_files(arg):
            unpacker = Unpacker(path=path, trace=options.trace, trace_regs=options.reg, dump_dir=options.dump, 
                                monitor_execs=options.dump_exec, monitor_writes=options.dump_write, 
                                function=options.export, carve=options.carve, arch=options.arch, timeout=options.timeout)
            try:
                unpacker.run()
            except Exception as e:
                unpacker.logger.error('Exception emulating {}:\n{}'.format(path, traceback.format_exc()))
            finally:
                unpacker.dump()
                            
