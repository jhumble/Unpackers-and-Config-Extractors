#!/usr/bin/env python3

import yaml
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
import re
from capstone import *
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

    Also keeps track of how many times each api has been called and stops
    logging after a set limit

    Forward imported functions to the corresponding handler (if any).
    """
    if not hasattr(self, 'win_functions'): # load the first time
        sys.path.append(os.path.dirname(os.path.realpath(__file__)))
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'winfuncs.json')) as fp:
            self.win_functions = json.load(fp)

    imp_api = '%s.%s' % (dll, name)
    try:
        self.api_counts[imp_api] += 1
    except:
        self.api_counts[imp_api] = 1

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
        if imp_api not in self.api_counts:
            self.api_counts[imp_api] = 1

        if self.api_counts[imp_api] < self.api_log_max:
            self.log_api(oret, imp_api, rv, argv)
            self.api_counts[imp_api] += 1
            if self.api_counts[imp_api] == self.api_log_max:
                self.logger.warning(f'Hit max log count of {self.api_log_max} for {imp_api}, supressing further call logs')

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
            # Log the API args and return value
            if self.api_counts[imp_api] < self.api_log_max:
                self.log_api(oret, imp_api, rv, argv)
                self.api_counts[imp_api] += 1
                if self.api_counts[imp_api] == self.api_log_max:
                    self.logger.warning(f'Hit max log count of {self.api_log_max} for {imp_api}, supressing further call logs')
            self.do_call_return(hook.argc, ret, rv, conv=hook.call_conv)
            return
        else: #elif self.exports_always_exist:
            imp_api = '%s.%s' % (dll, name)
            try:
                argc = self.win_functions[name]
                self.logger.debug(f'Emulating unimplemented API: {imp_api} with argc = {argc}')
                conv = e_arch.CALL_CONV_STDCALL
                argv = self.get_func_argv(conv, argc)
                rv = 0
                ret = self.get_ret_address()
                self.log_api(ret, imp_api, rv, argv)
                self.do_call_return(argc, ret, rv, conv=conv)
                return
            except KeyError:
                self.logger.error(f'Unsupported API: {imp_api} without definition in winfuncs.json')

    run = self.get_current_run()
    if run and run.get_api_count() > self.max_api_count:
        self.log_info("* Maximum number of API calls reached. Stopping current run.")
        run.error['type'] = 'max_api_count'
        run.error['count'] = self.max_api_count
        run.error['pc'] = hex(self.get_pc())
        run.error['last_api'] = imp_api
        self.on_run_complete()

class MonitoredSection:
    def __init__(self, section_type, start, size, scan_thresholds=[]):
        self.section_type = section_type
        self.start = start
        self.size = size
        self.end = start+size
        self.written = 0
        self.scan_thresholds = scan_thresholds
        self.dump = False
        self.strings = []
        self.yara_matches = []

    def __repr__(self):
        return 'MonitoredSection: Type: {}, range: 0x{:08X}-0x{:08X} Bytes Written: 0x{:08X}'.format(self.section_type, self.start, self.start+self.size, self.written)
    def __str__(self):
        return self.__repr__()
    


class Unpacker(speakeasy.Speakeasy):

    def __init__(self, path, config_path, **kwargs):


        super(Unpacker, self).__init__(debug=False)
    
        self.path = path
        self.exec_sections = {}
        self.write_sections = {}
        self.tracing = False
        self.trace_instr_count = 0

        self.logger = logging.getLogger('Unpacker')
        self.code_hook_active = False

        with open(self.path, 'rb') as fp:
            data = fp.read()

        #for prepatching bumblebee busyloop. Definitely need to find a better way to insert this sort of logic
        self.patch()

        try:
            self.pe = pefile.PE(data=data)
        except Exception as e:
            self.logger.info(f'{self.path} is not a PE file, assuming shellcode')
            self.pe = None

        self.load_config(config_path, **kwargs)
        if self.speakeasy_config:
            with open(self.speakeasy_config, 'r') as f:
                self.config = json.load(f)

        if self.arch == 'x86':
            self.arch = e_arch.ARCH_X86
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        elif self.arch in ('x64', 'amd64'):
            self.arch = e_arch.ARCH_AMD64
            self.disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            raise Exception('Unsupported architecture: %s' % arch)

        if not self.dump_dir:
            self.dump_dir = tempfile.mkdtemp()
        os.makedirs(self.dump_dir, exist_ok=True)

        if self.yara_dir:
            self.yara_rules = build_rules(self.yara_dir)
            self.initial_matches = set([match.rule for match in self.yara_rules.match(data=data)])
            self.logger.info(f'Initial yara matches: {self.initial_matches}')
            self.new_matches = []
        else:
            self.yara_rules = None

        if self.strings:
            candidates = [os.path.join(os.getcwd(), 'strings.yar'), os.path.join(os.path.join(sys.path[0], 'strings.yar'))]
            for candidate in candidates:
                if os.path.exists(candidate):
                    self.strings_rule = build_rules('strings.yar') 
                    break
            if not hasattr(self, 'strings_rule'):
                self.logger.error(f'Failed to locate strings.yar. Looked in {candidates}')
                self.strings = False
            else:
                matches = self.strings_rule.match(data=data)
                self.initial_strings = self.parse_string_matches(matches)
                self.dynamic_strings = []
            

        log_path = os.path.join(self.dump_dir, 'unpacker.log')
        handler = logging.FileHandler(log_path)
        handler.setLevel(logging.DEBUG)
        self.logger.addHandler(handler)
        self.logger.warning(f'File log: {log_path}')

        if self.trace:
            self.start_trace()

    def patch(self):
        from tempfile import mkstemp
        _, temppath = mkstemp()
        with open(self.path, 'rb') as fp:
            data = fp.read() 
        #busyloop = re.compile(rb'\x99\x41?\xF7[\x78-\x7F\xB8-\xBF\xF8-\xFF].{,48}\x99\x41?\xF7[\x78-\x7F\xB8-\xBF\xF8-\xFF].{,192}\x3B.{,8}\x0F\x8C....', re.DOTALL)
        busyloop = re.compile(rb'(\x48\x8B[\xC4\xCC\xD4\xDC\xEC\xF4\xFC]|\x48\x89[\x44\x4C\x54\x5C\x6C\x74\x7C]\x24[\x08\x10\x18\x20\x28\x30]).{,2000}?\x99\x41?\xF7[\x78-\x7F\xB8-\xBF\xF8-\xFF].{,64}\x99\x41?\xF7[\x78-\x7F\xB8-\xBF\xF8-\xFF]', re.DOTALL)
        """
        00007FFCB4D808B3 | 45:3B8D A0060000         | cmp r9d,dword ptr ds:[r13+6A0]                                                           | r13+6A0:"h9W"
        00007FFCB4D808BA | 0F8C 4DFEFFFF            | jl 365cd47be647a89c679eb9effed479d147e16fed036e7a932599a6afd58352e6_p31.7FFCB4D8070D     |
        """
        busyloop = re.compile(rb'\x99\x41?\xF7[\x78-\x7F\xB8-\xBF\xF8-\xFF].{,64}\x99\x41?\xF7[\x78-\x7F\xB8-\xBF\xF8-\xFF].{,512}?\x45\x3B[\x88-\x8F].{,8}\x0F\x8C....', re.DOTALL)
        min_size = 10**9
        smallest_match = None
        for match in busyloop.finditer(data):
            if len(match.group()) < min_size:
                min_size = len(match.group())
                smallest_match = match
        #if smallest_match:
            #patch_loc = match.start()
            patched = re.sub(rb'\x0F\x8C....', b'\x90'*6, data[match.start():match.end()])
            #patch_loc = match.start()+len(match.group()) - 6
            #self.logger.info(f'Patching conditional jump at 0x{patch_loc:08X} from {hexlify(data[patch_loc-8:patch_loc+8])} to RET')
            self.logger.info(f'Patching conditional jump at 0x{match.start():08X} from {hexlify(data[match.start():match.end()])} to {hexlify(patched)}')
            with open(temppath, 'wb') as fp:
                #fp.write(data[:patch_loc] + b'\x90'*6 + data[patch_loc+6:])
                fp.write(data[:match.start()] + patched + data[match.end():])
            self.path = temppath
            return 
        else:
            self.logger.error('Failed to find patch location for Bumblebee Crypter')


    def disasm(self, address: int, size: int):
        buf = self.mem_read(address, size)
        try:
            for i in self.disassembler.disasm(buf, address):
                return "{:08X}\t{:08X}: {:24s} {:10s} {:16s}".format(self.trace_instr_count, i.address, spaced_hex(buf), i.mnemonic,
                                                                     i.op_str)
        except:
            import traceback
            print(traceback.format_exc())

    def parse_string_matches(self, matches):
        if matches: 
            return substring_sieve([match[2] for match in matches[0].strings])
        else:
            return []

    def load_config(self, config_path=None, **kwargs):
        """ 
            Ensure required config options are present where mandatory
            and set defaults for those that are not mandatory
            Precedence: CLI > config > defaults
        """
        candidates = [os.path.join(os.getcwd(), 'config.yml'), os.path.join(os.path.join(sys.path[0], 'config.yml'))]
        print(candidates)
        if config_path:
            candidates = [config_path]
        for candidate in candidates:
            self.logger.debug(f'Trying to load config from {candidate}')
            try:
                with open(candidate, 'r') as fp:
                    self.unpacker_config = yaml.safe_load(fp)
                self.unpacker_config_file = candidate
                self.unpacker_config_dir = os.path.dirname(os.path.abspath(candidate))
                break
            except Exception as e:
                self.logger.info('Failed to load %s: %s' % (candidate, e))
                pass
        
        #handle arch differently, since if the file is a PE file we can just get the architecture type from it
        if self.pe and not kwargs.get('arch'):
            arch = self.pe.OPTIONAL_HEADER.Magic
            if arch == 0x10b:
                arch_default = 'x86'
            elif arch == 0x20B:
                arch_default = 'x64'
        else:
            arch_default = 'x86'

        # If these options are defined via cli args, overwrite values from config
        DEFAULTS = {'yara_dir': None, 'trace': False, 'trace_regs': False, 'arch': arch_default,
                    'timeout': 30, 'unsupported_api': None, 'api_max': 100, 'carve_pe': True, 'speakeasy_config': None,
                    'monitor_writes': True, 'min_write': 10, 'monitor_execs': False, 'dump_dir': '/tmp',
                    'export': None, 'scan_thresholds': [], 'strings': True, 'dump_all': False, 'breakpoint': []}

        for key, default in DEFAULTS.items():
            if not (kwargs.get(key, None) or key in self.unpacker_config):
                self.logger.warning(f'{key} not defined in {self.unpacker_config_file} and not provided via args. Defaulting to {default}')
                setattr(self, key, default)
            elif kwargs.get(key, None):
                self.logger.debug(f'self.{key} = {kwargs[key]} from CLI')
                setattr(self, key, kwargs[key])
            else:
                self.logger.debug(f'self.{key} = {self.unpacker_config[key]} from CONFIG')
                setattr(self, key, self.unpacker_config[key])


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
                self.logger.debug(f'Program attempting to free monitored and written-to section {section}. Dumping...')
                self.dump_section(section)
                free.append(addr)

        for addr in free:
            del self.write_sections[addr]

        try:
            return self.original_mem_unmap(base, size)
        except:
            return 
        

    def start_trace(self):
        if not self.tracing:
            self.tracing = True
            self.add_code_hook(self.trace_cb)

    def trace_cb(self, emu, address, size, ctx):

        rtn = '{:120s}'.format(self.disasm(address, size))
        if self.trace_regs:
            try:
                rtn += dump_regs(emu)
            except:
                self.logger.error(traceback.format_exc())
        self.logger.info(rtn)
        self.trace_instr_count +=1


    def scan(self, section):
        data = self.mem_read(section.start, section.size)
        if self.yara_rules:
            matches = self.yara_rules.match(data=data)
            matches = [match for match in self.yara_rules.match(data=data) if match.rule not in self.initial_matches] 
            if matches:
                self.logger.warning(f'New yara matches found in {section}: {matches}')
                self.new_matches += matches
                section.yara_matches += matches
        if self.strings:
            matches = self.strings_rule.match(data=data)
            if matches:
                matches = self.parse_string_matches(matches)
                new = []
                for string in substring_sieve(self.initial_strings, matches):
                    try:
                        new.append(string.decode('utf-16le').encode('ascii'))
                    except:
                        new.append(string)
                self.logger.debug(f'New strings found in {section}: {new}')
                self.dynamic_strings += new
                section.strings += new
        return data
                

    def dump(self):
        if self.dump_dir: 
            all_sections = list(self.exec_sections.values()) + list(self.write_sections.values())
            all_sections = [section for section in all_sections if section.written >= 10] # TODO make config item
            if len(all_sections) > 0:
                self.logger.info('Dumping monitored sections...')
                for section in all_sections:
                    self.dump_section(section)
        if self.strings:
            print('Dynamic Strings:')
            self.dynamic_strings = list(set(self.dynamic_strings))
            for string in self.dynamic_strings: 
                try:
                    print(f'\t{string.decode()}')
                except:
                    print(f'\t{string}')
        if self.yara_rules:
            print('Dynamic Yara Matches:')
            for match in set(self.new_matches):
                print(f'\t{match.rule}')


    def dump_section(self, section, addr=None):

        data = self.scan(section)

        found_pe = False
        if self.carve_pe:
            carved_pes = carve(data)
            if carved_pes:
                self.logger.info(f'Found {len(carved_pes)} PE files in {section}')
            for pe in carved_pes:
                path = os.path.join(self.dump_dir, f'{os.path.basename(self.path)}_{section.start+pe["offset"]:X}-{section.start+pe["offset"]+len(pe["data"]):X}.{pe["ext"]}')
                self.logger.info(f'[!]\tDumping carved PE file to {path}')
                found_pe = True
                with open(path, 'wb') as fp:
                    fp.write(pe["data"])
        # if a PE was carved always dump this mem region
        if not found_pe:
            if section.written < self.min_write:
                return
            if not self.dump_all and not (section.strings or section.yara_matches):
                self.logger.debug(f'Skip dumping {section} (no matches or new strings)')
                return
            if not self.dump_all and section.written < self.min_write:
                self.logger.debug(f'Skip dumping {section} Bytes written < minimum:  {section.written} < {self.min_write}')
                return 
        try:

            if addr:
                path = os.path.join(self.dump_dir, '%s_%X-%X_%X' % (os.path.basename(self.path), section.start, section.end, addr))
            else:
                path = os.path.join(self.dump_dir, '%s_%X-%X_%X' % (os.path.basename(self.path), section.start, section.end, section.written))
            with open(path, 'wb') as fp:
                self.logger.info('Dumping 0x%X bytes to %s' % (section.size, path))
                fp.write(data)

        except Exception as e:
            self.logger.error(traceback.format_exc())

    def monitor_section_execute(self, emu, address, size, ctx):
        # Watch address EIP in watched memory regions
        free = []
        for addr, section in self.exec_sections.items():
            try:
                if address >= section.start and address <= section.end:
                    self.logger.info('Caught execution in monitored memory section 0x%X-0x%X. Current Instruction: %s' % 
                        (section.start, section.end, self.disasm(address, size)))
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
                if section.scan_thresholds:
                    progress = section.written/section.size
                    surpassed = [x for x in section.scan_thresholds if x <= progress]
                    section.scan_thresholds = list(set(section.scan_thresholds) - set(surpassed))
                    if surpassed:
                        self.logger.debug(f'{section} {progress*100}% written. Passed scan thesholds: {surpassed}. Scanning...')
                        self.scan(section)
            except Exception as e:
                self.logger.error(traceback.format_exc())
                exit()

    def watch_writes(self, addr, size):
        self.logger.debug('Watching 0x{:08X}-0x{:08X} for Write/Free'.format(addr, addr+size))
        section = MonitoredSection('write', addr, size, self.scan_thresholds)
        self.write_sections[addr] = section
        self.add_mem_write_hook(self.monitor_section_write, begin=section.start, end=section.end)

    def watch_execs(self, addr, size):
        self.logger.debug('Watching 0x{:08X}-0x{:08X} for Exec'.format(addr, addr+size))
        section = MonitoredSection('execution', addr, size, self.scan_thresholds)
        self.exec_sections[addr] = section
        if not self.code_hook_active:
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
        self.emu.api_counts = {}
        self.emu.api_log_max = 100
 
        #Hook the memory mapper so we can set up watches
        self.original_mem_map = self.emu.mem_map
        self.emu.mem_map = self.hooked_mem_map
        #Hook mem unmapper
        self.original_mem_unmap = self.emu.mem_unmap
        self.emu.mem_unmap = self.hooked_mem_unmap

        #Hook api function handler
        self.emu.handle_import_func = types.MethodType(handle_import_func, self.emu)
        for bp in self.breakpoint:
            self.logger.info(f'Setting exec watch on 0x{bp:016X}')
            self.watch_execs(bp, 1)
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
                args = [0,1,0,0,0,0,0,0]
                if self.export:
                    exports = [exp for exp in module.get_exports() if exp.name == self.export]
                else:
                    exports = module.get_exports()

                if not exports:
                    self.logger.error(f'Unable to find export {self.export}')
                    return
                for exp in exports:
                    try:
                        self.logger.info('Calling Export {}: {:08X}'.format(exp.name, exp.address))
                        self.call(exp.address, args)
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
    parser.add_argument("-C", "--config", action="store", default=None,
      help="config file. Defaults to config.yml in same dir as unpack.py")
    parser.add_argument("-r", "--reg", dest='trace_regs', help="Dump register values with trace option", action='store_true', default=False)
    parser.add_argument("-t", "--trace", help="Enable full trace", action='store_true', default=False)
    parser.add_argument("-T", "--timeout", help="timeout", default=None, type=int)
    parser.add_argument("-b", "--breakpoint", help="breakpoint", default=[], nargs='*', type=str)
    parser.add_argument("-d", "--dump", dest='dump_dir', help="directory to dump memory regions and logs to", default=None)
    parser.add_argument("-e", "--monitor-dumps", dest='monitor_execs', help="dump dynamically allocated sections if code is executed from them", action='store_true', default=False)
    parser.add_argument("-E", "--export", help="If file is a dll run only dllmain and specified export, otherwise default to all exports", action='store', default=None)
    parser.add_argument("-S", "--strings", help="Report new strings from dumped files", default=False, action="store_true")
    parser.add_argument("-s", "--speakeasy-config", dest='speakeasy_config', help="Speakeasy config file", default=False, action="store")
    parser.add_argument("-y", "--yara", help="Report new yara results from dumped files", default=False, action="store_true")
    parser.add_argument("-c", "--carve", dest='carve_pe', help="Attempt to carve PE files from dumped sections", default=False, action="store_true")
    parser.add_argument("-a", "--arch", help="If input is shellcode, define architechture x86 or x64", default=None, action="store")
    parser.add_argument("-D", "--dump-matched", dest="dump_all", help="Only dump memory sections containing new strings or yara matches", default=False, action="store_true")
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    parser.add_argument('files', nargs='*')
    return parser.parse_args()


if __name__ == "__main__":
    options = parse_args()
    # Auto parse breakpoint args as hex/dec
    print(options.breakpoint)
    options.breakpoint = [int(x,0) for x in options.breakpoint]

    configure_logger(options.verbose)
    for arg in options.files:
        for path in recursive_all_files(arg):
            unpacker = Unpacker(path=path, config_path=options.config, **vars(options))
            try:
                unpacker.run()
            except Exception as e:
                unpacker.logger.error('Exception emulating {}:\n{}'.format(path, traceback.format_exc()))
            finally:
                unpacker.dump()
                            
