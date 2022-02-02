#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
#
# LAU kaijern (xwings) <kj@qiling.io>
# NGUYEN Anh Quynh <aquynh@gmail.com>
# DING tianZe (D1iv3) <dddliv3@gmail.com>
# SUN bowen (w1tcher) <w1tcher.bupt@gmail.com>
# CHEN huitao (null) <null@qiling.io>
# YU tong (sp1ke) <spikeinhouse@gmail.com>

import sys
sys.path.insert(0, "..")
from utils import *

del sys.path[0]

sys.tracebacklimit = 0

import logging
import argparse
import os
import speakeasy
import pefile
import traceback
import tempfile
from func_timeout import func_timeout, FunctionTimedOut
from utils import carve, configure_logger, stdout_redirected

from speakeasy.winenv.api import api
import speakeasy.winenv.defs.windows.windows as windefs

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

    def __init__(self, path, trace=False, trace_regs=False, dump_dir=None, monitor_execs=False, monitor_writes=False, output='debug', libcache=True, shellcode=False, function=None, carve=False):
        super(Unpacker, self).__init__(debug=False)
        self.path = path
        self.trace = trace
        self.trace_regs = trace_regs
        self.monitor_execution_sections = []
        self.monitor_write_sections = []
        self.monitor_writes = monitor_writes
        self.monitor_execs = monitor_execs
        self.tracing = False
        self.hooks = {}
        self.function = function
        self.carve = carve

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
            print(e)

        if self.monitor_execs:
            if 'VirtualProtect' not in self.hooks:
                self.hooks['VirtualProtect'] = True
                self.add_api_hook(self.hook_VirtualProtect, 'kernel32', 'VirtualProtect')
        if self.monitor_writes:
            if 'VirtualAlloc' not in self.hooks:
                self.hooks['VirtualAlloc'] = True
                self.add_api_hook(self.hook_VirtualAlloc, 'kernel32', 'VirtualAlloc')
            if 'HeapAlloc' not in self.hooks:
                self.hooks['HeapAlloc'] = True
                #self.set_api('HeapAlloc', Unpacker.hook_HeapAlloc)
            if 'RtlHeapAlloc' not in self.hooks:
                self.hooks['HeapAlloc'] = True
                self.add_api_hook(self.hook_RtlAllocateHeap, 'ntdll', 'RtlAllocateHeap')
            #if self.shellcoder:
                #TODO should use self.entry_point but it's not yet loaded at this point
                #self.watch_writes(0x00040000, len(self.shellcoder))
            else:
                self.watch_writes(self.loader.pe_image_address, self.loader.pe_image_address_size)
        if self.trace:
            self.start_trace()

    def hook_RtlAllocateHeap(self, emu, api_name, func, params):
        '''
            NTSYSAPI PVOID RtlAllocateHeap(
              [in]           PVOID  HeapHandle,
              [in, optional] ULONG  Flags,
              [in]           SIZE_T Size
            );
        '''

        HeapHandle, Flags, Size = params
        chunk = func(params)
        
        if chunk:
            emu.set_last_error(windefs.ERROR_SUCCESS)
        if self.monitor_writes:
            self.watch_writes(chunk, Size)

        return chunk

    def hook_VirtualAlloc(self, emu, api_name, func, params):
        '''
            LPVOID VirtualAlloc(
              [in, optional] LPVOID lpAddress,
              [in]           SIZE_T dwSize,
              [in]           DWORD  flAllocationType,
              [in]           DWORD  flProtect
            );
        '''
        lpAddress, dwSize, flAllocationType, flProtect = params
        ret = func(params)

        if flProtect & 0x40 and self.monitor_execs:
            self.watch_execs(addr, params['dwSize'])
        elif flProtect & 0x04 and self.monitor_writes:
            self.watch_writes(addr, params['dwSize'])
        return addr


    def hook_HeapAlloc(self, address, params):
        '''
            DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
              [in] HANDLE hHeap,
              [in] DWORD  dwFlags,
              [in] SIZE_T dwBytes
            );
        '''
        hHeap, dwFlags, dwBytes = params

        ret = func(params)

        self.watch_writes(addr, params['dwSize'])
        return ret

    def hook_VirtualProtect(self, emu, api_name, func, params):
        '''
            BOOL VirtualProtect(
              [in]  LPVOID lpAddress,
              [in]  SIZE_T dwSize,
              [in]  DWORD  flNewProtect,
              [out] PDWORD lpflOldProtect
            );
        '''
        lpAddress, dwSize, flNewProtect, lpflOldProtect = params
        mm = self.get_address_map(lpAddress)
        self.logger.debug('VirtualProtect Hook. Searching for chunk 0x%X...' % (params['lpAddress']))
        if not mm:
            # TODO error handling here and in k32
            self.logger.debug('chunk not found')
            return 0
        
        ret = func(params)

        self.logger.info('[+]\tMemory section found: 0x%X-0x%X. Watching for execution in range.' % (start, start+size))
        self.monitor_execution_sections.append(MonitoredSection('execution', start, size))
        if 'monitor_section_execute' not in self.hooks:
            self.logger.debug('Setting exec hook')
            self.hooks['monitor_section_execute'] = True
            self.hook_code(Unpacker.monitor_section_execute)
        else:
            self.logger.debug('Hook already set. Hooks: {}'.format(self.hooks))
        return 1

    def hook_VirtualFree(self, emu, api_name, func, params):
        '''
            BOOL VirtualFree(
              [in] LPVOID lpAddress,
              [in] SIZE_T dwSize,
              [in] DWORD  dwFreeType
            );
        '''
        lpAddress, dwSize, dwFreeType = params

        for i in range(0, len(self.monitor_write_sections)):
            section = self.monitor_write_sections[i]
            if lpAddress >= section.start and lpAddress < section.end and section.written >= 10: #TODO Make config item
                self.logger.info('Program attempting to free monitored and written-to section. Dumping...')
                self.dump_section(section)
                del self.monitor_write_sections[i]
        return func(params)


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
            all_sections = self.monitor_execution_sections + [section for section in self.monitor_write_sections if section.written >= 10] # TODO make config item
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

    def monitor_section_execute(self, address, size):
        # Watch address EIP in watched memory regions
        for i in range(0, len(self.monitor_execution_sections)):
            section = self.monitor_execution_sections[i]
            try:
                if address >= section.start and address <= section.end:
                    self.logger.debug('Caught execution in monitored memory section 0x%X-0x%X. Current Instruction: %s' % 
                        (section.start, section.end, disasm(self, self.disassembler, address, size, instr_bytes=False)))
                    if self.dump_dir:
                        self.dump_section(section, address)
                    del self.monitor_execution_sections[i]                
            except Exception as e:
                self.logger.info(traceback.format_exc())
                exit()

    def monitor_section_write(self, access, address, size, value, ctx):
        #print(f'monitor_section_write({str(type(self))}, {access}, {address}, {size:08X}, {value}')
        for section in self.monitor_write_sections:
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
        self.monitor_write_sections.append(section) 
        self.add_mem_write_hook(Unpacker.monitor_section_write, begin=section.start, end=section.end)
        self.add_api_hook(self.hook_VirtualFree, 'kernel32', 'VirtualFree')

    def watch_execs(self, addr, size):
        self.logger.debug('Watching 0x{:08X}-0x{:08X} for Exec'.format(addr, addr+size))
        section = MonitoredSection('execution', addr, size)
        self.monitor_execution_sections.append(section) 
        if 'monitor_section_execute' not in self.hooks:
            self.hooks['monitor_section_execute'] = True
            self.hook_code(Unpacker.monitor_section_execute)

        
    # Emulate the binary from begin until @end, with timeout in @timeout and
    # number of emulated instructions in @count
    def run(self, begin=None, end=None, timeout=0, count=0):
        # replace the original entry point, exit point, timeout and count
        self.timeout = timeout
        self.count = count

        module = self.load_module(self.path)
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
                pass
                # run exe
            else: # assume shellcode
                #TODO - watch section sc is mapped into (assumed rwx)
                #self.watch_writes(0x00040000, len(self.shellcoder))
                self.run_module(module)
        except Exception as e:
            self.logger.error('Program Crashed: {}'.format(e))
            self.logger.error(traceback.format_exc())
        finally:
            self.dump()

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
                                function=options.export, carve=options.carve)
            try:
                func_timeout(options.timeout, unpacker.run)
            except FunctionTimedOut:
                unpacker.logger.info('Emulation timed out after {}s'.format(options.timeout))
            except Exception as e:
                unpacker.logger.error('Exception emulating {}:\n{}'.format(path, traceback.format_exc()))
            finally:
                unpacker.dump()
                            
