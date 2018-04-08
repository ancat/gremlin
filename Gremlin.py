from memutils import read_process_memory, parse_maps_file, iovec, user_regs_struct
from elftools.elf.elffile import ELFFile

class Gremlin:
    def __init__(self, pid):
        self.pid = pid

        self.libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
        self.libc.ptrace.restype = ctypes.c_uint64
        self.libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]

        self.map_file = '/proc/{}/maps'.format(pid)
        self.exe_path = '/proc/{}/exe'.format(pid)
        self.executable = os.path.realpath(self.exe_path)

        self.addr_to_sym = {}
        self.sym_to_addr = {}
        self.elf = None
        self.maps = None

    def load_maps(self):
        handle = open(self.map_file, 'r')
        output = []
        for line in handle:
            line = line.strip()
            parts = line.split()
            (addr_start, addr_end) = map(lambda x: int(x, 16), parts[0].split('-'))
            permissions = parts[1]
            offset = int(parts[2], 16)
            device_id = parts[3]
            inode = parts[4]
            map_name = parts[5] if len(parts) > 5 else ''

            mapping = {
                'addr_start':  addr_start,
                'addr_end':    addr_end,
                'size':        addr_end - addr_start,
                'permissions': permissions,
                'offset':      offset,
                'device_id':   device_id,
                'inode':       inode,
                'map_name':    map_name
            }
            output.append(mapping)

            libc_map = proc.maps

        handle.close()
        self.maps = output

    def load_elf(self):
        handle = open(self.executable, 'r')
        self.elf = ELFFile(handle)
        #self.pltgot = self.elf.get_section_by_name('.plt.got').header
        self.pltgot = self.elf.get_section_by_name('.got.plt').header

        symbol_names = \
                    map(
                    lambda x: x.name,
                    self.elf.get_section_by_name('.dynsym').iter_symbols()
                )


        relocations = \
            list(self.elf.get_section_by_name('.rela.plt').iter_relocations())

        self.addr_to_sym = {}
        self.sym_to_addr = {}
        for rel in relocations:
            try:
                self.addr_to_sym[rel['r_offset']] = symbol_names[rel['r_info_sym']]
                self.sym_to_addr[symbol_names[rel['r_info_sym']]] = rel['r_offset']
            except IndexError:
                addr_to_sym[rel['r_offset']] = None

    def lookup_symbol(self, symbol_name):
        if not self.sym_to_addr:
            raise ValueError("ELF Not Processed, call load_elf first")

        if symbol_name in self.sym_to_addr:
            return self.sym_to_addr[symbol_name]

        return None

    def lookup_address(self, address):
        if not self.addr_to_sym:
            raise ValueError("ELF Not Processed, call load_elf first")

        if address in self.addr_to_sym:
            return self.addr_to_sym[address]

        return None

    def read_process_memory(self, address, size):
        bytes_buffer = ctypes.create_string_buffer('\x00'*size)
        local_iovec  = iovec(ctypes.cast(ctypes.byref(bytes_buffer), ctypes.c_void_p), size)
        remote_iovec = iovec(ctypes.c_void_p(address), size)
        bytes_transferred = self.libc.process_vm_readv(
            self.pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0
        )

        return bytes_buffer.raw

    def write_process_memory(self, address, size, data):
        bytes_buffer = ctypes.create_string_buffer('\x00'*size)
        bytes_buffer.raw = data
        local_iovec  = iovec(ctypes.cast(ctypes.byref(bytes_buffer), ctypes.c_void_p), size)
        remote_iovec = iovec(ctypes.c_void_p(address), size)
        bytes_transferred = self.libc.process_vm_writev(
            self.pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0
        )

        return bytes_transferred

    def ptrace_attach(self):
        return libc.ptrace(PTRACE_ATTACH, self.pid, None, None)

    def ptrace_detach(self):
        return libc.ptrace(PTRACE_DETACH, self.pid, None, None)

    def ptrace_getregs(self):
        pre = user_regs_struct()
        libc.ptrace(PTRACE_GETREGS, self.pid, None, ctypes.byref(pre))
        return pre

    def ptrace_setregs(self, regs_struct):
        libc.ptrace(PTRACE_SETREGS, self.pid, None, ctypes.byref(regs_struct))

    def ptrace_singlestep(self):
        libc.ptrace(PTRACE_SINGLESTEP, self.pid, 0, 0)

    def print_regs(self, regs_struct):
        for field_name, field_type in regs_struct._fields_:
            print field_name, hex(getattr(regs_struct, field_name))


