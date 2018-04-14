import ctypes
import sys
import os

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

class iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_ulong)
    ]

class dl_phdr_info(ctypes.Structure):
    _fields_ = [
        ("dlpi_addr", ctypes.c_void_p),
        ("dlpi_name", ctypes.c_char_p)

        # this structure has more fields but we don't need em /shrug
    ]

PTRACE_PEEKTEXT   = 1
PTRACE_PEEKDATA   = 2
PTRACE_POKETEXT   = 4
PTRACE_POKEDATA   = 5
PTRACE_CONT       = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17

pid = int(sys.argv[1])
shared_object = sys.argv[2]

def handle_signal(stat, expected, s):
    if os.WSTOPSIG(stat) == expected:
        ""
    elif os.WSTOPSIG(stat) == 11:
        print "child died (oops): {}".format(s)
        sys.exit(1)
    else:
        print "stopped for some other signal ({}): {}".format(os.WSTOPSIG(stat), s)
        sys.exit(1)

def load_maps(pid):
    handle = open('/proc/{}/maps'.format(pid), 'r')
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

    handle.close()
    return output

def find_base(libdl, so_path):
    state = ctypes.c_uint64()

    def callback(e, state, target):
        dlpi_addr = e.contents.dlpi_addr
        dlpi_name = e.contents.dlpi_name

        if dlpi_addr:
            if dlpi_name == target:
                state.value = dlpi_addr
                return 1

        return 0

    target_callback = lambda x: callback(x, state, so_path)

    prototype = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(dl_phdr_info))
    libdl.dl_iterate_phdr(prototype(target_callback), 0)

    return state.value

maps = load_maps(pid)
process_libc = filter(
    lambda x: '/libc-' in x['map_name'] and 'r-xp' == x['permissions'],
    maps
)

if not process_libc:
    print "Couldn't locate libc shared object in this process."
    sys.exit(1)

libc_base     = process_libc[0]['addr_start']
libc_location = process_libc[0]['map_name']

libdl = ctypes.CDLL('/lib/x86_64-linux-gnu/libdl.so.2')
libdl.dlopen.restype = ctypes.c_void_p
libdl.dlsym.restype = ctypes.c_void_p

libc_handle = libdl.dlopen(libc_location, 0)

dlopen_mode = ctypes.create_string_buffer("__libc_dlopen_mode\x00")
dlopen_mode = libdl.dlsym(ctypes.c_void_p(libc_handle), ctypes.byref(dlopen_mode))
dlopen_mode_offset = dlopen_mode - find_base(libdl, "/lib/x86_64-linux-gnu/libc.so.6")
__libc_dlopen_mode = dlopen_mode_offset + libc_base

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6') # Your libc location may vary!
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

libc.ptrace(PTRACE_ATTACH, pid, None, None)

stat = os.waitpid(pid, 0)

if os.WIFSTOPPED(stat[1]):
    handle_signal(stat[1], 19, "ptrace attach")

backup_registers = user_regs_struct()
registers        = user_regs_struct()

libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(backup_registers))
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
backup_code = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(registers.rip), None)

registers.rax = 9        # sys_mmap
registers.rdi = 0        # offset
registers.rsi = 10       # size
registers.rdx = 7        # map permissions
registers.r10 = 0x22     # anonymous
registers.r8 = 0         # fd
registers.r9 = 0         # fd

libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(registers.rip), 0x050f)
libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)

stat = os.waitpid(pid, 0)
if os.WIFSTOPPED(stat[1]):
    handle_signal(stat[1], 5, "mmap rwx")

libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
rwx_page = registers.rax
print "rwx page @", hex(rwx_page)

libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(backup_registers.rip), backup_code)
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(backup_registers))

def write_process_memory(pid, address, size, data):
    bytes_buffer = ctypes.create_string_buffer('\x00'*size)
    bytes_buffer.raw = data
    local_iovec  = iovec(ctypes.cast(ctypes.byref(bytes_buffer), ctypes.c_void_p), size)
    remote_iovec = iovec(ctypes.c_void_p(address), size)
    bytes_transferred = libc.process_vm_writev(
        pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0
    )

    return bytes_transferred

path = shared_object
write_process_memory(pid, rwx_page + 100, len(path)+1, path)

backup_registers = user_regs_struct()
registers        = user_regs_struct()

libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(backup_registers))
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

registers.rdi = rwx_page + 100 # path to .so file
registers.rsi = 1              # RTLD_LAZY
registers.rax = __libc_dlopen_mode

backup_code = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(registers.rip), None)

libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(registers.rip), 0xccd0ff)
libc.ptrace(PTRACE_CONT, pid, None, None)

stat = os.waitpid(pid, 0)
registers        = user_regs_struct()
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print "__libc_dlopen_mode returned", hex(registers.rax)
handle_signal(stat[1], 5, "__libc_dlopen_mode")

libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(backup_registers.rip), backup_code)
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(backup_registers))
libc.ptrace(PTRACE_CONT, pid, None, None)


