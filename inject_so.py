import ctypes
import sys
import os

# These could vary in your system
libc_path = "/usr/lib64/libc.so.6"
libdl_path = "/usr/lib64/libdl.so.2"
# For the inject use our own stack, and specify the size in bytes
stacksize = 200*1024

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
        print ("child died (oops): {}".format(s))
        sys.exit(1)
    else:
        print ("stopped for some other signal ({}): {}".format(os.WSTOPSIG(stat), s))
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
        print ("name addr ",dlpi_name,dlpi_addr)
        if dlpi_addr:
            if dlpi_name == target:
                state.value = dlpi_addr
                return 1
            # In my system, lib64 is a soft link to /usr/lib64, and the name could be either...
            # So scan using just the library name to make sure...
            if dlpi_name.decode('utf-8').split("/")[-1] == target.split("/")[-1]:
                state.value = dlpi_addr
                return 1
        return 0

    target_callback = lambda x: callback(x, state, so_path)

    prototype = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.POINTER(dl_phdr_info))
    libdl.dl_iterate_phdr(prototype(target_callback), 0)

    return state.value

maps = load_maps(pid)
process_libc = list(filter(
    lambda x: '/libc.' in x['map_name'] and 'r-xp' == x['permissions'],
    maps
))

if not process_libc:
    print ("Couldn't locate libc shared object in this process.")
    sys.exit(1)

libc_base     = process_libc[0]['addr_start']
libc_location = process_libc[0]['map_name']
libc_offset   = process_libc[0]['offset']
print ("libc in target is ", hex(libc_base),libc_location,hex(libc_offset))

libc = ctypes.CDLL(libc_path)
libdl = ctypes.CDLL(libdl_path)
libc.dlopen.restype = ctypes.c_void_p
libc.dlsym.restype = ctypes.c_void_p

libc_handle = libc.dlopen(libc_location, 0)

# Try __libc_dlopen_mode first, but this seems to be private in libc6
dlopen_call = ctypes.create_string_buffer(bytes("__libc_dlopen_mode","ascii")+b"\x00")
dlopen_call = libc.dlsym(ctypes.c_void_p(libc_handle), ctypes.byref(dlopen_call))
if not dlopen_call:
  # Try simply dlopen
  dlopen_call = ctypes.create_string_buffer(bytes("dlopen","ascii")+b"\x00")
  dlopen_call = libc.dlsym(ctypes.c_void_p(libc_handle), ctypes.byref(dlopen_call))
dlopen_call_offset = dlopen_call - find_base(libdl, libc_path)
print ("dlopen preferred call is offset @", hex(dlopen_call_offset))
dlopen_call = dlopen_call_offset + libc_base - libc_offset
print ("dlopen call in target is @", hex(dlopen_call))

libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64


libc.ptrace(PTRACE_ATTACH, pid, None, None)

stat = os.waitpid(pid, 0)

if os.WIFSTOPPED(stat[1]):
    handle_signal(stat[1], 19, "ptrace attach")

print ("Attached to target")

pagesize = os.sysconf("SC_PAGE_SIZE")
print ("page size is",pagesize)

pagesize  = os.sysconf("SC_PAGE_SIZE")
# Stacklen does not include an additional page used for the injection code and any parameters
# make it a multiple of pagesize
maplen = (int(((stacksize)+(pagesize-1))/pagesize) ) * pagesize + pagesize
print ("Setting mapsize to",hex(maplen),"bytes with pagesize",pagesize)

def ptrace_call_syscall(libc,syscall,arg1=0,arg2=0,arg3=0,arg4=0,arg5=0,arg6=0):
    backup_registers = user_regs_struct()
    registers        = user_regs_struct()

    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(backup_registers))
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
    backup_code = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(registers.rip), None)
    print ("Saved registers and injection point data")

    registers.rax = syscall
    registers.rdi = arg1
    registers.rsi = arg2
    registers.rdx = arg3
    registers.r10 = arg4
    registers.r8 =  arg5
    registers.r9 =  arg6

    libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
    libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(registers.rip), 0x050f)
    libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)

    stat = os.waitpid(pid, 0)
    if os.WIFSTOPPED(stat[1]):
        handle_signal(stat[1], 5, "syscall")

    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

    libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(backup_registers.rip), backup_code)
    libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(backup_registers))
    print ("restored process state after syscall")
    return registers.rax

# sys_mmap, offset=0, size=maplen, permissions=7,0x22 is anonymous
rwx_page = ptrace_call_syscall(libc,9,0,maplen,7,0x22)
print ("mmap complete, rwx page @", hex(rwx_page),"to",hex(rwx_page+maplen))

def write_process_memory(pid, address, size, data):
    bytes_buffer = ctypes.create_string_buffer(size)
    bytes_buffer.raw = bytes(data,"ascii")
    local_iovec  = iovec(ctypes.cast(ctypes.byref(bytes_buffer), ctypes.c_void_p), size)
    remote_iovec = iovec(ctypes.c_void_p(address), size)
    bytes_transferred = libc.process_vm_writev(
        pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0
    )

    return bytes_transferred

path = shared_object
write_process_memory(pid, rwx_page + 0xff, len(path)+1, path)

# Stack starts at the last 16 byte aligned area of rwx_page
stack = (rwx_page + maplen - 1)&(0xfffffffffff0)
print ("setting stack to",hex(stack))

def ptrace_call_library(libc,libaddr,stack,injectaddr,arg1=0,arg2=0,arg3=0,arg4=0,arg5=0,arg6=0):

  backup_registers = user_regs_struct()
  registers        = user_regs_struct()

  libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(backup_registers))
  libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))

  registers.rsp = stack           # our private stack
  registers.rax = libaddr         # function to call
  registers.rdi = arg1            # arg1
  registers.rsi = arg2            # arg2
  registers.rdx = arg3            # arg3
  registers.rcx = arg4            # arg4
  registers.r8 = arg5             # arg5
  registers.r9 = arg6             # arg6
  registers.rip = injectaddr      # where our injected subroutine call is

  libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
  libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(rwx_page), 0xccd0ff)
  libc.ptrace(PTRACE_CONT, pid, None, None)

  stat = os.waitpid(pid, 0)
  registers        = user_regs_struct()
  libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
  print ("library call returned", hex(registers.rax))
  handle_signal(stat[1], 5, "library call")
  libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(backup_registers))
  return registers.rax

rtn = ptrace_call_library(libc,dlopen_call,stack,rwx_page,rwx_page+0xff,1)

def ptrace_getstr(libc,addr,maxlen=256):
    # read null terminated string from the target. For safety, use a maxlen
    i=0
    retstr = ""
    while (i<maxlen):
      word = libc.ptrace(PTRACE_PEEKDATA, pid, ctypes.c_void_p(rtn+i), None)
      word = word.to_bytes(8,"little")
      for x in word:
          if (x==0):
              i=maxlen
          else:
              if i<maxlen:
                retstr+=chr(x)
      i=i+8
    return retstr

if (rtn == 0):
  # call dlerror, and if it returns a pointer treat it as a (char *) null terminated
  dlerror_call = ctypes.create_string_buffer(bytes("dlerror","ascii")+b"\x00")
  dlerror_call = libc.dlsym(ctypes.c_void_p(libc_handle), ctypes.byref(dlerror_call))
  dlerror_call_offset = dlerror_call - find_base(libdl, libc_path)
  dlerror_call = dlerror_call_offset + libc_base - libc_offset
  rtn = ptrace_call_library(libc,dlerror_call,stack,rwx_page)
  if (rtn):
    retstr = ptrace_getstr(libc,rtn)
    print ("error is",retstr)

libc.ptrace(PTRACE_CONT, pid, None, None)
print ("target process resuming")


