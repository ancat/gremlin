import ctypes, sys, os, string

try:
    pid = int(sys.argv[1])
except IndexError:
    print >> sys.stderr, "{} <process_id>".format(sys.argv[0])
    sys.exit(1)

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
libc.process_vm_readv.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint64]

class iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_ulong)
    ]

def parse_maps_file(handle):
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

    return output

def read_process_memory(func, pid, address, size):
    bytes_buffer = ctypes.create_string_buffer('\x00'*size)
    local_iovec  = iovec(ctypes.cast(ctypes.byref(bytes_buffer), ctypes.c_void_p), size)
    remote_iovec = iovec(ctypes.c_void_p(address), size)
    bytes_transferred = libc.process_vm_readv(pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0)
    return bytes_buffer

def print_printable_strings(input_string):
    cur_str = ""
    for cursor in xrange(len(input_string)):
        character = input_string[cursor]
        if ord(character) >= 0x20 and ord(character) < 0x7f:
            cur_str += character
        else:
            if len(cur_str) > 4:
                print cur_str

            cur_str = ""

map_file = '/proc/{}/maps'.format(pid)
exe_path = '/proc/{}/exe'.format(pid)
try:
    map_handle = open(map_file, 'r')
    mappings =  parse_maps_file(map_handle)
    map_handle.close()
except IOError:
    print >> sys.stderr, "Couldn't read from {}, is /proc/ mounted?".format(map_file)
    sys.exit(1)

executable_path = os.path.realpath(exe_path)
if executable_path == exe_path:
    print >> sys.stderr, "Couldn't retrieve executable path?"
    sys.exit(1)

exe_maps = filter(lambda x: executable_path in x['map_name'], mappings)
exe_maps += filter(lambda x: x['map_name'] in ['[stack]', '[vsyscall]', '[heap]', '[vdso]', ''], mappings)

for mapping in exe_maps:
    memory = read_process_memory(libc.process_vm_readv, pid, mapping['addr_start'], mapping['size'])
    print_printable_strings(memory.raw)