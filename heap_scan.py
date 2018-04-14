import sys
import ent
import struct
import hashlib
import memutils

sha1 = lambda x: hashlib.sha1(x).hexdigest()[:8]

#https://crypto.stackexchange.com/questions/25498/how-to-create-a-pem-file-for-storing-an-rsa-key

pid = int(sys.argv[1])
libc = memutils.get_libc()

candidates = []

maps = open('/proc/{}/maps'.format(pid))
maps = memutils.parse_maps_file(maps)
heap = filter(lambda x: x['map_name'] == '[heap]', maps)
if not heap:
    print "No heap found."
    sys.exit(1)

heap = heap[0]
heap_range = (heap['addr_start'], heap['addr_end'])
heap_data = memutils.read_process_memory(libc.process_vm_readv, pid, heap['addr_start'], heap['size'])


def hexdump(data, columns, lines=0):
    printable = range(0x21, 0x7f)
    buf = ""
    num_lines = 0
    for i, byte in enumerate(data):
        if i%columns == 0:
            offset_buf = format(i, '08x')+":"
            hex_buf = ""
            byte_buf = ""
        hex_buf += byte.encode('hex')+" "
        if ord(byte) in printable:
            byte_buf += byte
        else:
            byte_buf += "."
        if i%columns == columns-1 or i == len(data)-1:
            buf += offset_buf + " " + hex_buf.ljust(columns*3, ' ') + " " + byte_buf + "\n"
            num_lines += 1
        if num_lines == lines:
            break
    return buf

i = 0
while i < len(heap_data)-8:
    ptr = struct.unpack('Q', heap_data[i:i+8])[0]
    if heap_range[0] <= ptr and ptr <= heap_range[1]:
        offset = ptr-heap_range[0]
        dump = heap_data[offset:offset+256]
        entropy = ent.entropy(dump)
        if entropy > 7:

            contains_ptr = False
            for j in range(0xff-8):
                ptr2 = struct.unpack('Q', dump[j:j+8])[0]
                if heap_range[0] <= ptr2 and ptr2 <= heap_range[1]:
                    contains_ptr = True
                    break

            if not contains_ptr:
                print hex(ptr), "\t", hex(ptr-heap_range[0]), "\t", sha1(dump)
                print hexdump(dump, 10, 5)
    i += 1

