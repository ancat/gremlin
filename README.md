# gremlin
wink

Miscellaneous process introspection scripts/PoCs/etc. Most of them should have no
external dependencies but some will only work on x86_64 due to hardcoded assembly.

## get_memory_strings.py

It's like running `strings` from binutils on a binary, except on a running process'
memory. In the screenshot below I'm dumping strings that aren't present in the binary
but are in memory.

![strings](https://pbs.twimg.com/media/DXaMfQ0WsAAGKn3.jpg:large)

## inject_so.py

Python proof of concept for loading shared objects. Very specific to x86_64 but
"should" work on most flavors of linux. In the screenshot below, I injected a
shared object that prints cat emojis into a running htop process.

![inject_so](https://i.imgur.com/79XCq6q.png)
