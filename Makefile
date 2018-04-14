all:
	gcc -Wl,--no-as-needed -L/usr/lib/x86_64-linux-gnu/  -l:/usr/lib/x86_64-linux-gnu/libpython2.7.so -lpython2.7 -I/usr/include/python2.7 -pthread -shared -fPIC -o pyject.so pyject.c
	gcc -pthread -shared -fPIC -o fancy.so fancy.c
