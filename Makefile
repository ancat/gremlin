all:
	gcc -Wl,--no-as-needed -L/usr/lib64/  -l:libpython3.11.so.1.0 -lpython3.11 -I/usr/include/python3.11 -pthread -shared -fPIC -o pyject.so pyject.c
	gcc -pthread -shared -fPIC -o fancy.so fancy.c

clean:
	${RM} fancy.so pyject.so
