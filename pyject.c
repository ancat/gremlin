#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <Python.h>

__attribute__((constructor))
void main() {
    Py_Initialize();
    PyRun_SimpleString("from time import time,ctime\n"
                         "print 'Today is',ctime(time())\n");
    PyRun_SimpleString("import this");
    Py_Finalize();
}


