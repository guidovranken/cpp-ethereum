CC=clang++-4.0
CFLAGS=-DETH_FATDB -Ibuild -Iinclude -I../utils -I../evmjit/include -I../libdevcore/.. -isystem /home/jhg/.hunter/_Base/b96750b/978b192/9d3cb74/Install/include -O2 -g -DETH_RELEASE -fstack-protector-strong -Wimplicit-fallthrough -Wall -Wextra -Wno-unknown-pragmas -std=c++11

all: cpp_vm_runner.a
vmrunner.o: vmrunner.cpp
	$(CC) $(CFLAGS) vmrunner.cpp -c -o vmrunner.o
cpp_vm_runner.a: vmrunner.o
	bash createlib.sh
