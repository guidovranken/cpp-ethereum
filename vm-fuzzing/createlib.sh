#!/bin/bash
ar -M <<EOM
CREATE cpp_vm_runner.a
ADDLIB ../build/libevm/libevm.a
ADDLIB ../build/libethcore/libethcore.a
ADDLIB ../build/libdevcore/libdevcore.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_system.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_filesystem.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_thread.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_unit_test_framework.a
ADDMOD vmrunner.o
SAVE
END
EOM
