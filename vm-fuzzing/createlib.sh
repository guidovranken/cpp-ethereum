#!/bin/bash
ar -M <<EOM
CREATE cpp_vm_runner.a
ADDLIB ../build/libevm/libevm.a
ADDLIB ../build/libdevcrypto/libdevcrypto.a
ADDLIB ../build/libethereum/libethereum.a
ADDLIB ../build/libethcore/libethcore.a
ADDLIB ../build/libdevcore/libdevcore.a
ADDLIB ../build/libethashseal/libethashseal.a
ADDLIB ../build/libethash/libethash.a
ADDLIB /home/jhg/.hunter/_Base/b96750b/978b192/9d3cb74/Install/lib/libjsoncpp.a
ADDLIB /home/jhg/.hunter/_Base/b96750b/978b192/9d3cb74/Install/lib/libcryptopp.a
ADDLIB ../build/deps/lib/libff.a
ADDLIB ../build/deps/lib/libmpir.a
ADDLIB ../build/utils/libscrypt/libscrypt.a
ADDLIB ../build/deps/lib/libsecp256k1.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_system.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_filesystem.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_thread.a
ADDLIB /usr/lib/x86_64-linux-gnu/libboost_unit_test_framework.a
ADDMOD vmrunner.o
SAVE
END
EOM
