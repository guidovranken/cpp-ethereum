#!/bin/bash
cd ..
rm -rf build
mkdir build
cd build
CC="clang-4.0" CXX="clang++-4.0" CFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,edge -g" CXXFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,edge -g" cmake ..
CC="clang-4.0" CXX="clang++-4.0" CFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,edge -g" CXXFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-gep,trace-div,edge -g" cmake --build .
