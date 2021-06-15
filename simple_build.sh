mkdir build
set -e
cd build
cmake ..
make
cd ..
./build/MemStrings ./samples/problem
