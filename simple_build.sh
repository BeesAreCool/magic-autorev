git submodule foreach git pull
mkdir build
set -e
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make
cd ..
./build/MemStrings ./samples/problem
