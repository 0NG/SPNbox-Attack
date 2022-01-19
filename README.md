```bash
mkdir build

cd build

# should use clang
CC=clang CXX=clang++ cmake ..

make

# 3 round attack on SPNbox-8
./bin/attack

# 3 round attack on SPNbox-16
./bin/attack16

# bench of the attack on SPNbox-8
./bin/attack_bench

```

