# LetBroRock
A software-only implementation of Intel LBR(Last Branch Record). Bro, Let's Rock and Roll!

## Prerequisites
Install necessary libraries:

`libunwind`:
```
sudo yum install libunwind libunwind-devel
```

`AMED`:
```
cd third_party
git clone git@github.com:Mellorsssss/AMED.git
cd AMED
git checkout melos
```

`Dynamorio`:
Download the 10.0 version and put it under `third_party` with name `Dynamorio`.

## Compile
```
mkdir build
cd build
cmake .. && make -j8
```
