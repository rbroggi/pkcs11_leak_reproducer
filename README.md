## A PKCS11 lib valgrind leak report reproducer

In this small repo the idea is to provide a reproducer to a valgrind leak report when using a PKCS11 library.
The code does: 
1. Uses the pkcs11-lib `dlopen`-ing it;
1. Uses the credentials passed in the command line to create a session to a provided slotLabel also provided in the command line;
1. Generates a private AES key in the HSM;
1. Uses this private key to encrypt/decrypt a payload using AES_GCM mechanism;
1. Check that the Decrypted payload is equal to the original;

Below you will find how to:
1. compile the c++ code;
2. run it using an existing library installation; 
3. run a Docker container that packs a SoftHSMv2 installation as to provide a benchmark where no leaks are present;

### Compilation of cpp code:

Before continuing with the compilation, make sure you have installed in your system the following dependencies:

* [cmake](https://cmake.org/)
* A modern cpp compiler ([gcc](https://gcc.gnu.org/), [clang](https://clang.llvm.org/), etc...) featuring cpp17 support
* [valgrind](http://valgrind.org/)

Clone the repo and jump into the repo directory:
```bash
git clone https://github.com/rbroggi/pkcs11_leak_reproducer.git
cd pkcs11_leak_reproducer
```
Run [cmake](https://cmake.org/) and make for build of the program;
```bash
cmake -G "Unix Makefiles" ./ -B./build && \
cd build && \
make
```
Run the program using valgrind giving the following arguments: `"<path_to_the_lib>" "<token_slot_label>" "<token_slot_pwd>" ` 
```bash
valgrind --tool=memcheck --xml=yes --xml-file=/tmp/valgrind --gen-suppressions=all --leak-check=full --leak-resolution=med --track-origins=yes --vgdb=no ./pkcs11_leak_reproducer "<path_to_the_lib>" "<token_slot_label>" "<token_slot_pwd>" 
```
Check the result in file: `/tmp/valgrind`

### Build and run Dockerfile 

Benchmark results using SoftHSM Docker installation. You can either 
run the commands below on your system or simply check the github action
under this repo to see the results.

Clone the repo and jump into the repo directory:
```bash
git clone https://github.com/rbroggi/pkcs11_leak_reproducer.git
cd pkcs11_leak_reproducer
```
Build the image:
```bash
docker build -t thales-case-minimal -f Dockerfile.minimal .
```
Run the image:
```bash
docker run thales-case-minimal
```

