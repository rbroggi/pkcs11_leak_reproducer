## Software HSM and c++ 

In this small repo the idea is to demo how to use SoftHSM from cpp as a substitute of a real hsm modulo.
The main things to understand are:

1. The softHSM is configured during the `Dockerfile.minimal` build;
2. The cpp code does: 
    1. Connect to the SoftHSM through a binary which is `dlopen`-ed;
    1. Uses the credentials configured in 1. to create a session;
    1. Generates a private AES key in the HSM;
    1. Uses this private key to encrypt/decrypt a payload using AES_GCM mechanism;
    1. Check that the Decrypted payload is equal to the original;

This repo packs also a `Dockerfile` which installs many dependencies that are not directly linked to this project,
it's only a convenience image for cpp remote development (bundles several cpp tools and toolchains along with 
bare minimum products needed by this software). 

* [SoftHSM](https://github.com/opendnssec/SoftHSMv2) - A software implementation of a Hardware Security Module;

The only dependency for this repo to work is docker. For a better overview of the software used please refer to the specific Dockerfiles.

## Usage

1. Clone the repo and jump into the repo directory:
```bash
git clone https://github.com/rbroggi/soft_hsm_cpp.git
cd soft_hsm_cpp
```
2. Build the image:
```bash
docker build -t softhsm-minimal -f Dockerfile.minimal .
```
3. Run the image:
```bash
docker run softhsm-minimal
```


