FROM ubuntu:18.04
ARG SOFTHSMV=2.5.0

# Make sure the image is updated, install some prerequisites,
# Download the latest version of Clang (official binary) for Ubuntu
# Extract the archive and add Clang to the PATH
RUN apt-get update && apt-get install -y \
  build-essential \
  gcc-8 \
  g++-8 \
  cmake \
  git-core \
  make \
  libssl-dev \
  libseccomp-dev \
  autoconf \
  automake \
  libtool \
  pkg-config

# GCC 7, 8, 9
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 80 --slave /usr/bin/g++ g++ /usr/bin/g++-8 --slave /usr/bin/gcov gcov /usr/bin/gcov-8 && \
    update-alternatives --config gcc

# Builging sfthsmv2/installing
RUN git clone --branch ${SOFTHSMV} https://github.com/opendnssec/SoftHSMv2.git && \
		cd SoftHSMv2 && \
		sh autogen.sh && \
		./configure --disable-gost && \
		make && \
		make install

# Exporting the softhsm config
ENV SOFTHSM2_CONF=/etc/softhsm2.conf

# configuring HSM slot
RUN softhsm2-util --init-token --slot 0 --label "FKH" --pin 1234 --so-pin 0000

COPY . /root/pkcs11_leak_reproducer

RUN cd /root/pkcs11_leak_reproducer && \
    cmake -G "Unix Makefiles" ./ -B./build && \
    cd build && \
    make

# Install valgrind
RUN apt-get update && apt-get install -y valgrind

# If you want to run it with valgrind simply change the last command to fit:
CMD cd /root/pkcs11_leak_reproducer/build && \
    /usr/bin/valgrind --tool=memcheck --log-file=/tmp/valgrind \
    --gen-suppressions=all --leak-check=full \
    --leak-resolution=med --track-origins=yes --vgdb=no \
    ./pkcs11_leak_reproducer "/usr/local/lib/softhsm/libsofthsm2.so" "FKH" "1234" && \
    cat /tmp/valgrind


