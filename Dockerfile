# CLion remote docker environment (How to build docker container, run and stop it)
#
# Build and run:
#   docker build -t softhsm-client:1.0 -f Dockerfile .
#   docker run -d --link=hsm:hsm --cap-add sys_ptrace -p 2222:22 --name hsm-client softhsm-client:1.0
#   ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[localhost]:2222"
#
# stop:
#   docker stop hsm-client
# start
#   docker stop hsm-client
# ssh credentials (test user):
#   user@password
# Check http://releases.llvm.org/download.html#9.0.0 for the latest available binaries
FROM ubuntu:18.04
ARG SOFTHSMV=2.5.0

# Make sure the image is updated, install some prerequisites,
# Download the latest version of Clang (official binary) for Ubuntu
# Extract the archive and add Clang to the PATH
RUN apt-get update && apt-get install -y \
  ssh \
  xz-utils \
  build-essential \
  curl \
  gcc \
  g++ \
  gdb \
  cmake \
  rsync \
  tar \
  python \
  && rm -rf /var/lib/apt/lists/* \
  && curl -SL http://releases.llvm.org/9.0.0/clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04.tar.xz \
  | tar -xJC . && \
  mv clang+llvm-9.0.0-x86_64-linux-gnu-ubuntu-18.04 clang_9.0.0 && \
  echo 'export PATH=/clang_9.0.0/bin:$PATH' >> ~/.bashrc && \
  echo 'export LD_LIBRARY_PATH=/clang_9.0.0/lib:$LD_LIBRARY_PATH' >> ~/.bashrc

# GCC 7, 8, 9
RUN apt-get update && \
    apt install -y software-properties-common && \
    add-apt-repository ppa:ubuntu-toolchain-r/test && \
    apt install -y gcc-7 g++-7 gcc-8 g++-8 gcc-9 g++-9 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 90 --slave /usr/bin/g++ g++ /usr/bin/g++-9 --slave /usr/bin/gcov gcov /usr/bin/gcov-9 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 80 --slave /usr/bin/g++ g++ /usr/bin/g++-8 --slave /usr/bin/gcov gcov /usr/bin/gcov-8 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70 --slave /usr/bin/g++ g++ /usr/bin/g++-7 --slave /usr/bin/gcov gcov /usr/bin/gcov-7 && \
    update-alternatives --config gcc

###########################################################
# Dependencies for pkcs11-proxy and opensc for pkcs11-tool#
###########################################################
# Dependencies for softHSM / pkcs11
RUN apt-get update && \
    apt-get install -y  git-core make cmake libssl-dev libseccomp-dev wget autoconf automake libtool pkg-config

# Builging sfthsmv2/installing
RUN git clone --branch ${SOFTHSMV} https://github.com/opendnssec/SoftHSMv2.git && \
		cd SoftHSMv2 && \
		sh autogen.sh && \
		./configure --disable-gost && \
		make && \
		make install && \
		export SOFTHSM2_CONF=/etc/softhsm2.conf && \
		softhsm2-util --init-token --slot 0 --label "FKX" --pin 1234 --so-pin 0000 && \
		softhsm2-util --init-token --slot 1 --label "FKH" --pin 1234 --so-pin 0000


# Config for clion to run
RUN ( \
    echo 'LogLevel DEBUG2'; \
    echo 'PermitRootLogin yes'; \
    echo 'PasswordAuthentication yes'; \
    echo 'Subsystem sftp /usr/lib/openssh/sftp-server'; \
  ) > /etc/ssh/sshd_config_test_clion \
  && mkdir /run/sshd

RUN useradd -m user \
  && yes password | passwd user

RUN echo 'export SOFTHSM2_CONF=/etc/softhsm2.conf' >> /home/user/.profile

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config_test_clion"]
