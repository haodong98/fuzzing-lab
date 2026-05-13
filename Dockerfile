# EPFL CS-412 Fuzzing Lab — libpng + AFL++
#
# Layout:
#   /opt/AFLplusplus       — built AFL++ toolchain (afl-clang-fast, afl-clang-lto, afl-fuzz, qemu_mode)
#   /opt/libpng-1.2.56     — pristine libpng source (Makefile copies it into /work for build-time patching)
#   /work                  — mounted from host (this directory contains src/, patches/, Makefile, ...)
#
# Pin everything that affects reproducibility. AFL++ tag, libpng version, and the LLVM major version
# are all explicit so reviewers regenerate the same binaries.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LLVM_VERSION=14
# AFLPP_TAG (not AFL_TAG) — afl-fuzz misinterprets variables prefixed with AFL_ as runtime knobs.
ARG AFLPP_TAG=v4.21c
ENV LIBPNG_VERSION=1.2.56

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} \
        llvm-${LLVM_VERSION}-dev \
        llvm-${LLVM_VERSION}-tools \
        lld-${LLVM_VERSION} \
        libllvm${LLVM_VERSION} \
        libc++-${LLVM_VERSION}-dev \
        libc++abi-${LLVM_VERSION}-dev \
        git \
        cmake \
        ninja-build \
        python3 python3-dev python3-pip \
        automake autoconf libtool pkg-config \
        wget curl ca-certificates \
        gnuplot-nox bsdmainutils \
        zlib1g-dev libgmp-dev \
        libglib2.0-dev libpixman-1-dev \
        flex bison file \
        vim-tiny less procps \
    && update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-${LLVM_VERSION}   100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_VERSION} 100 \
    && update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-${LLVM_VERSION} 100 \
    && rm -rf /var/lib/apt/lists/*

# AFL++ from source. distrib target builds LLVM mode (afl-clang-fast/lto), gcc-plugin mode, and the
# helpers we use (afl-tmin, afl-cmin, afl-plot, afl-cov dependencies). qemu_mode is a separate build
# step because it pulls QEMU sources and is heavier.
WORKDIR /opt
RUN git clone --depth=1 --branch=${AFLPP_TAG} https://github.com/AFLplusplus/AFLplusplus.git
WORKDIR /opt/AFLplusplus
RUN make distrib LLVM_CONFIG=llvm-config-${LLVM_VERSION} \
    && make install
# QEMU user-mode emulation — required for Q7. CPU_TARGET pins to x86_64; on Apple Silicon hosts
# this still works because Docker emulates linux/amd64 by default for this image.
RUN cd qemu_mode && CPU_TARGET=x86_64 ./build_qemu_support.sh
# QASan = QEMU + AddressSanitizer-like instrumentation for binary-only targets (optional bonus for Q7).
RUN cd qemu_mode/libqasan && make

# libpng pristine source. We do NOT build it here — the Makefile in /work re-extracts to a build dir,
# applies patches, and builds with the right flags. Keeping the pristine copy in the image lets you
# re-build offline.
WORKDIR /opt
RUN wget -q https://download.sourceforge.net/libpng/libpng-${LIBPNG_VERSION}.tar.gz \
    && tar xf libpng-${LIBPNG_VERSION}.tar.gz \
    && rm libpng-${LIBPNG_VERSION}.tar.gz

# Smoke-test the toolchain so build failures show up at image-build time, not at fuzz time.
RUN afl-fuzz -h 2>&1 | head -3 \
    && afl-clang-fast --version 2>&1 | head -1 \
    && afl-clang-lto --version 2>&1 | head -1 \
    && ls /opt/AFLplusplus/utils/libpng_no_checksum/ \
    && ls /opt/AFLplusplus/dictionaries/png.dict \
    && ls /opt/libpng-${LIBPNG_VERSION}/png.h

ENV LIBPNG_SRC=/opt/libpng-${LIBPNG_VERSION}
ENV PATH=/opt/AFLplusplus:${PATH}

# AFL++ runtime hints. AFL_SKIP_CPUFREQ silences the cpufreq-governor warning on Docker hosts where
# /sys/devices/system/cpu/* is not writable. AFL_AUTORESUME makes -i unnecessary on resume.
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_AUTORESUME=1

WORKDIR /work
CMD ["/bin/bash"]
