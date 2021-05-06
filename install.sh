#!/bin/bash

set -e

if [[ -z "${PREFIX}" ]]; then
    echo "No PREFIX specified. Dont know where to install rd files!"
    echo ""
    echo "e.g. $ PREFIX=~/myrd ./install.sh"
    echo "     This command will install rd files and directories to ~/myrd "
    echo "     rd related files will be stored in ~/myrd/bin, ~/myrd/lib and ~/myrd/share"
    exit 1
fi

if [[ -d "${PREFIX}" ]]; then
    echo "Installing rd to: ${PREFIX}"
    echo "NOTE: ${PREFIX}/bin, ${PREFIX}/lib, ${PREFIX}/share will be populated with rd files..."
else
    echo "'${PREFIX}' does not exist. Trying to create it"
    install -v -d "${PREFIX}"
fi

if [[ -n "${DEBUG}" ]]; then
    echo "Debug version will be compiled"
    DEBUG="--debug"
fi

set -x
cargo install ${DEBUG} --locked --force --path . --root "${PREFIX}"
set +x

echo "Installing additional files and directories"
install -v -d "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/rd_page_64 "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/rd_page_64_replay "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/rd_page_32 "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/rd_page_32_replay "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/32bit-avx.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/32bit-core.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/32bit-linux.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/32bit-sse.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/64bit-avx.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/64bit-core.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/64bit-linux.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/64bit-seg.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/64bit-sse.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/amd64-avx-linux.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/amd64-linux.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/i386-avx-linux.xml "${PREFIX}/share/rd"
install -v -m 0644 -C target/share/rd/i386-linux.xml "${PREFIX}/share/rd"

install -v -d "${PREFIX}/share/rd/src/preload"
install -v -m 0644 -C target/share/rd/src/preload/syscall_hook.S "${PREFIX}/share/rd/src/preload"
install -v -m 0644 -C target/share/rd/src/preload/syscallbuf.c "${PREFIX}/share/rd/src/preload"
install -v -m 0644 -C target/share/rd/src/preload/raw_syscall.S "${PREFIX}/share/rd/src/preload"
install -v -m 0644 -C target/share/rd/src/preload/breakpoint_table.S "${PREFIX}/share/rd/src/preload"
install -v -m 0644 -C target/share/rd/src/preload/overrides.c "${PREFIX}/share/rd/src/preload"
install -v -m 0644 -C target/share/rd/src/preload/preload_interface.h "${PREFIX}/share/rd/src/preload"
install -v -m 0644 -C target/share/rd/src/preload/syscallbuf.h "${PREFIX}/share/rd/src/preload"

install -v -d "${PREFIX}/lib/rd"
install -v -m 0644 -C target/lib/rd/librdpreload.so "${PREFIX}/lib/rd"
install -v -m 0644 -C target/lib/rd/librdpreload_32.so "${PREFIX}/lib/rd"

install -v -d "${PREFIX}/bin"
install -v -m 0755 -C target/bin/rd_exec_stub "${PREFIX}/bin"
install -v -m 0755 -C target/bin/rd_exec_stub_32 "${PREFIX}/bin"

echo "Done"
