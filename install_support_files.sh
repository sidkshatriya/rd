#!/bin/sh
install -v -d ~/.cargo/share/rd/src/preload
install -v -C target/share/rd/src/preload/syscall_hook.S ~/.cargo/share/rd/src/preload  
install -v -C target/share/rd/src/preload/syscallbuf.c ~/.cargo/share/rd/src/preload 
install -v -C target/share/rd/src/preload/raw_syscall.S ~/.cargo/share/rd/src/preload 
install -v -C target/share/rd/src/preload/breakpoint_table.S ~/.cargo/share/rd/src/preload 
install -v -C target/share/rd/src/preload/overrides.c ~/.cargo/share/rd/src/preload 
install -v -C target/share/rd/src/preload/preload_interface.h ~/.cargo/share/rd/src/preload 
install -v -C target/share/rd/src/preload/syscallbuf.h ~/.cargo/share/rd/src/preload

install -v -d ~/.cargo/share/rd/src/preload
install -v -C target/share/rd/rd_page_64 ~/.cargo/share/rd 
install -v -C target/share/rd/rd_page_64_replay ~/.cargo/share/rd 
install -v -C target/share/rd/rd_page_32 ~/.cargo/share/rd 
install -v -C target/share/rd/rd_page_32_replay ~/.cargo/share/rd 

install -v -d ~/.cargo/lib/rd
install -v -C target/lib/rd/librdpreload.so ~/.cargo/lib 
install -v -C target/lib/rd/librdpreload_32.so ~/.cargo/lib/rd

install -v -d ~/.cargo/bin
install -v -C target/bin/rd_exec_stub ~/.cargo/bin
install -v -C target/bin/rd_exec_stub_32 ~/.cargo/bin

 
