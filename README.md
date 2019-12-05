# OVS Flow Rust Project
This project implements flow_extract() functions in OVS using Rust in order to
explore Rust's memory safety features.
 
## Introduction
Programming in unsafe languages like C is easily in jeopardy of memory issues
such as buffer and stack overflows, dangling pointers, accesses of
uninitialized or deallocated memory, and memory leakage.  These memory safety
issues can be exploited and leads to serve security vulnerability, and
unpredictable behavior. For example, memory bugs in OVS’s packet processing,
especially in parsing packet content and building the flow key, are prone to
attacks, since it is always be executed for every packet. Thus, an attacker
can craft packets to exploit the memory issue and launch a buffer overflow
attack, such as [CVE-2016-2074: MPLS buffer overflow vulnerabilities in
Open vSwitch](https://mail.openvswitch.org/pipermail/ovs-announce/2016-March/000082.html).
Other than the security vulnerability, a small memory leakage in the
packet processing path can quickly accumulated and leads to ovs-vswitchd
crash when it runs out of memory, such as [ofproto-dpif-xlate: Fix bug that
may leak ofproto_flow_mod ](https://github.com/openvswitch/ovs/commit/1bddcb5dc598).  Bugs like
these two are hard to detect and common in software written in C language.

Rust is a system programming language that provides memory safety without
runtime overhead.  Rust gives users fine control over the use of memory,
but keeps track of the lifetime and ownership of each memory region.
This model leads to less likely of memory leak, dangling pointers,
or memory corruption issues.  In this project, we are working on
replacing one of the memory safety critical parts in OVS from C code to
Rust, starting by flow_extract().

## Try it out
Build flow rust as a shared library.
```
$ git clone https://github.com/williamtu/flow-rust.git
$ cd flow-rust
$ cargo build --release
$ cp ./target/release/libovsflowrust.so /lib/x86_64-linux-gnu/
$ ldconfig
```

Later on, you can apply [this patch](misc/0001-Rust-Try-flow-rust.patch)
on your OVS repo to try flow Rust on your system.
