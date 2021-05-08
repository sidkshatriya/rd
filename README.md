# `rd` The Record & Debug Tool

The Record & Debug Tool (`rd`) is a Rust language port of the [rr-debugger/rr](https://github.com/rr-debugger/rr) debugger.

With `rd` you can _record_ Linux program executions. Subsequently you can replay these executions back exactly and _debug_ them in the gdb front-end. If you know how to use `rr` then you already know how to use `rd`.

Why is it a good idea to port `rr` to Rust? See [below](https://github.com/sidkshatriya/rd#why-implement-in-rust).

**Current Status** : The port is substantially complete and is currently of an alpha level quality. You should be able to use `rd` for the tasks you would ordinarily use `rr` for. The `rr` project keeps accumulating features and fixes and many of them have not found their way into `rd` yet. However, the expectation is that `rd` should be reasonably robust, complete and usable now. Please report any issues!

## Credits

The `rd` project would not have been possible without the work done in the [rr-debugger/rr](https://github.com/rr-debugger/rr) project. Many human-years of development effort have gone into making `rr` the truly amazing piece of software that it is.

The `rd` project is grateful to all the contributors of the `rr-debugger/rr` project.

For more details see [CREDITS.md](CREDITS.md)

## Background 

`rd` works on the same principles as `rr`. Please see [rr-debugger/rr](https://github.com/rr-debugger/rr) where you will find further information. More specifically, an excellent technical overview of `rr` can be found at [arXiv:1705.05937](https://arxiv.org/abs/1705.05937).

## Contributions

Contributions to the Record and Debug Tool (`rd`) are welcome and encouraged!

By contributing to `rd` you agree to license your contributions under the MIT license without any additional terms or conditions.

## Building 

rd requires a nightly version of the rust `x86_64-unknown-linux-gnu` toolchain to compile.

```bash
$ git clone git@github.com:sidkshatriya/rd.git
$ cd rd
$ cargo build --release 
```

Alternatively, build in debug mode . Things will run much more slowly as the code will be compiled with lower compiler optimizations, extra debug-mode assertions etc. 

```bash
# Defaults to debug mode by default
$ cargo build 
```

In general, use release mode as the debug mode can be much slower. Run `rd` in debug mode if you run into issues or are working on developing `rd`.

The program has been tested to compile and run properly on a **64-bit Ubuntu 20.04** installation at the moment only. 

Please file a ticket if `rd` does not work properly for your specific Linux distribution. In general, if `rr` compiles and runs properly in your Linux distro, `rd` should do the same.

Before trying to install or run `rd` make sure:
```bash
$ sudo apt install cmake make capnproto libcapnp-dev gdb g++-multilib libclang-11-dev
```

## Running `rd` via `cargo`

Invoking `cargo run` without any command line parameters will give you help.
```bash
$ cd rd
# This command will provide general help on rd
# To run debug mode simply omit `--release`
$ cargo run --release
```

To get help on specific `rd` sub-command e.g. `record`
```bash
$ cargo run --release -- record --help
```

Here is a simple way to record and replay (the replay is non-interactive) `ls -l`.

```bash
# Note that we add another '--' in case we are passing any command line params to rd 
$ cargo run --release -- record ls -- -l
$ cargo run --release -- replay -a
```

## Installing `rd`

It can get pretty tiresome to keep running `rd` via cargo. A simple script `install.sh` has been provided to install the rd binary and related support files to your directory of choice.

```bash
$ cd rd
$ PREFIX=~/myrd ./install.sh
```

This installs rd at `$HOME/myrd`. Files will be stored at `~/myrd/bin`, `~/myrd/lib` and `~/myrd/share`. The install script is extremely simple and can be easily understood. You may also want to add `~/myrd/bin` to your `PATH` at this point.

Assuming that `~/myrd/bin`is in your `PATH` it is very easy to invoke `rd` now.

```bash
# Records ls -l invocation
$ rd record ls -- -l

# Non-interatively replays the ls -l recording
$ rd replay -a

# Interatively replays the ls -l recording
$ rd replay
```

Please note that the `install.sh` script is rudimentary. _As always, check (and modify as necessary) the unix permissions/ownership of the files and directories created_, especially, if you install to a location like `~/.local` `/usr/local` etc. In general it is recommended to install `rd` to a separate directory in `$HOME` e.g. `~/myrd`, `~/rd` etc. as that interferes the least with your existing system.

## What works

The port is substantially complete and is ready for end-user usage and developer contributions. The project contains 55,000+ lines of ported over Rust code.

The following work:
* `rd rerun`
* `rd replay`
  * Both interactive replay (which uses the gdb front-end) and non-interative replay (`-a` flag) are supported
* `rd record`
* `rd buildid`
* `rd dump`
* `rd traceinfo`

A 64-bit build of `rd` supports the record/replay of _both_ 32 & 64-bit Linux programs. However, building and running `rd` to record/replay 32-bit programs in a 32-bit Linux distribution is currently _not_ supported.

## Tips and Suggestions

### Recording & Debugging program runs

#### To record a program

```bash
$ rd record <program to be recorded>
```
If you want to pass arguments to the program:

```bash
$ rd record <program to be recorded> -- <arguments>
```

_Example_:
```bash
$ rd record ls -- -l
```
#### To replay and debug the last recorded program in the gdb front-end
```bash
$ rd replay
```
### Logging

The various logging levels are `debug`, `info`, `warn`, `info` and `fatal`. To log at `warn` by default and `debug` for all messages from the `auto_remote_syscalls` rust module (as an example) do:

```bash
$ RD_LOG=all:warn,auto_remote_syscalls:debug rd /* rd params here */
```

## Why implement in Rust?
Here are some (necessarily subjective) reasons why it might be a good idea to have a Rust port of `rr`.

### Reduce complexity, increase reliability
`rr` is written in C/C++. C/C++ is a complex beast. As the Linux userspace/kernel interface gets more and more complex and gathers even more quirks, the `rr` codebase gets more and more complex too. With Rust the hope is that we have a clean and modern language that allows us to manage the complexity of record/replay. Of course, we still need to deal with the inherent complexity of record/replay but Rust helps with writing robust and reliable code. Once the code is written it is also easier to doing refactorings with more confidence in Rust. 

### Reduce barriers to understanding and contribution
Once you understand the core principles, Rust can be easier than C/C++ to grok. Hopefully this will allow more people to inspect, improve and offer fixes to the `rd` codebase.

### Provide an alternative, compatible implementation
Just like there can be multiple compilers for the same language, it might be a good idea to have multiple compatible implementations of `rr`. This might help with debugging weird bugs and optimize various implementations around different parameters.

### Be a playground for experimental features
This is something for the future. The hope is `rd` can become a playground for experimentation and implement some innovative features in record/replay. Also `rd` has access to the awesome Rust cargo ecosystem which means that functionality already implemented elsewhere can be added to it much more easily.
