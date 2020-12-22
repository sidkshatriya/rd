# `rd` The Record & Debug Tool

`rd` is a Rust language port of the [rr-debugger/rr](https://github.com/rr-debugger/rr) debugger.

The port is  _in-progress_ but many things work already (see [below](https://github.com/sidkshatriya/rd#what-works)).

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

The program has been tested to compile and run properly on a 64-bit Ubuntu 20.04 installation at the moment only. 

Please file a ticket if `rd` does not work properly for your specific Linux distribution. In general, if `rr` compiles and runs properly in your Linux distro, `rd` should do the same.

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
```

Please note that the `install.sh` script is rudimentary. _As always, check (and modify as necessary) the unix permissions of the files and directories created_, especially, if you install to a location like `~/.local` `/usr/local` etc. In general it is recommended to install `rd` to a separate directory in `$HOME` e.g. `~/myrd`, `~/rd` etc. as that interferes the least with your existing system.

## Credits

The `rd` project would not have been possible without the work done in the [rr-debugger/rr](https://github.com/rr-debugger/rr) project. Many human-years of development effort have gone into making `rr` the truly amazing piece of software that it is.

The `rd` project is grateful to all the contributors of the `rr-debugger/rr` project.

## Background 

`rd` works on the same principles as `rr`. Please see [rr-debugger/rr](https://github.com/rr-debugger/rr) where you will find further information. More specifically, an excellent technical overview of `rr` can be found at [arXiv:1705.05937](https://arxiv.org/abs/1705.05937).

## Contributions

Contributions to the Record and Debug Tool (`rd`) are welcome and encouraged!

By contributing to `rd` you agree to license your contributions under the MIT license without any additional terms or conditions.

## What works

The port is currently in progress and not ready for end-user usage. However developers interested in contributing to this project will find there is a lot to work with and build upon. The project already contains 45k+ lines of ported over Rust code.

`rd` can now record program runs (i.e. traces) on its own now (just like `rr`). See below for details.

The following work:
* `rd rerun`
* `rd replay -a`
  * Interactive replay (which uses a debugger like gdb) is not yet supported
  * In other words, non-interative replay (`-a` flag) is currently supported
* `rd record`
  * The recording functionality is mostly complete
* `rd buildid`
* `rd dump`
* `rd traceinfo`

## Tips and Suggestions

### Logging

The various logging levels are `debug`, `info`, `warn`, `info` and `fatal`. To log at `warn` by default and `debug` for all messages from the `auto_remote_syscalls` rust module (as an example) do:

```bash
$ RD_LOG=all:warn,auto_remote_syscalls:debug rd <etc params>
```

### Recording program runs (i.e. traces)

`rd` can record program runs (i.e. traces) on its own (just like `rr`). Recording with syscall buffers enabled or disabled are both supported. 
 
```bash
$ rd record <program to be recorded>
```
If you want to pass arguments to the program:

```bash
$ rd record <program to be recorded> -- <arguments>
```

Example:
```bash
$ rd record ls -- -l
```

Notes:
  * The recording functionality is mostly complete

### Replaying using `rr`

As mentioned above `rd` cannot do interactive replay i.e. in the gdb debugger yet. 

Non-interative replay i.e. `rd replay -a` is supported though. 

If you want replay via gdb, you can record using `rd` and replay using `rr`.

```bash
$ rd record ls 
rd: Saving execution to trace directory "/home/abcxyz/.local/share/rd/ls-3".
base_file_monitor.rs	    mmapped_file_monitor.rs   proc_fd_dir_monitor.rs  stdio_monitor.rs
magic_save_data_monitor.rs  preserve_file_monitor.rs  proc_mem_monitor.rs     virtual_perf_counter_monitor.rs

# Now we can replay *interactively*  using rr
# Assuming rr is in your PATH, add the exact directory on the first line after rd is invoked
$ rr replay /home/abcxyz/.local/share/rd/ls-3
```
