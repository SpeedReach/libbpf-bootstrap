# eBPF Sequencer

## Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/SpeedReach/libbpf-bootstrap.git
```

## Building
Forked from libbpf-bootstrap, uses Makefile for build system.

## Install Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

## Run the sequencer
We use golang for user space code. So golang needs to be installed too.

First run the server.
```shell
cd src/golang
go run main.go
```

Next run the eBPF code.
``` 
cd src/c
make tc
sudo ./tc lo
```
