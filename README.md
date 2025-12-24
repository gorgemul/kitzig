# kitzig

`kitzig` is a small command-line utility written in **Zig** that bundles some tools that I frequently used

It provides quick helpers for:
- timestamp conversion
- number base conversion
- math calculation (bc wrapper)
- SSH / SCP shortcuts based on config
- lightweight config inspection

The goal is to replace multiple ad-hoc shell scripts and commands with one fast, portable(macos/linux) tool.


## Usage

```sh
OPTIONS:
    -h,   --help,        show this help message
    -c,   --config       show exist configuration
    -cv,  --config_value get config value by [config-name]
    -t,   --timestamp    1757651421 -> 2025-09-12 12:30:21, vice versa
    -n,   --number       decimal, binary(0b or 0B prefix), hex(0x or 0X prefix) transfer to one another
    -m,   --math         wrapper calculator above bc, in zsh when use multiply('*')
                         need to be quoted, so support replace 'x' for '*'
                         2x3 <==> 2*3
    -ssh, --ssh          kit -ssh [config-name]
    -scp, --scp          kit -scp <foo_dir> <bar_dir> [config-name]
```

## Zig Version Requirement

This project currently targets **Zig master** and does **not** build with stable Zig releases.

```bash
❯ zig version
0.16.0-dev.1484+d0ba6642b
```
### Build

```bash
make build
```

### Install
```bash
make install
```