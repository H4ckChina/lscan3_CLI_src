# Linux Radmin service/version probe

This is a Linux-only, non-authenticating Radmin service fingerprinting tool.

## Build

```sh
make -f Makefile.radmin_probe
```

## Usage

The input file contains one IPv4 address per line. Blank lines and lines beginning with `#` are ignored.

```sh
./radmin_probe -i targets.txt -p 4899 -o ./results -t 32
```

`-t` accepts 1-1024 worker threads. The program prints progress for every completed target and reports thread creation failures instead of silently ignoring them.

Output is organized by detected version and port:

```text
results/
├── 2.0/4899.txt
├── 2.1/4899.txt
├── 2.2/4899.txt
├── 3/4899.txt
└── unknown/4899.txt
```

Each output file contains one confirmed target IP per line. Use this only on systems you own or are explicitly authorized to assess.
