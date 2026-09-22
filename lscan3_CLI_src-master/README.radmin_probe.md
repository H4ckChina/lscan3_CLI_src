# Linux Radmin service/version probe

This directory contains `radmin_probe`, a Linux-only, non-authenticating Radmin service fingerprinting tool.

It sends only the unauthenticated Radmin version request and records confirmed responses. It does not attempt passwords, usernames, hashes, or any authentication exchange.

## Build

```sh
make -f Makefile.radmin_probe
```

## Usage

The input file contains one IPv4 address per line. Blank lines and lines beginning with `#` are ignored.

```sh
./radmin_probe -i targets.txt -p 4899 -o ./results -t 8
```

Output is organized as requested:

```text
results/
├── 2.0/4899.txt
├── 2.1/4899.txt
├── 2.2/4899.txt
├── 3/4899.txt
└── unknown/4899.txt
```

Each output file contains one confirmed target IP per line. Use this only on systems you own or are explicitly authorized to assess.
