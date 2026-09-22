# Linux Radmin service/version probe

## Build

```sh
make -f Makefile.radmin_probe clean
make -f Makefile.radmin_probe
chmod +x radmin_probe_dir
```

## Directory input mode

`radmin_probe_dir` accepts a directory with one `.txt` file per port. The filename (without `.txt`) must be a TCP port number, and each file contains one IPv4 address per line.

Example:

```text
ports/
├── 4899.txt
├── 5000.txt
└── 6000.txt
```

Run sequentially in numeric filename order:

```sh
./radmin_probe_dir -i ./ports -o ./results -t 2048 -w 3000
```

The wrapper reports the number of input files and the current file, then invokes the non-authenticating C probe for that port. Results remain organized as `results/<version>/<port>.txt`.

The C probe performs only unauthenticated Radmin service/version detection; it does not attempt usernames, passwords, hashes, or login validation. Use it only on systems you own or are explicitly authorized to assess.
