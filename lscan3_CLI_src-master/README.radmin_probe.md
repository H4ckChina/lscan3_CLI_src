# Linux Radmin service/version probe

## Build

```sh
make -f Makefile.radmin_probe clean
make -f Makefile.radmin_probe
```

## Directory input mode

The main program now accepts a directory with one `.txt` file per port. The filename without `.txt` must be a TCP port number, and each file contains one IPv4 address per line.

Example:

```text
ports/
├── 4899.txt
├── 5000.txt
└── 6000.txt
```

Run directly with the main program:

```sh
./radmin_probe -i ./ports -o ./results -t 2048 -w 3000
```

The program counts valid port files, sorts them numerically, and processes them sequentially. Results are written as `results/<version>/<port>.txt`, with one IP address per line.

The probe performs only unauthenticated Radmin service/version detection; it does not attempt usernames, passwords, hashes, or login validation. Use it only on systems you own or are explicitly authorized to assess.
