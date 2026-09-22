# Single-line progress output

The probe no longer needs to print a separate `[found]` line. Apply the change to an existing checkout with:

```sh
cd lscan3_CLI_src
./lscan3_CLI_src-master/apply_single_line_progress.sh lscan3_CLI_src-master/radmin_probe.c
cd lscan3_CLI_src-master
make -f Makefile.radmin_probe clean
make -f Makefile.radmin_probe
```

The script creates `radmin_probe.c.bak`, removes the extra `[found]` newline output, and makes the progress line clear and repaint itself using `\033[2K\r`.
