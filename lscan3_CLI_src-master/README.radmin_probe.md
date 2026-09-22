# Fix overall single-line progress

Run this once after pulling the repository:

```sh
cd ~/lscan3_CLI_src/lscan3_CLI_src-master
python3 fix_overall_progress.py
make -f Makefile.radmin_probe clean
make -f Makefile.radmin_probe
```

The patch makes the main probe use one global progress line. `checked`, `remaining`, `ETA`, and `found` are updated for every target across all port files; discovery no longer creates extra terminal lines.
