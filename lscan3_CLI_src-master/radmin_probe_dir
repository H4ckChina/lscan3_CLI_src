#!/usr/bin/env bash
set -u

usage() {
    echo "Usage: $0 -i input_dir [-o output_dir] [-t threads] [-w timeout_ms]" >&2
}

input_dir=""
output_dir="./results"
threads=4
timeout_ms=3000

while getopts ":i:o:t:w:h" opt; do
    case "$opt" in
        i) input_dir=$OPTARG ;;
        o) output_dir=$OPTARG ;;
        t) threads=$OPTARG ;;
        w) timeout_ms=$OPTARG ;;
        h) usage; exit 0 ;;
        :) echo "Missing argument for -$OPTARG" >&2; usage; exit 2 ;;
        \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 2 ;;
    esac
done

if [[ -z "$input_dir" || ! -d "$input_dir" ]]; then
    echo "Input directory does not exist: $input_dir" >&2
    usage
    exit 2
fi
if ! [[ "$threads" =~ ^[1-9][0-9]*$ && "$timeout_ms" =~ ^[1-9][0-9]*$ ]]; then
    echo "threads and timeout must be positive integers" >&2
    exit 2
fi

mapfile -t files < <(find "$input_dir" -maxdepth 1 -type f -name '*.txt' -printf '%f\n' | sort -V)
file_count=${#files[@]}
if (( file_count == 0 )); then
    echo "No .txt files found in: $input_dir" >&2
    exit 1
fi

mkdir -p "$output_dir" || exit 1
printf '[start] input files: %d | threads per file: %s | output: %s\n' "$file_count" "$threads" "$output_dir"

processed=0
for filename in "${files[@]}"; do
    port=${filename%.txt}
    if ! [[ "$port" =~ ^[1-9][0-9]*$ ]] || (( port > 65535 )); then
        echo "[skip] $filename: filename must be a TCP port in the range 1-65535" >&2
        ((processed++))
        continue
    fi

    ((processed++))
    printf '\n[file %d/%d] port=%s targets=%s\n' "$processed" "$file_count" "$port" "$filename"
    ./radmin_probe -i "$input_dir/$filename" -p "$port" -o "$output_dir" -t "$threads" -w "$timeout_ms"
    rc=$?
    if (( rc != 0 )); then
        echo "[file $processed/$file_count] failed: $filename (exit=$rc)" >&2
    fi
done

printf '\n[complete] processed files: %d/%d\n' "$processed" "$file_count"
