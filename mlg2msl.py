#!/usr/bin/env python3
"""
mlg2msl - convert TunerStudio / MegaLogViewer binary logs (.mlg, "MLVLG" format
version 2) to MSL (TunerStudio tab-separated text log) or CSV.

Format reference:
  https://www.efianalytics.com/TunerStudio/docs/MLG_Binary_LogFormat_2.0.pdf
  rusEFI firmware/console/binary_mlg_log/binary_mlg_logging.cpp

Layout (all values big-endian):
  header (24 bytes): "MLVLG\0", u16 version, u32 timestamp,
                     u32 infoDataStart, u32 dataBeginIndex,
                     u16 recordLength, u16 numFields
  field descriptors (89 bytes each): u8 type, char[34] name, char[10] units,
                     u8 displayStyle, f32 scale, f32 transform, s8 digits,
                     char[34] category
  data records (4 + recordLength + 1 bytes): u8 blockType(0), u8 rollingCounter,
                     u16 timestamp(10us), field payload, u8 checksum
                     (checksum = sum of payload bytes mod 256)

Usage:
  python3 mlg2msl.py re_11.mlg                # -> re_11.msl next to input
  python3 mlg2msl.py *.mlg                    # convert many
  python3 mlg2msl.py re_11.mlg -o out.msl     # explicit output (single input)
  python3 mlg2msl.py re_11.mlg -f csv         # -> re_11.csv (comma-separated,
                                              #    no units row unless --units-row)

Unlike MegaLogViewer's own MSL export, this keeps the original field names,
computes values in double precision (MLV goes through float32 and mangles
large integers like mcuSerial), and does not rebase Time to start at zero.
"""

import argparse
import csv
import math
import struct
import sys

MAGIC = b"MLVLG\x00"
HEADER_SIZE = 24
DESCRIPTOR_SIZE = 89

# MLG scalar type id -> (struct format char, size in bytes)
TYPES = {
    0: ("B", 1),  # U08
    1: ("b", 1),  # S08
    2: ("H", 2),  # U16
    3: ("h", 2),  # S16
    4: ("I", 4),  # U32
    5: ("i", 4),  # S32
    6: ("q", 8),  # S64
    7: ("f", 4),  # F32
}


def cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("latin-1").strip()


class Field:
    __slots__ = ("type_id", "name", "units", "scale", "transform", "digits", "category")

    def __init__(self, buf: bytes):
        self.type_id = buf[0]
        self.name = cstr(buf[1:35])
        self.units = cstr(buf[35:45])
        self.scale, self.transform = struct.unpack_from(">ff", buf, 46)
        self.digits = struct.unpack_from(">b", buf, 54)[0]
        self.category = cstr(buf[55:89])


def parse_header(data: bytes):
    base = data.find(MAGIC)
    if base < 0:
        raise ValueError("not an MLG file: MLVLG magic not found")
    version, = struct.unpack_from(">H", data, base + 6)
    if version != 2:
        raise ValueError(f"unsupported MLG format version {version} (only v2 supported)")
    _timestamp, _info_start, data_begin, record_length, num_fields = struct.unpack_from(
        ">IIIHH", data, base + 8
    )
    fields = []
    off = base + HEADER_SIZE
    for _ in range(num_fields):
        fields.append(Field(data[off:off + DESCRIPTOR_SIZE]))
        off += DESCRIPTOR_SIZE

    payload_len = sum(TYPES[f.type_id][1] for f in fields)
    if payload_len != record_length:
        raise ValueError(
            f"field sizes sum to {payload_len} but header says record length {record_length}"
        )
    return base, data_begin, record_length, fields


def make_formatter(field: Field):
    """Return a fast raw-value -> string function for one field.

    Rounds half away from zero (like MegaLogViewer), not half-to-even like
    printf: a duty cycle of 10.5 with 0 digits prints as 11, not 10.
    """
    scale, transform = field.scale, field.transform
    if scale == 1.0 and transform == 0.0 and field.type_id != 7 and field.digits <= 0:
        return str  # integer field passed through unscaled
    digits = max(field.digits, 0)
    q = 10.0 ** digits
    floor = math.floor

    def fmt(v):
        x = v * scale + transform
        y = floor(abs(x) * q + 0.5) / q
        if x < 0 and y != 0:
            y = -y
        return "%.*f" % (digits, y)

    return fmt


def convert(path: str, out_path: str, units_row: bool = False,
            delimiter: str = ",") -> None:
    with open(path, "rb") as fh:
        data = fh.read()

    base, data_begin, record_length, fields = parse_header(data)
    record_struct = struct.Struct(">" + "".join(TYPES[f.type_id][0] for f in fields))
    formatters = [make_formatter(f) for f in fields]
    rec_size = 4 + record_length + 1  # prefix + payload + checksum

    rows = 0
    bad_checksums = 0
    expected_counter = None
    pos = base + data_begin
    end = len(data)

    with open(out_path, "w", newline="") as out:
        # MegaLogViewer writes .msl with plain LF line endings
        writer = csv.writer(out, delimiter=delimiter,
                            lineterminator="\n" if delimiter == "\t" else "\r\n")
        writer.writerow([f.name for f in fields])
        if units_row:
            writer.writerow([f.units for f in fields])

        while pos + rec_size <= end:
            block_type = data[pos]
            if block_type != 0:
                print(f"  note: stopping at unknown block type {block_type} "
                      f"(offset {pos})", file=sys.stderr)
                break
            counter = data[pos + 1]
            payload = data[pos + 4: pos + 4 + record_length]

            if expected_counter is not None and counter != expected_counter:
                # SD-card files are preallocated to 32 MiB without zeroing, so
                # past the end of real data the file holds padding or remnants
                # of older deleted logs. The rolling counter is written
                # strictly sequentially, so a break in it marks end-of-data.
                if any(payload):
                    print(f"  note: rolling counter break at offset {pos} "
                          f"(expected {expected_counter}, got {counter}); "
                          f"treating as end of data", file=sys.stderr)
                break
            expected_counter = (counter + 1) & 0xFF

            if (sum(payload) & 0xFF) != data[pos + 4 + record_length]:
                bad_checksums += 1
                pos += rec_size
                continue

            values = record_struct.unpack(payload)
            writer.writerow([f(v) for f, v in zip(formatters, values)])
            rows += 1
            pos += rec_size

    msg = f"{path}: {rows} records, {len(fields)} fields -> {out_path}"
    if bad_checksums:
        msg += f" ({bad_checksums} records skipped: bad checksum)"
    print(msg)


def main() -> None:
    ap = argparse.ArgumentParser(description="Convert MLG binary logs to MSL or CSV")
    ap.add_argument("inputs", nargs="+", help=".mlg file(s) to convert")
    ap.add_argument("-o", "--output", help="output path (single input only); "
                    "a .csv extension implies -f csv")
    ap.add_argument("-f", "--format", choices=("msl", "csv"),
                    help="output format (default: msl, or inferred from -o extension)")
    ap.add_argument("--units-row", action="store_true",
                    help="CSV only: write a second header row with field units "
                    "(MSL always has one)")
    args = ap.parse_args()

    if args.output and len(args.inputs) > 1:
        ap.error("-o/--output only makes sense with a single input file")

    fmt = args.format
    if fmt is None:
        fmt = "csv" if args.output and args.output.lower().endswith(".csv") else "msl"
    # MSL is tab-separated and always carries a units row under the names row
    delimiter = "\t" if fmt == "msl" else ","
    units_row = True if fmt == "msl" else args.units_row

    failures = 0
    for path in args.inputs:
        stem = path[:-4] if path.lower().endswith(".mlg") else path
        out_path = args.output or f"{stem}.{fmt}"
        try:
            convert(path, out_path, units_row=units_row, delimiter=delimiter)
        except (ValueError, OSError) as exc:
            print(f"{path}: ERROR: {exc}", file=sys.stderr)
            failures += 1
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
