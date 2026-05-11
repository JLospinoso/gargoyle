"""Extract position-independent bytes from a COFF object section."""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

COFF_FILE_HEADER_SIZE = 20
COFF_SECTION_HEADER_SIZE = 40
COFF_STRING_TABLE_SIZE_FIELD = 4
COFF_FILE_HEADER = struct.Struct("<HHLLLHH")
COFF_SECTION_HEADER = struct.Struct("<8sLLLLLLHHL")


class CoffError(ValueError):
    """Raised when a COFF object cannot be converted to PIC bytes."""


def read_string_table(data: bytes, pointer_to_symbol_table: int, number_of_symbols: int) -> bytes:
    """Return the COFF string table, if one is present."""
    offset = pointer_to_symbol_table + (number_of_symbols * 18)
    if pointer_to_symbol_table == 0 or offset + COFF_STRING_TABLE_SIZE_FIELD > len(data):
        return b""
    size = struct.unpack_from("<L", data, offset)[0]
    if size < COFF_STRING_TABLE_SIZE_FIELD or offset + size > len(data):
        raise CoffError("invalid COFF string table")
    return data[offset + COFF_STRING_TABLE_SIZE_FIELD : offset + size]


def decode_section_name(raw_name: bytes, string_table: bytes) -> str:
    """Decode an 8-byte COFF section name."""
    name = raw_name.rstrip(b"\0")
    if not name:
        return ""
    if name.startswith(b"/"):
        try:
            string_offset = int(name[1:].decode("ascii"))
        except ValueError as exc:
            raise CoffError(f"invalid COFF section name reference {name!r}") from exc
        if string_offset < COFF_STRING_TABLE_SIZE_FIELD:
            raise CoffError(f"invalid COFF string table offset {string_offset}")
        index = string_offset - COFF_STRING_TABLE_SIZE_FIELD
        if index >= len(string_table):
            raise CoffError(f"COFF string table offset {string_offset} is out of range")
        end = string_table.find(b"\0", index)
        if end == -1:
            end = len(string_table)
        return string_table[index:end].decode("utf-8")
    return name.decode("utf-8")


def extract_section(data: bytes, section_name: str, allow_relocations: bool) -> bytes:
    """Extract raw section data from a COFF object."""
    if len(data) < COFF_FILE_HEADER_SIZE:
        raise CoffError("input is too small to be a COFF object")

    (
        _machine,
        number_of_sections,
        _timestamp,
        pointer_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        _characteristics,
    ) = COFF_FILE_HEADER.unpack_from(data)

    section_offset = COFF_FILE_HEADER_SIZE + size_of_optional_header
    section_table_size = number_of_sections * COFF_SECTION_HEADER_SIZE
    if section_offset + section_table_size > len(data):
        raise CoffError("COFF section table extends past end of file")

    string_table = read_string_table(data, pointer_to_symbol_table, number_of_symbols)
    for index in range(number_of_sections):
        header_offset = section_offset + (index * COFF_SECTION_HEADER_SIZE)
        (
            raw_name,
            _virtual_size,
            _virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            _pointer_to_relocations,
            _pointer_to_linenumbers,
            number_of_relocations,
            _number_of_linenumbers,
            _characteristics,
        ) = COFF_SECTION_HEADER.unpack_from(data, header_offset)

        name = decode_section_name(raw_name, string_table)
        if name != section_name:
            continue
        if number_of_relocations and not allow_relocations:
            raise CoffError(
                f"section {section_name!r} has {number_of_relocations} relocation(s); "
                "PIC extraction requires fully resolved bytes"
            )
        end = pointer_to_raw_data + size_of_raw_data
        if pointer_to_raw_data == 0 or end > len(data):
            raise CoffError(f"section {section_name!r} raw data is out of range")
        return data[pointer_to_raw_data:end]

    raise CoffError(f"section {section_name!r} not found")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract raw position-independent bytes from a COFF object section."
    )
    parser.add_argument("object", type=Path, help="Input COFF object file")
    parser.add_argument("output", type=Path, help="Output .pic file")
    parser.add_argument("--section", default=".text", help="Section to extract")
    parser.add_argument(
        "--allow-relocations",
        action="store_true",
        help="Allow extraction when the selected section still has relocations",
    )
    return parser.parse_args()


def main() -> int:
    """Run the extractor."""
    args = parse_args()
    try:
        data = args.object.read_bytes()
        pic = extract_section(data, args.section, args.allow_relocations)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(pic)
    except OSError as exc:
        print(f"extract_pic.py: {exc}", file=sys.stderr)
        return 1
    except CoffError as exc:
        print(f"extract_pic.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
