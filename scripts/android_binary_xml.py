#!/usr/bin/env python3
"""Strict structural check for an Android binary XML manifest.

Reference for the same check in src/custom_mutators/v2/axml_check.c; the two
must agree byte for byte (tests/test_axml_structure.py). It verifies chunk
framing, string-pool bounds and termination, and string references. It does
not judge manifest semantics: a structurally valid manifest can still be
refused by Android, so a device install remains the admission test.
"""

import struct
import sys
import zipfile

RES_STRING_POOL, RES_XML, RES_XML_RESOURCE_MAP = 0x0001, 0x0003, 0x0180
XML_START_NS, XML_END_NS, XML_START_ELEMENT, XML_END_ELEMENT, XML_CDATA = (
    0x0100, 0x0101, 0x0102, 0x0103, 0x0104)
UTF8_FLAG = 1 << 8
NO_STRING = 0xFFFFFFFF
TYPE_STRING = 0x03
MAX_MANIFEST_BYTES = 16 * 1024 * 1024


def _u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _string_pool(data, start, size):
    """Return (string_count, None) or (None, reason)."""
    if _u16(data, start + 2) != 28 or size < 28:
        return None, "string_pool_header"
    count, styles, flags = _u32(data, start + 8), _u32(data, start + 12), _u32(data, start + 16)
    strings_start, styles_start = _u32(data, start + 20), _u32(data, start + 24)
    if count > size // 4 or styles > size // 4:
        return None, "string_pool_count"
    table_end = 28 + 4 * (count + styles)
    if table_end > size or strings_start < table_end or strings_start > size:
        return None, "string_pool_layout"
    if styles:
        if styles_start < strings_start or styles_start > size:
            return None, "string_pool_layout"
        data_len = styles_start - strings_start
    else:
        data_len = size - strings_start
    base = start + strings_start
    utf8 = bool(flags & UTF8_FLAG)
    for index in range(count):
        off = _u32(data, start + 28 + 4 * index)
        if utf8:
            for _ in range(2):  # UTF-16 length, then UTF-8 byte length
                if off >= data_len:
                    return None, "string_offset"
                length = data[base + off]
                off += 1
                if length & 0x80:
                    if off >= data_len:
                        return None, "string_offset"
                    length = ((length & 0x7F) << 8) | data[base + off]
                    off += 1
            if off + length >= data_len or data[base + off + length] != 0:
                return None, "string_termination"
        else:
            if off + 2 > data_len:
                return None, "string_offset"
            length = _u16(data, base + off)
            off += 2
            if length & 0x8000:
                if off + 2 > data_len:
                    return None, "string_offset"
                length = ((length & 0x7FFF) << 16) | _u16(data, base + off)
                off += 2
            end = off + 2 * length
            if end + 2 > data_len or _u16(data, base + end) != 0:
                return None, "string_termination"
    return count, None


def structure_error(data):
    """Return None when `data` is structurally sound, else a short reason."""
    size = len(data)
    if size < 8 or size > MAX_MANIFEST_BYTES:
        return "document_size"
    if _u16(data, 0) != RES_XML or _u16(data, 2) != 8 or _u32(data, 4) != size:
        return "document_header"
    cursor, strings, depth, namespaces, elements = 8, None, 0, 0, 0
    while cursor < size:
        if size - cursor < 8:
            return "chunk_truncated"
        kind, header, chunk = _u16(data, cursor), _u16(data, cursor + 2), _u32(data, cursor + 4)
        if header < 8 or chunk < header or chunk > size - cursor or (header | chunk) & 3:
            return "chunk_bounds"
        if strings is None:
            if kind != RES_STRING_POOL:
                return "string_pool_missing"
            strings, reason = _string_pool(data, cursor, chunk)
            if reason:
                return reason
        elif kind == RES_XML_RESOURCE_MAP:
            if header != 8:
                return "resource_map_header"
        elif kind in (XML_START_NS, XML_END_NS, XML_START_ELEMENT, XML_END_ELEMENT, XML_CDATA):
            ext = cursor + 16
            need = {XML_START_ELEMENT: 20, XML_CDATA: 12}.get(kind, 8)
            if header != 16 or chunk < 16 + need:
                return "node_size"
            ref = lambda offset: (_u32(data, offset) == NO_STRING or
                                  _u32(data, offset) < strings)
            if not ref(cursor + 12):
                return "string_reference"
            if kind in (XML_START_NS, XML_END_NS):
                if not ref(ext) or _u32(data, ext + 4) >= strings:
                    return "string_reference"
                namespaces += 1 if kind == XML_START_NS else -1
                if namespaces < 0:
                    return "namespace_nesting"
            elif kind == XML_CDATA:
                if _u32(data, ext) >= strings:
                    return "string_reference"
            else:
                if not ref(ext) or _u32(data, ext + 4) >= strings:
                    return "string_reference"
                if kind == XML_END_ELEMENT:
                    depth -= 1
                    if depth < 0:
                        return "element_nesting"
                else:
                    attr_start, attr_size, attr_count = (
                        _u16(data, ext + 8), _u16(data, ext + 10), _u16(data, ext + 12))
                    if (attr_start < 20 or attr_size < 20 or
                            attr_start + attr_size * attr_count > chunk - 16):
                        return "attribute_bounds"
                    for index in range(attr_count):
                        attr = ext + attr_start + index * attr_size
                        if (not ref(attr) or _u32(data, attr + 4) >= strings or
                                not ref(attr + 8) or _u16(data, attr + 12) != 8 or
                                (data[attr + 15] == TYPE_STRING and
                                 _u32(data, attr + 16) >= strings)):
                            return "attribute_value"
                    depth += 1
                    elements += 1
        else:
            return "chunk_type"
        cursor += chunk
    if strings is None or not elements or depth or namespaces:
        return "document_incomplete"
    return None


def apk_structure_error(path):
    try:
        with zipfile.ZipFile(path) as archive:
            return structure_error(archive.read("AndroidManifest.xml"))
    except (OSError, KeyError, RuntimeError, zipfile.BadZipFile) as exc:
        return f"unreadable:{type(exc).__name__}"


if __name__ == "__main__":
    status = 0
    for name in sys.argv[1:]:
        reason = apk_structure_error(name)
        print(f"{'valid' if reason is None else 'invalid:' + reason}\t{name}")
        status |= reason is not None
    sys.exit(status)
