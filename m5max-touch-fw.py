#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the K114c (14-inch MacBook Pro, M5 Max) touch firmware blobs for Linux
from the two macOS restore-image members, no other tool needed.

Inputs (from the macOS 27.3 beta 1 / 26C5035r restore image, Firmware/ folder):
  K114_Multitouch.im4p     ->  apple/tpmtfw-k114c.bin   (trackpad, keyboard)
  K114_KiwiFirmware.im4p   ->  apple/tpkiwifw-k114c.bin (touch screen)

Usage:
  m5max-touch-fw.py -i K114_Multitouch.im4p K114_KiwiFirmware.im4p -o OUTDIR
  sudo cp OUTDIR/apple/* /lib/firmware/apple/

The touch screen blob is written with three optional operations removed: ops 26, 29 and 30 of
the kiwi sequence are placeholder Property writes (address 0, requirement False). The driver
cannot run them, and the load stops at block 26 with them in. The script checks each of the
three still has that shape before it drops it, and refuses otherwise.

Apple firmware never goes into a repository. This script only reads the files you give it.
"""
import argparse, base64, hashlib, struct, sys
import xml.etree.ElementTree as ET

FW_MAGIC = b"HIDF"
FW_VER = 1
FW_HDR_LEN = 32


def tlv(d, o):
    tag = d[o]; o += 1
    ln = d[o]; o += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(d[o:o + n], "big"); o += n
    return tag, ln, o, d[o:o + ln]


def der_payload(raw):
    """Walk the IM4P DER structure and return the big OCTET STRING payload
    (the compressed-XML firmware descriptor plist)."""
    o = raw.find(b"IM4P") - 2
    tag, ln0, v0, _ = tlv(raw, o)
    assert tag == 0x16, "not an IM4P"
    o2 = v0 + ln0
    while o2 < len(raw) - 2:
        tag, ln, nxt, _ = tlv(raw, o2)
        if tag == 0x04 and ln > 64:
            return raw[nxt:nxt + ln]
        o2 = nxt + ln
    raise SystemExit("no firmware payload found")


def unmunge(el, idmap):
    if "ID" in el.attrib:
        idmap[el.attrib["ID"]] = el
    if "IDREF" in el.attrib:
        return idmap[el.attrib["IDREF"]]
    el2 = ET.Element(el.tag)
    el2.attrib = {k: v for k, v in el.attrib.items() if k != "size"}
    el2.text = el.text
    for child in el:
        el2.append(unmunge(child, idmap))
    return el2


def from_el(el):
    t = el.tag
    if t == "dict":
        kids = list(el)
        assert len(kids) % 2 == 0, "odd dict"
        return {kids[i].text: from_el(kids[i + 1]) for i in range(0, len(kids), 2)}
    if t == "array":
        return [from_el(c) for c in el]
    if t == "string":
        return el.text or ""
    if t == "integer":
        return int((el.text or "0").strip(), 0)
    if t == "true":
        return True
    if t == "false":
        return False
    if t == "data":
        return base64.b64decode("".join((el.text or "").split()))
    raise SystemExit(f"unsupported plist element {t}")


def load_plist(xml_bytes):
    root = ET.fromstring(xml_bytes.rstrip(b"\x00"))
    body = root[0] if root.tag == "plist" else root
    return from_el(unmunge(body, {}))


def plist_to_bin_mtp(plist):
    """Serialize the descriptor plist into the MTP load blob (adapted from the MIT-licensed
    asahi_firmware trackpad serializer)."""
    iface_offset = None
    for i in plist:
        if i.get("Type") == "Config":
            ic = i["Config"].get("Interface Config", [])
            ic = [j for j in ic if "HIDRecorder Descriptor" not in j]
            i["Config"]["Interface Config"] = ic
            for j in ic:
                j.pop("HIDRecorder Descriptor", None)
                j["bInterfaceNumber"] = None

    def serialize(o):
        if o is None:
            yield None
        elif o is True:
            yield bytes([0xF5])
        elif o is False:
            yield bytes([0xF4])
        elif isinstance(o, dict):
            n = len(o)
            assert n < 0x10
            yield bytes([0xA0 + n])
            for k, v in o.items():
                yield from serialize(k)
                yield from serialize(v)
        elif isinstance(o, list):
            n = len(o)
            if n < 0x18:
                yield bytes([0x80 + n])
            elif n <= 0xFF:
                yield bytes([0x98, n])
            elif n <= 0xFFFF:
                yield bytes([0x99]) + struct.pack(">H", n)
            else:
                raise SystemExit("array too large")
            for v in o:
                yield from serialize(v)
        elif isinstance(o, str):
            b = o.encode("utf-8") + b"\0"
            n = len(b)
            if n < 0x18:
                yield bytes([0x60 + n])
            elif n <= 0xFF:
                yield bytes([0x78, n])
            else:
                yield bytes([0x79]) + struct.pack(">H", n)
            yield b
        elif isinstance(o, int):
            if o < 0x18:
                yield bytes([o])
            elif o <= 0xFF:
                yield bytes([0x18, o])
            elif o <= 0xFFFF:
                yield bytes([0x19]) + struct.pack(">H", o)
            elif o <= 0xFFFFFFFF:
                yield bytes([0x1A]) + struct.pack(">I", o)
            else:
                yield bytes([0x1B]) + struct.pack(">Q", o)
        elif isinstance(o, bytes):
            if len(o) <= 0xFFFF:
                yield (4, 3)
                yield struct.pack(">BH", 0x59, len(o))
            else:
                yield (4, 4)
                yield struct.pack(">BI", 0x5A, len(o))
            yield o
        else:
            raise SystemExit(f"unsupported plist value {type(o)}")

    def add_padding(chunks):
        nonlocal iface_offset
        off = 0
        for b in chunks:
            if b is None:
                assert iface_offset is None
                iface_offset = off
                b = b"\x00"
            if isinstance(b, tuple):
                align, i = b
                if (off + i) % align != 0:
                    pad = align - ((off + i) % align)
                    off += pad
                    yield b"\xd3" * pad
            else:
                off += len(b)
                yield b

    blob = b"".join(add_padding(serialize(plist)))
    assert iface_offset is not None, "no interface offset in descriptor"
    hdr = struct.pack("<4sIII", FW_MAGIC, FW_VER, FW_HDR_LEN, len(blob))
    hdr += struct.pack("<I12x", iface_offset)
    return hdr + blob



CUT_KIWI_OPS = (26, 29, 30)


def dec(b, i):
    ib = b[i]; mt = ib >> 5; ai = ib & 31; i += 1
    if ai < 24:
        v = ai
    elif ai == 24:
        v = b[i]; i += 1
    elif ai == 25:
        v = struct.unpack(">H", b[i:i+2])[0]; i += 2
    elif ai == 26:
        v = struct.unpack(">I", b[i:i+4])[0]; i += 4
    elif ai == 27:
        v = struct.unpack(">Q", b[i:i+8])[0]; i += 8
    else:
        raise ValueError("ai %d at %d" % (ai, i))
    if mt == 0:
        return v, i
    if mt == 1:
        return -1 - v, i
    if mt == 2:
        return ("bytes", v, b[i:i+v][:8].hex()), i + v
    if mt == 3:
        return b[i:i+v].decode("utf8", "replace").rstrip("\0"), i + v
    if mt == 4:
        out = []
        for _ in range(v):
            x, i = dec(b, i); out.append(x)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(v):
            k, i = dec(b, i); x, i = dec(b, i); out[k] = x
        return out, i
    if mt == 6:
        x, i = dec(b, i)
        return ("tag", v, x), i
    if mt == 7:
        return {20: False, 21: True, 22: None}.get(ai, ("simple", ai)), i
    raise ValueError("mt %d" % mt)


def cut_kiwi_optional_ops(raw):
    """Return the kiwi blob without the optional address-0 Property ops."""
    magic, ver, hl, dl, ioff = struct.unpack("<5I", raw[:20])
    assert raw[:4] == FW_MAGIC and hl == FW_HDR_LEN and len(raw) == hl + dl, (hl, dl, len(raw))
    data = raw[hl:]
    assert data[0] == 0x98 and data[1] == 0x28, "unexpected kiwi op count: %s" % data[:2].hex()
    spans = []
    i = 2
    for _ in range(0x28):
        j = dec(data, i)[1]
        spans.append((i, j))
        i = j
    assert i == dl, (i, dl)
    for n in CUT_KIWI_OPS:
        op = dec(data, spans[n][0])[0]
        assert op["Type"] == "Property" and op["Address"] == 0 and op["Requirement"] == {"Type": "False"}, n
        assert spans[n][1] <= ioff, n
    out = bytearray(b"\x98" + bytes([0x28 - len(CUT_KIWI_OPS)]))
    removed = 0
    for n, (a, b) in enumerate(spans):
        if n in CUT_KIWI_OPS:
            removed += b - a
            continue
        out += data[a:b]
    new_ioff = ioff - removed
    assert data[ioff] == out[new_ioff]
    return struct.pack("<5I", magic, ver, hl, len(out), new_ioff) + raw[20:hl] + bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--inputs", nargs="+", required=True,
                    help="K114_Multitouch.im4p K114_KiwiFirmware.im4p")
    ap.add_argument("-o", "--outdir", required=True)
    a = ap.parse_args()
    import os
    out = os.path.join(a.outdir, "apple")
    os.makedirs(out, exist_ok=True)
    for src in a.inputs:
        raw = open(src, "rb").read()
        xml_bytes = der_payload(raw)
        plist = load_plist(xml_bytes)
        key = next(iter(plist)) if isinstance(plist, dict) else None
        entries = plist[key] if key else plist
        blob = plist_to_bin_mtp(entries)
        kiwi = "Kiwi" in src
        if kiwi:
            blob = cut_kiwi_optional_ops(blob)
        name = "tpkiwifw-k114c.bin" if kiwi else "tpmtfw-k114c.bin"
        dst = os.path.join(out, name)
        open(dst, "wb").write(blob)
        h = hashlib.sha256(blob).hexdigest()
        print(f"{name}: {len(blob)} bytes sha256 {h}")


if __name__ == "__main__":
    main()
