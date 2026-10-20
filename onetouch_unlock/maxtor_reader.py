#!/usr/bin/env python3
"""Linux DriveLock probe and one-attempt unlock for Maxtor OneTouch II / OneTouch IIIs enclosures.

Protocol reference: Maxtor's 2005 MXOPSWD.sys, DRVIFNT.dll and MaxUtilities.exe;
see docs/PROTOCOL.md.
Runtime requires only Python's standard library and Linux SG_IO.
"""

import argparse
import ctypes
import getpass
import hashlib
import json
import os
import re
import stat
import struct
import sys
from dataclasses import asdict, dataclass
from itertools import islice
from pathlib import Path

SG_IO = 0x2285
SG_NONE, SG_TO_DEVICE, SG_FROM_DEVICE = -1, -2, -3
ENCLOSURES = {
    "OneTouch II": 251000193024,
    "OneTouch IIIs": 1000215674880,
}
SECTOR_SIZE = 512
UNLOCK_CDB = bytes.fromhex("f2 00 00 00 00 00 00 02 00 00")
QA_CDB = bytes.fromhex("ed 00 00 00 00 00 00 00 01 00")


class RecoveryError(Exception):
    pass


class SgIoHeader(ctypes.Structure):
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


def sense_text(data):
    if not data:
        return "no sense data"
    kind = data[0] & 0x7F
    if kind in (0x70, 0x71) and len(data) >= 14:
        key, asc, ascq = data[2] & 15, data[12], data[13]
    elif kind in (0x72, 0x73) and len(data) >= 4:
        key, asc, ascq = data[1] & 15, data[2], data[3]
    else:
        return f"sense={data.hex()}"
    return f"sense={key:02x}/{asc:02x}/{ascq:02x}"


class ScsiDevice:
    def __init__(self, path, writable=False):
        if sys.platform != "linux":
            raise RecoveryError("Run this tool in the Ubuntu VM or on Linux")
        self.fd = os.open(path, (os.O_RDWR if writable else os.O_RDONLY) | os.O_CLOEXEC)
        mode = os.fstat(self.fd).st_mode
        if not (stat.S_ISBLK(mode) or stat.S_ISCHR(mode)):
            os.close(self.fd)
            raise RecoveryError("Target must be a block or SCSI generic device")
        self.writable = writable
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
        self.libc.ioctl.restype = ctypes.c_int

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def command(self, cdb, *, read=0, write=None, exact=True):
        if not 1 <= len(cdb) <= 16 or not 0 <= read <= 4096:
            raise ValueError("Unbounded SCSI request")
        if write is not None and (
            not self.writable or cdb != UNLOCK_CDB or len(write) != 512 or read
        ):
            raise ValueError("Only the verified 512-byte unlock data-out command is allowed")
        if write is None and cdb[0] not in (0x12, 0x25, 0x28, 0xED):
            raise ValueError("Unsupported read command")
        size = len(write) if write is not None else read
        command = (ctypes.c_ubyte * len(cdb)).from_buffer_copy(cdb)
        payload = (ctypes.c_ubyte * max(1, size))()
        if write is not None:
            ctypes.memmove(payload, write, size)
        sense = (ctypes.c_ubyte * 64)()
        header = SgIoHeader(
            interface_id=ord("S"),
            dxfer_direction=SG_TO_DEVICE
            if write is not None
            else SG_FROM_DEVICE
            if read
            else SG_NONE,
            cmd_len=len(cdb),
            mx_sb_len=len(sense),
            dxfer_len=size,
            dxferp=ctypes.addressof(payload),
            cmdp=ctypes.addressof(command),
            sbp=ctypes.addressof(sense),
            timeout=30000,
        )
        try:
            if self.libc.ioctl(self.fd, SG_IO, ctypes.byref(header)) < 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            if header.status or header.host_status or header.driver_status or header.info & 1:
                detail = sense_text(bytes(sense[: header.sb_len_wr]))
                raise RecoveryError(
                    f"SCSI {cdb[0]:02x}: status={header.status:#x}, "
                    f"host={header.host_status:#x}, driver={header.driver_status:#x}, {detail}"
                )
            if not 0 <= header.resid <= size or (exact and header.resid):
                raise RecoveryError(f"SCSI {cdb[0]:02x}: unexpected residual {header.resid}/{size}")
            return bytes(payload[: size - header.resid]) if read else b""
        finally:
            if write is not None:
                ctypes.memset(payload, 0, size)

    def inquiry(self):
        return self.command(bytes.fromhex("12 00 00 00 60 00"), read=96, exact=False)

    def vpd(self, page):
        raw = self.command(bytes((0x12, 1, page, 0, 255, 0)), read=255, exact=False)
        return parse_vpd(raw, page)


def parse_vpd(raw, page):
    if len(raw) < 4 or raw[1] != page:
        raise RecoveryError(f"Invalid VPD {page:02x} header")
    length = int.from_bytes(raw[2:4], "big")
    if length > len(raw) - 4:
        raise RecoveryError(f"Truncated VPD {page:02x}: expected {length}, got {len(raw) - 4}")
    return raw[: length + 4]


def parse_inquiry(raw):
    if len(raw) < 36 or raw[4] + 5 < 36:
        raise RecoveryError("Truncated standard INQUIRY")
    return {
        "peripheral": raw[0],
        "vendor": raw[8:16].decode("ascii", "replace").strip(),
        "product": raw[16:32].decode("ascii", "replace").strip(),
        "revision": raw[32:36].decode("ascii", "replace").strip(),
    }


def require_onetouch(identity):
    if identity["vendor"] != "Maxtor" or identity["product"] not in ENCLOSURES:
        raise RecoveryError(
            "Expected Maxtor OneTouch II or OneTouch IIIs; "
            f"got {identity['vendor']!r} {identity['product']!r}"
        )
    if identity["peripheral"] & 31 != 0:
        raise RecoveryError("Selected peripheral is not a direct-access disk")


def discover_one_touch(sys_class=Path("/sys/class"), dev_root=Path("/dev")):
    """Find one exact enclosure in sysfs; SG aliases take priority over disks."""
    matches = {}
    observed = []
    for kind, pattern in (("scsi_generic", r"sg[0-9]+"), ("block", r"sd[a-z]+")):
        directory = sys_class / kind
        if not directory.exists():
            continue
        entries = list(islice(directory.iterdir(), 257))
        if len(entries) > 256:
            raise RecoveryError("SCSI inventory exceeds the discovery limit")
        for entry in sorted(entries):
            if re.fullmatch(pattern, entry.name) is None:
                continue
            path = dev_root / entry.name
            try:
                backing = (entry / "device").resolve(strict=True)
                vendor = (backing / "vendor").read_text(encoding="ascii").strip()
                model = (backing / "model").read_text(encoding="ascii").strip()
            except (FileNotFoundError, UnicodeError):
                continue
            if not path.exists():
                continue
            if len(observed) < 12:
                observed.append(f"{path}: {vendor} {model}")
            if vendor == "Maxtor" and model in ENCLOSURES:
                matches.setdefault(backing, str(path))
    if len(matches) == 1:
        return next(iter(matches.values()))
    if matches:
        raise RecoveryError(
            "More than one OneTouch enclosure found; specify a device: "
            + ", ".join(matches.values())
        )
    inventory = "; ".join(observed) or "no SCSI devices found"
    raise RecoveryError(
        "No Maxtor OneTouch II or OneTouch IIIs is visible. "
        "Connect that enclosure to Ubuntu in Fusion. Observed: " + inventory
    )


@dataclass(frozen=True)
class SecurityStatus:
    supported: bool
    enabled: bool
    locked: bool
    attempts_exceeded: bool
    erasing: bool


def security_status(raw):
    raw = parse_vpd(raw, 0xC0)
    if len(raw) < 7:
        raise RecoveryError("Security VPD is too short")
    return SecurityStatus(
        bool(raw[5] & 1), bool(raw[5] & 2), bool(raw[5] & 4), bool(raw[5] & 16), bool(raw[6] & 1)
    )


def credential(text):
    encoded = text.encode("utf-16-le")
    if len(encoded) > 4096:
        raise RecoveryError("Password/answer exceeds the bounded input size")
    return hashlib.sha1(encoded).digest() + bytes(12)


def unlock_payload(derived):
    if len(derived) != 32:
        raise ValueError("Credential must contain 32 bytes")
    return bytes(2) + derived + bytes(478)


def record_checksum(data):
    first = second = 0
    for value in data:
        first = (first + value) & 255
        second = (second + first) & 255
    return bytes((first, second))


def parse_question_record(raw):
    if len(raw) != 512 or raw[:8] != b"Mxtr#1.0" or raw[8:10] != b"\x01\x00":
        raise RecoveryError("Unsupported Maxtor question record")
    if record_checksum(raw[:510]) != raw[510:512]:
        raise RecoveryError("Question record checksum failed")
    try:
        question = raw[0x10:0x70].decode("utf-16-le").split("\0", 1)[0]
    except UnicodeDecodeError as exc:
        raise RecoveryError("Invalid UTF-16 question") from exc
    return question, raw[0x70:0x90]


def read_question(device, features):
    if 0x0B not in features:
        raise RecoveryError("Enclosure does not advertise discrete storage")
    return parse_question_record(device.command(QA_CDB, read=512))


def identify(device, expected_serial=None):
    identity = parse_inquiry(device.inquiry())
    require_onetouch(identity)
    serial_raw = device.vpd(0x80)[4:]
    serial = serial_raw.decode("ascii", "strict").strip("\0 ")
    if not serial or any(ord(ch) < 32 or ord(ch) > 126 for ch in serial):
        raise RecoveryError("Missing or invalid enclosure serial number")
    identity["serial"] = serial
    if expected_serial is not None and serial != expected_serial:
        raise RecoveryError(f"Serial mismatch: expected {expected_serial!r}, got {serial!r}")
    features = device.vpd(0xC1)[4:]
    if 0x0C not in features:
        raise RecoveryError("Enclosure does not advertise DriveLock security")
    return identity, features, security_status(device.vpd(0xC0))


def check_ready_to_unlock(status):
    if not status.supported or not status.enabled or not status.locked:
        raise RecoveryError("DriveLock is not supported, enabled, and locked; no unlock sent")
    if status.attempts_exceeded or status.erasing:
        raise RecoveryError("Drive reports exhausted attempts or active erase; no unlock sent")


def check_unlock_result(status):
    if (
        not status.supported
        or not status.enabled
        or status.locked
        or status.attempts_exceeded
        or status.erasing
    ):
        raise RecoveryError(
            f"Unlock command returned an inconsistent security status: {asdict(status)}"
        )


def read_capacity(device, expected_size):
    raw = device.command(bytes.fromhex("25 00 00 00 00 00 00 00 00 00"), read=8)
    last_lba, block_size = struct.unpack(">II", raw)
    if last_lba == 0xFFFFFFFF:
        raise RecoveryError("READ CAPACITY(16) required; outside this disk's expected geometry")
    capacity = (last_lba + 1) * block_size
    if block_size != SECTOR_SIZE or capacity != expected_size:
        raise RecoveryError(f"Unexpected capacity: {capacity} bytes, {block_size}-byte blocks")
    return capacity


def read_sample(device, lba, expected_size):
    capacity = read_capacity(device, expected_size)
    if not 0 <= lba <= capacity // SECTOR_SIZE - 8:
        raise RecoveryError("Sample would extend beyond the disk")
    cdb = struct.pack(">BBIBHB", 0x28, 0, lba, 0, 8, 0)
    data = device.command(cdb, read=4096)
    return {
        "lba": lba,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "all_zero": not any(data),
        "capacity_bytes": capacity,
    }


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="action", required=True)
    probe = sub.add_parser("probe", help="read identity and DriveLock status")
    probe.add_argument("device", nargs="?", help="device path; omit to find the original enclosure")
    probe.add_argument(
        "--question", action="store_true", help="also read the saved security question"
    )
    unlock = sub.add_parser("unlock", help="send exactly one password/answer unlock attempt")
    unlock.add_argument("device")
    unlock.add_argument("--expect-serial", required=True, help="serial printed by probe")
    unlock.add_argument("--answer", action="store_true", help="use the saved security answer")
    read = sub.add_parser("read", help="verify a 4-KiB sector read without displaying its contents")
    read.add_argument("device")
    read.add_argument("--expect-serial", required=True)
    read.add_argument("--lba", type=int, default=0)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if sys.platform != "linux":
            raise RecoveryError("Run this tool in the Ubuntu VM or on Linux")
        path = args.device if args.device is not None else discover_one_touch()
        with ScsiDevice(path, writable=args.action == "unlock") as device:
            identity, features, status = identify(device, getattr(args, "expect_serial", None))
            if args.action == "probe":
                result = {
                    "device": path,
                    "identity": identity,
                    "features": [f"{value:02x}" for value in features],
                    "security": asdict(status),
                }
                if args.question:
                    result["question"] = read_question(device, features)[0]
            elif args.action == "unlock":
                check_ready_to_unlock(status)
                if args.answer:
                    question, encoded = read_question(device, features)
                    print(f"Security question: {question}", file=sys.stderr)
                    answer = credential(getpass.getpass("Security answer: "))
                    derived = bytes(a ^ b for a, b in zip(encoded, answer, strict=True))
                else:
                    derived = credential(getpass.getpass("DriveLock password: "))
                # Recheck the same open device after the interactive prompt.
                _, _, status = identify(device, args.expect_serial)
                check_ready_to_unlock(status)
                device.command(UNLOCK_CDB, write=unlock_payload(derived))
                after = security_status(device.vpd(0xC0))
                check_unlock_result(after)
                result = {
                    "identity": identity,
                    "security": asdict(after),
                    "sample": read_sample(device, 0, ENCLOSURES[identity["product"]]),
                }
            else:
                if status.locked or status.erasing:
                    raise RecoveryError("Disk is locked or erasing")
                result = {
                    "identity": identity,
                    "sample": read_sample(device, args.lba, ENCLOSURES[identity["product"]]),
                }
            print(json.dumps(result, indent=2))
        return 0
    except (RecoveryError, OSError, UnicodeError, EOFError) as exc:
        print(f"maxtor_reader: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
