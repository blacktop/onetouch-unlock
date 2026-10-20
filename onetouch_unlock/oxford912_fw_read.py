#!/usr/bin/env python3
"""Read Oxford 912's 64-KiB internal firmware through Linux FireWire cdev.

The only writes select firmware or timestamp data through the read cursor. There are no
flash, erase, reset, mode-switch, or arbitrary-address commands in this tool.
Requires a real FireWire controller and the original OneTouch II enclosure.
"""

import argparse
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
import re
import select
import stat
import struct
import sys
import time
from pathlib import Path

CSR_VERSION = 0xFFFFF0050000
CSR_HW_VERSION = 0xFFFFF0090020
READ_CURSOR = 0xFFFFF0090014
TIMESTAMP_SELECTOR = 0xFFFFFFF0
FLASH_SIZE = 0x10000


class FirmwareError(Exception):
    pass


class BusReset(ctypes.Structure):
    _fields_ = [
        ("closure", ctypes.c_uint64),
        ("type", ctypes.c_uint32),
        ("node_id", ctypes.c_uint32),
        ("local_node_id", ctypes.c_uint32),
        ("bm_node_id", ctypes.c_uint32),
        ("irm_node_id", ctypes.c_uint32),
        ("root_node_id", ctypes.c_uint32),
        ("generation", ctypes.c_uint32),
    ]


class GetInfo(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("rom_length", ctypes.c_uint32),
        ("rom", ctypes.c_uint64),
        ("bus_reset", ctypes.c_uint64),
        ("bus_reset_closure", ctypes.c_uint64),
        ("card", ctypes.c_uint32),
    ]


class SendRequest(ctypes.Structure):
    _fields_ = [
        ("tcode", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("closure", ctypes.c_uint64),
        ("data", ctypes.c_uint64),
        ("generation", ctypes.c_uint32),
    ]


def ioctl_number(direction, number, structure):
    return direction << 30 | ctypes.sizeof(structure) << 16 | ord("#") << 8 | number


def validate_version(version):
    if version >> 20 != 0x912:
        raise FirmwareError(f"Not an Oxford 912 firmware version: {version:#010x}")


def validate_reset_vector(word):
    if word & 0xFF000000 == 0xEA000000:
        offset = word & 0xFFFFFF
        if offset & 0x800000:
            offset -= 0x1000000
        target = 8 + 4 * offset
        if 0 <= target < FLASH_SIZE:
            return
    if word & 0xFFFFF000 == 0xE59FF000:
        return
    raise FirmwareError(f"First firmware word is not a plausible ARM reset vector: {word:#010x}")


def parse_timestamp(raw):
    if len(raw) != 24 or raw[0] == 0:
        raise FirmwareError("Missing Oxford normal-firmware timestamp")
    parts = [part for part in raw.split(b"\0") if part]
    if len(parts) != 2:
        raise FirmwareError("Malformed Oxford firmware timestamp")
    clock = date = None
    for part in parts:
        if re.fullmatch(rb"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]", part):
            clock = part.decode("ascii")
        match = re.fullmatch(
            rb"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([ 0-3][0-9]) ([0-9]{4})", part
        )
        if match:
            month = (
                b"Jan",
                b"Feb",
                b"Mar",
                b"Apr",
                b"May",
                b"Jun",
                b"Jul",
                b"Aug",
                b"Sep",
                b"Oct",
                b"Nov",
                b"Dec",
            ).index(match[1]) + 1
            try:
                date = datetime.date(int(match[3]), month, int(match[2])).isoformat()
            except ValueError as exc:
                raise FirmwareError("Invalid Oxford firmware date") from exc
    if clock is None or date is None:
        raise FirmwareError("Oxford normal-firmware timestamp was not recognized")
    return f"{date} {clock}"


class FireWireDevice:
    def __init__(self, path):
        if sys.platform != "linux" or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise FirmwareError("This reader supports 64-bit Linux FireWire cdev")
        path = Path(path).resolve()
        if path.parent != Path("/dev") or re.fullmatch(r"fw[0-9]+", path.name) is None:
            raise FirmwareError("Expected an exact /dev/fwN character device")
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            if not stat.S_ISCHR(os.fstat(self.fd).st_mode):
                raise FirmwareError("Target is not a FireWire character device")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.libc = ctypes.CDLL(None, use_errno=True)
            self.libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
            self.libc.ioctl.restype = ctypes.c_int
            rom = (ctypes.c_uint32 * 256)()
            reset = BusReset()
            info = GetInfo(
                version=5,
                rom_length=ctypes.sizeof(rom),
                rom=ctypes.addressof(rom),
                bus_reset=ctypes.addressof(reset),
                bus_reset_closure=0,
            )
            self.ioctl(ioctl_number(3, 0, GetInfo), info)
            if info.version < 1 or not 20 <= info.rom_length <= ctypes.sizeof(rom):
                raise FirmwareError("Invalid FireWire configuration ROM")
            if reset.node_id == reset.local_node_id:
                raise FirmwareError("Selected the local FireWire controller")
            self.guid = rom[3] << 32 | rom[4]
            self.generation = reset.generation
            self.sequence = 0
            self.deadline = time.monotonic() + 180
            sysfs = Path("/sys/bus/firewire/devices")
            node = sysfs / path.name
            if int((node / "guid").read_text().strip(), 16) != self.guid:
                raise FirmwareError("FireWire node changed during identity check")
            candidates = [node, *sorted(sysfs.glob(path.name + ".*"))]
            identified = False
            for candidate in candidates:
                try:
                    vendor = (candidate / "vendor_name").read_text().strip()
                    model = (candidate / "model_name").read_text().strip()
                except FileNotFoundError:
                    continue
                if vendor == "Maxtor" and model == "OneTouch II":
                    identified = True
                    break
            if not identified:
                raise FirmwareError("Configuration ROM does not identify a Maxtor OneTouch II")
        except BaseException:
            os.close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def ioctl(self, number, argument):
        if self.libc.ioctl(self.fd, number, ctypes.byref(argument)) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    def transaction(self, address, value=None):
        if value is None:
            if address not in (CSR_VERSION, CSR_HW_VERSION, READ_CURSOR):
                raise ValueError("Unsupported CSR read")
        elif address != READ_CURSOR or value not in (0, TIMESTAMP_SELECTOR):
            raise ValueError("Only the firmware and timestamp read-cursor selectors are allowed")
        self.sequence += 1
        payload = ctypes.create_string_buffer(struct.pack(">I", value or 0), 4)
        request = SendRequest(
            tcode=4 if value is None else 0,
            length=4,
            offset=address,
            closure=self.sequence,
            data=ctypes.addressof(payload),
            generation=self.generation,
        )
        self.ioctl(ioctl_number(1, 1, SendRequest), request)
        deadline = min(self.deadline, time.monotonic() + 3)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], max(0, remaining))[0]:
                raise FirmwareError("FireWire request timed out")
            event = os.read(self.fd, 4096)
            if len(event) < 12:
                raise FirmwareError("Truncated FireWire event")
            closure, kind = struct.unpack_from("=QI", event)
            if kind == 0:
                raise FirmwareError("FireWire bus reset during read; reconnect and probe again")
            if kind != 1 or closure != self.sequence or len(event) < 20:
                raise FirmwareError("Unexpected FireWire response")
            rcode, length = struct.unpack_from("=II", event, 12)
            expected = 4 if value is None else 0
            if rcode or length != expected or len(event) < 20 + length:
                raise FirmwareError(f"FireWire CSR {address:#014x}: rcode={rcode}, length={length}")
            return struct.unpack_from(">I", event, 20)[0] if value is None else None

    def identity(self):
        version = self.transaction(CSR_VERSION)
        validate_version(version)
        hardware = self.transaction(CSR_HW_VERSION)
        if hardware != 0x39313241:  # "912A", as consumed by OxsemiDevice.
            raise FirmwareError(f"Unexpected Oxford hardware identity: {hardware:#010x}")
        self.transaction(READ_CURSOR, TIMESTAMP_SELECTOR)
        timestamp = parse_timestamp(
            b"".join(struct.pack("<I", self.transaction(READ_CURSOR)) for _ in range(6))
        )
        result = {
            "guid": f"0x{self.guid:016x}",
            "vendor": "Maxtor",
            "model": "OneTouch II",
            "version": f"0x{version:08x}",
            "hardware_version": f"0x{hardware:08x}",
            "timestamp": timestamp,
            "generation": self.generation,
            "flash_bytes": FLASH_SIZE,
        }
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("probe").add_argument("device")
    dump = commands.add_parser("dump")
    dump.add_argument("device")
    dump.add_argument("output", type=Path)
    dump.add_argument("--expect-guid", required=True, type=lambda text: int(text, 16))
    dump.add_argument("--expect-version", required=True, type=lambda text: int(text, 16))
    args = parser.parse_args(argv)
    try:
        with FireWireDevice(args.device) as device:
            identity = device.identity()
            if args.action == "probe":
                print(json.dumps(identity, indent=2))
                return 0
            if (
                device.guid != args.expect_guid
                or int(identity["version"], 16) != args.expect_version
            ):
                raise FirmwareError("GUID or firmware version changed since probe")
            receipt_path = args.output.with_name(args.output.name + ".json")
            if args.output.exists() or receipt_path.exists():
                raise FirmwareError("Output or receipt already exists")
            device.transaction(READ_CURSOR, 0)
            first = device.transaction(READ_CURSOR)
            validate_reset_vector(first)
            firmware = bytearray(struct.pack("<I", first))
            while len(firmware) < FLASH_SIZE:
                firmware.extend(struct.pack("<I", device.transaction(READ_CURSOR)))
            # Byte order matches the original PPC updater's QuadBuffer::GetArrayOfChars.
            with args.output.open("xb") as output:
                output.write(firmware)
            receipt = {
                "identity": identity,
                "bytes": len(firmware),
                "sha256": hashlib.sha256(firmware).hexdigest(),
                "read_cursor_csr": f"0x{READ_CURSOR:012x}",
                "firmware_start": 0,
                "byte_order": "little-endian ARM words",
            }
            with receipt_path.open("x") as output:
                json.dump(receipt, output, indent=2)
                output.write("\n")
            print(json.dumps(receipt, indent=2))
            return 0
    except (FirmwareError, OSError, ValueError) as exc:
        print(f"oxford912_fw_read: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
