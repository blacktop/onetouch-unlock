#!/usr/bin/env python3
"""Execute the original MaxUtilities hash code in an isolated QEMU x86 guest.

Needs clang, llvm-objcopy, and qemu-system-i386. The guest has no disk or network.
The exact original PE is required; only its pure SHA-1 functions are executed.
"""

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path

BINARY = Path("MaxUtilities.exe")
WORK = Path("qemu-hash")
EXPECTED_SHA256 = "b04cee6ff837e5baaa6a4d6a763cc87fdf8e31d761e059cbc2b8fcad7c17fe9d"
LOAD = 0x100000
REFERENCE_START, REFERENCE_END = 0x456C30, 0x45768A
CONSTANTS_START, CONSTANTS_END = 0x4821CC, 0x4821DC
CASES = (
    "",
    "password",
    "MasterErase",
    "Pässwörd",
    "🔑",
    "a" * 27,
    "a" * 28,
    "a" * 31,
    "a" * 32,
    "a" * 33,
    "a" * 127,
)


def original_bytes(start_va, end_va):
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError("MaxUtilities.exe hash does not match the reference")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise RuntimeError("Not a PE file")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    base = struct.unpack_from("<I", data, optional + 28)[0]
    if (machine, magic, base) != (0x14C, 0x10B, 0x400000):
        raise RuntimeError("Unexpected PE layout")
    for index in range(count):
        section = optional + optional_size + index * 40
        _, rva, size, offset = struct.unpack_from("<IIII", data, section + 8)
        start, end = start_va - base - rva, end_va - base - rva
        if 0 <= start < end <= size:
            return data[offset + start : offset + end]
    raise RuntimeError("Original byte range is not contained in one PE section")


def assembly():
    lines = [
        ".code32",
        ".section .text",
        ".global _start",
        "_start:",
        ".long 0x1badb002, 0x10000, -(0x1badb002 + 0x10000)",
        f".long {LOAD}, {LOAD}, {CONSTANTS_END}, 0x900000, {LOAD + 32}",
        "cli",
        "cld",
        "movl $0x800000, %esp",
    ]
    for index, value in enumerate(CASES):
        length = len(value.encode("utf-16-le"))
        lines += [
            "xorl %eax,%eax",
            "movl $0x820000,%edi",
            "movl $8,%ecx",
            "rep stosl",
            "pushl $0x810000",
            "movl $0x456c30,%eax",
            "call *%eax",
            "addl $4,%esp",
            f"pushl ${length}",
            f"pushl $({LOAD} + input_{index} - _start)",
            "pushl $0x810000",
            "movl $0x457530,%eax",
            "call *%eax",
            "addl $12,%esp",
            "pushl $0x820000",
            "pushl $0x810000",
            "movl $0x457600,%eax",
            "call *%eax",
            "addl $8,%esp",
            "call print_digest",
        ]
    lines += [
        "xorl %eax,%eax",
        "outl %eax,$0xf4",
        "hlt",
        "jmp .-1",
        "print_digest:",
        "movl $0x820000,%esi",
        "movl $32,%ecx",
        "1:",
        "lodsb",
        "movb %al,%bl",
        "shrb $4,%al",
        "call print_nibble",
        "movb %bl,%al",
        "andb $15,%al",
        "call print_nibble",
        "loop 1b",
        "movb $10,%al",
        "outb %al,$0xe9",
        "ret",
        "print_nibble:",
        "cmpb $10,%al",
        "jb 2f",
        "addb $87,%al",
        "jmp 3f",
        "2:",
        "addb $48,%al",
        "3:",
        "outb %al,$0xe9",
        "ret",
    ]
    for index, value in enumerate(CASES):
        data = value.encode("utf-16-le") or b"\0"
        lines += [f"input_{index}:", ".byte " + ",".join(str(b) for b in data)]
    return "\n".join(lines) + "\n"


def command(name):
    found = shutil.which(name)
    if found is None:
        raise RuntimeError(f"Missing required command: {name}")
    return found


def run_guest(image):
    return subprocess.run(
        [
            command("qemu-system-i386"),
            "-machine",
            "pc",
            "-accel",
            "tcg,thread=single",
            "-m",
            "32",
            "-nodefaults",
            "-no-reboot",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-nic",
            "none",
            "-debugcon",
            "stdio",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-kernel",
            str(image),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )


def main():
    global BINARY, WORK
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "binary", type=Path, help="the original MaxUtilities.exe (SHA-256 is verified)"
    )
    parser.add_argument(
        "--work", type=Path, default=WORK, help="scratch directory for the guest image and receipt"
    )
    args = parser.parse_args()
    BINARY, WORK = args.binary, args.work
    WORK.mkdir(parents=True, exist_ok=True)
    source, obj, stub, image = (
        WORK / name for name in ("guest.S", "guest.o", "stub.bin", "guest.bin")
    )
    source.write_text(assembly())
    subprocess.run(
        [command("clang"), "-target", "i386-none-elf", "-c", str(source), "-o", str(obj)],
        check=True,
        timeout=30,
    )
    subprocess.run(
        [command("llvm-objcopy"), "-O", "binary", "-j", ".text", str(obj), str(stub)],
        check=True,
        timeout=30,
    )
    code = stub.read_bytes()
    if len(code) >= REFERENCE_START - LOAD:
        raise RuntimeError("Verification stub overlaps the original code")
    guest = bytearray(CONSTANTS_END - LOAD)
    guest[: len(code)] = code
    guest[REFERENCE_START - LOAD : REFERENCE_END - LOAD] = original_bytes(
        REFERENCE_START, REFERENCE_END
    )
    guest[CONSTANTS_START - LOAD : CONSTANTS_END - LOAD] = original_bytes(
        CONSTANTS_START, CONSTANTS_END
    )
    image.write_bytes(guest)
    result = run_guest(image)
    (WORK / "stdout.txt").write_text(result.stdout)
    (WORK / "stderr.txt").write_text(result.stderr)
    expected = [
        (hashlib.sha1(value.encode("utf-16-le")).digest() + bytes(12)).hex() for value in CASES
    ]
    if result.returncode != 1 or result.stdout.splitlines() != expected:
        raise RuntimeError(f"Reference execution failed (exit {result.returncode}); see {WORK}")
    negative_image = WORK / "guest-negative.bin"
    guest[CONSTANTS_START - LOAD] ^= 1
    negative_image.write_bytes(guest)
    negative = run_guest(negative_image)
    (WORK / "negative-stdout.txt").write_text(negative.stdout)
    if (
        negative.returncode != 1
        or len(negative.stdout.splitlines()) != len(CASES)
        or negative.stdout.splitlines() == expected
    ):
        raise RuntimeError("Mutated original constant table did not fail the compatibility check")
    receipt = {
        "reference_sha256": EXPECTED_SHA256,
        "guest_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "emulated_functions": ["0x456c30", "0x457530", "0x457600"],
        "constant_table": "0x4821cc",
        "matching_cases": len(CASES),
        "mutated_constant_table_rejected": True,
        "result": "SHA1(UTF-16LE without terminator) + 12 zero bytes",
    }
    (WORK / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
