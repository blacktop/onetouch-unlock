import ctypes
import tempfile
import unittest
from pathlib import Path

from onetouch_unlock import maxtor_reader as reader


def vpd(page, payload):
    return bytes((0, page)) + len(payload).to_bytes(2, "big") + payload


def inquiry(vendor=b"Maxtor", product=b"OneTouch II"):
    return bytes((0, 0, 0, 0, 31, 0, 0, 0)) + vendor.ljust(8) + product.ljust(16) + b"0200"


class ReferenceDevice:
    def __init__(self, *, model=b"OneTouch II", serial=b"SERIAL", features=b"\x0b\x0c", flags=7):
        self.model, self.serial, self.features, self.flags = model, serial, features, flags
        self.calls = []

    def inquiry(self):
        self.calls.append("inquiry")
        return inquiry(product=self.model)

    def vpd(self, page):
        self.calls.append(page)
        return {
            0x80: vpd(page, self.serial),
            0xC1: vpd(page, self.features),
            0xC0: vpd(page, bytes((0, self.flags, 0))),
        }[page]


class ProtocolTests(unittest.TestCase):
    def discovery_fixture(self, root, number, vendor, model, *, disk=True, generic=True):
        backing = root / "devices" / str(number)
        backing.mkdir(parents=True)
        (backing / "vendor").write_text(vendor + "\n")
        (backing / "model").write_text(model + "\n")
        for kind, name, enabled in (
            ("scsi_generic", f"sg{number}", generic),
            ("block", "sd" + chr(ord("a") + number), disk),
        ):
            if not enabled:
                continue
            entry = root / "class" / kind / name
            entry.mkdir(parents=True)
            (entry / "device").symlink_to(backing, target_is_directory=True)
            (root / "dev").mkdir(exist_ok=True)
            (root / "dev" / name).touch()

    def test_discovery_deduplicates_aliases_and_prefers_sg(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.discovery_fixture(root, 0, "Initio", "6L250R0")
            self.discovery_fixture(root, 1, "Maxtor  ", "OneTouch II     ")
            self.assertEqual(
                reader.discover_one_touch(root / "class", root / "dev"), str(root / "dev/sg1")
            )

    def test_discovery_rejects_two_enclosures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.discovery_fixture(root, 0, "Maxtor", "OneTouch II")
            self.discovery_fixture(root, 1, "Maxtor", "OneTouch II")
            with self.assertRaisesRegex(reader.RecoveryError, "More than one"):
                reader.discover_one_touch(root / "class", root / "dev")

    def test_discovery_reports_initio_without_selecting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.discovery_fixture(root, 0, "Initio", "6L250R0", generic=False)
            with self.assertRaisesRegex(reader.RecoveryError, "Initio 6L250R0"):
                reader.discover_one_touch(root / "class", root / "dev")

    def test_linux_64_bit_sg_abi(self):
        self.assertEqual(ctypes.sizeof(reader.SgIoHeader), 88)
        self.assertEqual(reader.SgIoHeader.dxferp.offset, 16)
        self.assertEqual(reader.SgIoHeader.status.offset, 64)
        self.assertEqual(reader.SgIoHeader.info.offset, 80)

    def test_reference_password_vector(self):
        # SHA-1 of UTF-16LE "password"; independently checked by original x86 code.
        self.assertEqual(
            reader.credential("password").hex(),
            "e8f97fba9104d1ea5047948e6dfb67facd9f5b73000000000000000000000000",
        )
        data = reader.unlock_payload(reader.credential("password"))
        self.assertEqual(len(data), 512)
        self.assertEqual(data[:2], b"\0\0")
        self.assertEqual(data[34:], bytes(478))
        self.assertEqual(reader.UNLOCK_CDB.hex(), "f2000000000000020000")

    def test_rejected_identity_stops_before_vendor_commands(self):
        device = ReferenceDevice(model=b"6L250R0")
        with self.assertRaises(reader.RecoveryError):
            reader.identify(device)
        self.assertEqual(device.calls, ["inquiry"])

    def test_wrong_serial_stops_before_feature_or_status_commands(self):
        device = ReferenceDevice()
        with self.assertRaises(reader.RecoveryError):
            reader.identify(device, "WRONG")
        self.assertEqual(device.calls, ["inquiry", 0x80])

    def test_missing_security_advertisement(self):
        device = ReferenceDevice(features=b"\x0b")
        with self.assertRaises(reader.RecoveryError):
            reader.identify(device)
        self.assertNotIn(0xC0, device.calls)

    def test_every_unlock_gate(self):
        good = reader.security_status(vpd(0xC0, b"\0\x07\0"))
        reader.check_ready_to_unlock(good)
        for flags, erase in ((6, 0), (5, 0), (3, 0), (23, 0), (7, 1)):
            with self.subTest(flags=flags, erase=erase), self.assertRaises(reader.RecoveryError):
                reader.check_ready_to_unlock(
                    reader.security_status(vpd(0xC0, bytes((0, flags, erase))))
                )

    def test_truncated_vpd_rejected(self):
        for raw in (b"", b"\0\xc0\0\xff", b"\0\xc1\0\0"):
            with self.subTest(raw=raw), self.assertRaises(reader.RecoveryError):
                reader.security_status(raw)

    def test_unlock_success_requires_supported_and_enabled(self):
        reader.check_unlock_result(reader.security_status(vpd(0xC0, b"\0\x03\0")))
        for flags, erase in ((0, 0), (1, 0), (2, 0), (7, 0), (19, 0), (3, 1)):
            with self.subTest(flags=flags, erase=erase), self.assertRaises(reader.RecoveryError):
                reader.check_unlock_result(
                    reader.security_status(vpd(0xC0, bytes((0, flags, erase))))
                )

    def test_question_validation_and_answer_reconstruction(self):
        raw = bytearray(512)
        raw[:10] = b"Mxtr#1.0\x01\0"
        question = "First pet?".encode("utf-16-le")
        raw[0x10 : 0x10 + len(question)] = question
        password, answer = reader.credential("secret"), reader.credential("Spot")
        raw[0x70:0x90] = bytes(a ^ b for a, b in zip(password, answer, strict=True))
        raw[510:] = reader.record_checksum(raw[:510])
        parsed_question, encoded = reader.parse_question_record(bytes(raw))
        self.assertEqual(parsed_question, "First pet?")
        self.assertEqual(bytes(a ^ b for a, b in zip(encoded, answer, strict=True)), password)
        for offset in (0, 8, 0x10, 0x70, 510, 511):
            bad = bytearray(raw)
            bad[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(reader.RecoveryError):
                reader.parse_question_record(bytes(bad))

    def test_no_secret_in_cli_arguments(self):
        options = reader.parser().format_help()
        self.assertNotIn("--password", options)

    def test_onetouch_iiis_identity_accepted(self):
        device = ReferenceDevice(model=b"OneTouch IIIs", serial=b"3SER1AL7")
        identity, features, status = reader.identify(device, "3SER1AL7")
        self.assertEqual(identity["product"], "OneTouch IIIs")
        self.assertEqual(identity["serial"], "3SER1AL7")
        self.assertTrue(status.supported and status.enabled and status.locked)
        self.assertFalse(status.attempts_exceeded or status.erasing)
        self.assertEqual(reader.ENCLOSURES[identity["product"]], 1000215674880)

    def test_discovery_accepts_onetouch_iiis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.discovery_fixture(root, 1, "Maxtor  ", "OneTouch IIIs   ")
            self.assertEqual(
                reader.discover_one_touch(root / "class", root / "dev"), str(root / "dev/sg1")
            )

    def test_read_capacity_is_checked_against_the_identified_enclosure(self):
        class CapacityDevice:
            def command(self, cdb, *, read=0, write=None, exact=True):
                return (1953546239).to_bytes(4, "big") + (512).to_bytes(4, "big")

        device = CapacityDevice()
        self.assertEqual(
            reader.read_capacity(device, reader.ENCLOSURES["OneTouch IIIs"]), 1000215674880
        )
        with self.assertRaises(reader.RecoveryError):
            reader.read_capacity(device, reader.ENCLOSURES["OneTouch II"])


if __name__ == "__main__":
    unittest.main()
