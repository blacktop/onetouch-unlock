import ctypes
import struct
import unittest

from onetouch_unlock import oxford912_fw_read as firmware


class FirmwareProtocolTests(unittest.TestCase):
    def test_timestamp_from_original_owc_firmware(self):
        original = b"12:48:46\0\0\0\0Jan 14 2005\0"
        self.assertEqual(firmware.parse_timestamp(original), "2005-01-14 12:48:46")
        for bad in (
            bytes(24),
            original[:23],
            original.replace(b"48", b"68"),
            original.replace(b"Jan 14", b"Feb 31"),
            original.replace(b"Jan", b"???"),
        ):
            with self.subTest(raw=bad), self.assertRaises(firmware.FirmwareError):
                firmware.parse_timestamp(bad)

    def test_linux_firewire_cdev_abi(self):
        self.assertEqual(ctypes.sizeof(firmware.BusReset), 40)
        self.assertEqual(ctypes.sizeof(firmware.GetInfo), 40)
        self.assertEqual(ctypes.sizeof(firmware.SendRequest), 40)
        self.assertEqual(firmware.ioctl_number(3, 0, firmware.GetInfo), 0xC0282300)
        self.assertEqual(firmware.ioctl_number(1, 1, firmware.SendRequest), 0x40282301)

    def test_oxford_version_and_reset_vector_guards(self):
        firmware.validate_version(0x91210200)
        firmware.validate_reset_vector(0xEA00000C)
        self.assertEqual(struct.pack("<I", 0xEA00000C), bytes.fromhex("0c0000ea"))
        for value in (0, 0x91110200, 0xFFFFFFFF):
            with self.subTest(version=value), self.assertRaises(firmware.FirmwareError):
                firmware.validate_version(value)
        for value in (0, 0xFFFFFFFF, 0xEA7FFFFF, 0xEAFFFFFD, 0x0C0000EA):
            with self.subTest(vector=value), self.assertRaises(firmware.FirmwareError):
                firmware.validate_reset_vector(value)


if __name__ == "__main__":
    unittest.main()
