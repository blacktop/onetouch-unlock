# Maxtor OneTouch DriveLock protocol

Recovered from the original 2005 Maxtor software by static analysis and an emulated execution check.
Verified on real hardware against a OneTouch II (Oxford 912, firmware `023g`) and a OneTouch IIIs
(Oxford 924, firmware `0338`), both successfully unlocked.

## Sources and provenance

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `onetouch-iii-install.iso` | [Archived original 2005 Maxtor installation CD](https://archive.org/download/MaxtorOneTouchIIIInstallationSoftware/Install%20CD.iso) | `38125d05dc9f3a5c33fb49ae059efad092d7ba640f920b38321f30dd2de60760` |
| `drivers/security/MXOPSWD.sys` | CD above | `3ffb5acc3a0e8dd45c33c11be9772f01fbeb902d9e5ad4dc5130aadabd1bf947` |
| `app/DRVIFNT.dll` | Original installer, extracted offline | `925000bc0de0cbaee8d1ab399eae66c5c9bc04006476afb0c88ff1f1d846cccc` |
| `app/MaxUtilities.exe` | Original installer, extracted offline | `b04cee6ff837e5baaa6a4d6a763cc87fdf8e31d761e059cbc2b8fcad7c17fe9d` |
| `OWC_912_Config.zip` | [Original OWC download](https://eshop.macsales.com/tech_center/manuals/mercuryfirewire/format/raid/OWC_912_Config.zip) | `358265dae470da2b2baba0c7ff36fadbb975aefa9d6fd05940d1971bc3cd7fe8` |
| `FW912_v1_02_0300.bin` | OWC archive above | `41b94b3abe9bb672c03af26a0266be27473d8fb1fe7e6d0bd2f07dcc23e9ef13` |

The security driver's INF (`mxopswd.inf`) binds to `USBSTOR\DiskMaxtor__OneTouch_II`,
`OneTouch_III`, `OneTouch_IIIm` and `OneTouch_IIIs`, and to the same models over SBP-2 (FireWire).
The protocol below therefore applies to the whole OneTouch II/III family.

## Host protocol

Addresses refer to the exact binaries above.

| Operation | Evidence and framing |
| --- | --- |
| Feature discovery | `MXOPSWD.sys:0x115ce`; `DRVIFNT.dll:0x10005689`. INQUIRY EVPD page `C1` lists feature bytes: `0x0c` = security, `0x0b` = discrete storage (the saved question). |
| Security status | `DRVIFNT.dll:0x10007740`. INQUIRY EVPD page `C0`, byte 5 bits 0/1/2/4 = supported/enabled/locked/attempts-exceeded; byte 6 bit 0 = erasing. |
| Credential | `MaxUtilities.exe:0x40c570`: SHA-1 of the exact UTF-16LE bytes of the string (no terminator), padded with 12 zero bytes to 32 bytes. |
| Unlock | `MaxUtilities.exe:0x4564b0` → IOCTL `0x230014` → `MXOPSWD.sys:0x11d9c` / `DRVIFNT.dll:0x10004140`: CDB `f2 00 00 00 00 00 00 02 00 00`, 512 bytes data-out: zero 16-bit control word, the 20-byte digest, 490 zero bytes. |
| Saved question | `DRVIFNT.dll:0x100042f0`; `MaxUtilities.exe:0x456910`. CDB `ed 00 00 00 00 00 00 00 01 00` reads discrete record 0: 512 bytes, signature `Mxtr#1.0`, version 1.0, UTF-16LE question at `0x10..0x6f`, encoded credential at `0x70..0x8f`, bytes 510/511 a rolling byte sum and sum-of-sums over the first 510 bytes. |
| Answer recovery | `MaxUtilities.exe:0x40c650` / `0x40c780`: the stored credential is the XOR of the padded password hash and the padded answer hash; XOR with the answer hash recovers the unlock credential. |

The vendor opcodes mirror ATA security one for one: `F1` set password, `F2` unlock, `F4` erase, `F6`
disable, each with the 512-byte ATA password-sector layout as payload. The enclosure passes them to
the disk, so the lock lives on the disk as ATA security. The application sets a fixed master password
(derived from a constant string) at enable time and sets the user password with the *maximum*
capability flag (`0x0100` in the control word), so the master can only erase, never unlock.

### Input rules of the original dialogs

From the dialog resources in `MaxUtilities.exe`:

- Password: case-sensitive, "six or more characters and one number required".
- Security answer: the edit controls carry `ES_LOWERCASE`, so answers were lowercased on entry;
  20 characters maximum. The question came from a fixed drop-down list.

### Observed responses on real hardware

| Situation | Response |
| --- | --- |
| Read while locked, OneTouch IIIs | sense key *Data Protect*, ASC/ASCQ `F0/01` |
| Read while locked, OneTouch II | sense key *Illegal Request*, ASC/ASCQ `F0/01` |
| Unlock with a wrong credential | CHECK CONDITION, sense `05/F0/00`; lock state unchanged |
| Fifth wrong attempt since power-on | `attempts_exceeded` set; cleared by a power cycle |
| Successful unlock | `locked` clears; the bridge then resets its USB link once |
| No saved question | the `ED` read returns success with zero bytes |
| READ CAPACITY(10) on the Oxford 912 | last LBA reported one too high (block count instead of last block); READ CAPACITY(16) unsupported |

## Credential verification

`verify_maxtor_hash.py` extracts the original SHA-1 routines (`0x456c30`, `0x457530`, `0x457600`)
and their constant table (`0x4821cc`) from `MaxUtilities.exe`, runs them in a minimal Multiboot guest
under QEMU with no disk or network, and compares 11 inputs (empty, ASCII, Unicode, a non-BMP character,
block and padding boundaries) with Python's SHA-1; a mutated constant table must fail. This proves the
derivation, independent of any hardware.

## Oxford 912 firmware reader

From the symbol-rich OWC updater (PowerPC) and an independent OWC ARM firmware image:

- `FWTransport::GetFirmwareQuadlets` (`0x269bc`) writes the start address to CSR `0xfffff0090014`,
  then reads successive quadlets from the same CSR; the 912 has 65536 bytes of internal flash.
- CSR `0xfffff0050000` carries the firmware family (top 12 bits `0x912`); hardware CSR
  `0xfffff0090020` must read `912A`; the normal-firmware timestamp is selected through cursor
  `0xfffffff0`.
- In the ARM image, a write to that CSR sets a RAM cursor (`0x986..0x9a6`) and a read advances it by
  four (`0xedc..0xef0`).

`oxford912_fw_read.py` implements the read path over the Linux FireWire character device. Its only
data-out transactions select the timestamp or set the cursor to zero; it never switches modes or writes
flash. It requires a real FireWire controller and has not been run on hardware.
