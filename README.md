# onetouch-unlock

Probe and unlock **Maxtor OneTouch II / OneTouch III** external drives that were locked with Maxtor's
"DriveLock" feature, using **your own** password or security answer. Read-only on the disk, one unlock
attempt per run, Linux only.

Maxtor's software and its Windows-only drivers are long gone. These enclosures (Oxford 912/924 bridges)
still answer the vendor SCSI commands that software used. This tool reimplements the host side of that
protocol, recovered from the original 2005 installation CD (see `docs/PROTOCOL.md` for the evidence
and provenance), so a locked OneTouch can be opened on a modern machine.

## What a locked OneTouch looks like

- macOS / Windows see the enclosure but report **no media**.
- Linux sees the disk with its real size, but every read fails with sense key *Data Protect* or
  *Illegal Request* and vendor code `F0/01`.
- The bare disk pulled out of the enclosure refuses every read on a USB adapter: the lock is **ATA security
  on the disk itself**, set through the enclosure. Pulling the disk does not bypass it, and neither does
  anything else: the software's built-in master credential is set at *maximum* capability, so it can only
  erase. You need the password or the security answer.

## Requirements

- Linux with the `sg` driver (`sudo modprobe sg`). A VM with USB passthrough works.
- The OneTouch connected **through its own enclosure** over USB. Generic USB bridges do not forward the
  vendor commands; the tool refuses the known-bad Initio `13fd:1040` adapter explicitly.
- Enough power: a 12 V **3 A** supply. On a 2 A brick these drives brown out at spin-up and never
  enumerate.
- Python 3.10+. No third-party packages.

## Usage

```sh
sudo modprobe sg
sudo python3 -m onetouch_unlock.maxtor_reader probe                       # finds one enclosure, prints identity + lock state
sudo python3 -m onetouch_unlock.maxtor_reader probe /dev/sg1 --question   # also shows the saved security question
sudo python3 -m onetouch_unlock.maxtor_reader unlock /dev/sg1 --expect-serial SERIAL            # password
sudo python3 -m onetouch_unlock.maxtor_reader unlock /dev/sg1 --expect-serial SERIAL --answer   # security answer
sudo python3 -m onetouch_unlock.maxtor_reader read /dev/sg1 --expect-serial SERIAL              # verify a 4 KiB read
```

The credential is prompted for, never passed on the command line. After a successful unlock the enclosure
usually resets its USB link once; reconnect it and re-run `probe` to confirm `locked: false`. The lock
re-engages only when the enclosure loses power. Mount the volume read-only and copy your data off.

### Things learned the hard way

- **Security answers are all lowercase.** The original dialog forced the answer field to lowercase
  (max 20 characters); the password field was case-sensitive (6+ characters with a digit). Type the answer
  in lowercase.
- A wrong credential returns `sense=05/f0/00`. Five wrong attempts set *attempts exceeded* and the tool
  refuses to send more; a power cycle of the enclosure resets the counter.
- An enclosure with no saved question returns zero bytes for the question record; use the password.
- The OneTouch II (Oxford 912) reports its capacity one sector high in READ CAPACITY(10); the `read`
  check expects the exact nominal size, so it may refuse that model. Linux reads are unaffected.

## Oxford 912 firmware reader

`onetouch_unlock/oxford912_fw_read.py` reads the 64 KiB internal flash of an Oxford 912 bridge over
**FireWire** (Linux `firewire-cdev`), using the same CSR mechanism as the vendor updater. It is read-only,
requires a real FireWire controller, and was written as part of the research; it has not been run against
real hardware.

## Verifying the credential derivation

`onetouch_unlock/verify_maxtor_hash.py` runs the original x86 hash routines from `MaxUtilities.exe` in a
QEMU guest and compares them with the Python implementation (needs `clang`, `llvm-objcopy`,
`qemu-system-i386`, and the original executable, whose SHA-256 is pinned).

```sh
python3 -m onetouch_unlock.verify_maxtor_hash /path/to/MaxUtilities.exe
```

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## Safety

The tool only ever sends INQUIRY, READ CAPACITY, one READ, the documented question read, and one unlock
command with the credential you type. It has no erase, password-change, firmware or arbitrary-command
interface, checks the enclosure's identity and serial before every vendor command, and stops on any
unexpected response. Use it on your own hardware.

## License

MIT.
