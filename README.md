# mtk-termux

A standalone Python 3.11+ toolkit for servicing MediaTek devices over USB from
**rooted Termux** (Android OTG) or **desktop Linux**. It covers the low-level
pieces between "plug the phone in" and "start a Download Agent":

- sysfs/pyusb USB enumeration and non-blocking BROM/Preloader hotplug polling;
- BROM synchronization, `HW_CODE`, target-config and memory commands;
- SLA/DAA certificate and auth-bundle handling;
- Kamakiri and HeapB8 exploit orchestration (payloads supplied by you);
- XFlash V5 and DA v6 XML protocols, DA1 upload and DA2 startup;
- MediaTek scatter-file and EFI GPT parsing;
- eMMC RPMB framing, authenticated read/write and key provisioning;
- Rich interactive TUI plus scriptable CLI modes.

The session intentionally **stops after DA2 starts**. It does not erase or
flash partitions on its own. Flashing helpers are library APIs so that every
write needs explicit addresses and data.

> This project is unaffiliated with MediaTek. It contains no vendor firmware,
> signed DA images, auth keys, or exploit payloads. Bring your own files.
> Use it only on hardware you own or are authorized to service.

**First time here?** The [detailed usage guide](docs/usage.md) covers
installation, asset preparation, BROM entry, manual/auto runs, profiles,
troubleshooting and safety.

## Requirements

- Python 3.11 or newer.
- A rooted Android device running Termux with a working OTG adapter, **or** a
  desktop Linux machine with USB access.
- `libusb-1.0` and `pyusb` for USB access.
- `rich` for the interactive TUI (optional for CLI modes).
- A MediaTek DA container (`MTK_AllInOne_DA.bin` / `MTK_DA_V6.bin`), and
  usually a matching preloader image. An `.auth` bundle is needed for
  SLA/DAA-protected devices.

## Termux setup

```sh
pkg update
pkg install python libusb clang make git
python -m pip install pyusb rich
```

Check the environment from a root shell:

```sh
su -c 'id -u'
su -c 'python -m ui.termux_cli --mode scan'
```

`/dev/bus/usb` is not readable by the Termux app UID. You must run the tool as
uid 0 through Magisk, KernelSU, or an equivalent root implementation:

```sh
su -c 'cd /path/to/mtk-termux && python -m ui.termux_cli --mode auto'
```

If `su` works but the process still cannot open the device, check SELinux and
make sure no other flasher (mtkclient, SP Flash Tool, a running `adb`) has the
interface claimed. The CLI reports root, `su`, SELinux and usbfs diagnostics.

### OTG notes

- Use an OTG adapter that passes data, not a charge-only cable.
- Power the phone off before entering BROM. For many devices, hold the
  appropriate key combination (often Vol- or both volume keys) while plugging
  the cable in.
- BROM appears as `0e8d:0003`; the Preloader appears as `0e8d:2000`.
- BROM is only visible for a short time. `--mode auto` polls sysfs every
  150 ms so it does not miss the window.

## Quick start

```sh
# List USB devices, including non-MediaTek ones.
python -m ui.termux_cli --mode scan
python -m ui.termux_cli --mode scan --json

# Handshake with a device and print HW_CODE/target config (no DA upload).
python -m ui.termux_cli --mode probe --wait 30

# Interactive TUI (default).
python -m ui.termux_cli

# Explicit manual assets. The session boots DA1/DA2 and then stops.
python -m ui.termux_cli --mode manual \
  --da MTK_AllInOne_DA.bin \
  --preloader preloader.bin \
  --auth device.auth

# Automatic asset selection: read HW_CODE, choose DA/preloader/auth, run.
python -m ui.termux_cli --mode auto --once
```

`--mode manual` still asks for a trigger before touching USB when the TUI is
used. In headless CLI mode, manual and auto both wait for a device according to
`--wait` (0 means forever).

### Useful flags

| Flag | Meaning |
| --- | --- |
| `--da PATH` | DA container; used before profile/discovery selection. |
| `--preloader PATH` | Preloader image used for EMI/DRAM setup. |
| `--auth PATH` | `.auth`/certificate bundle for SLA/DAA targets. |
| `--payload PATH` | Payload blob for Kamakiri/HeapB8. |
| `--exploit auto\|kamakiri\|heapb8\|none` | Exploit strategy. |
| `--profiles-dir PATH` | Directory of SoC profile JSON files. |
| `--assets-dir PATH` | Extra directory scanned for DA/preloader/auth files. |
| `--wait SECONDS` | Device wait timeout; `0` waits forever. |
| `--once` | Stop after one device in auto mode. |
| `--dry-run`, `--mode validate` | Parse and validate files without USB. |
| `--allow-unsigned-da` | Continue after auth failure (development only). |
| `--no-root-check` | Skip the uid pre-check; the usbfs permission probe still decides. |
| `--elevate` | Re-exec through `su -c`. |
| `--list-profiles` | Show loaded SoC profiles. |
| `--json` | JSON output for scan. |
| `-v` | Debug logging. |

## Modes

### `scan`

Enumerates `/sys/bus/usb/devices` (falling back to pyusb), then prints mode,
VID:PID, bus/address and the usbfs path. It does not require root unless the
kernel hides the device metadata.

### `probe`

Opens the BROM, performs the byte-wise handshake, reads `HW_CODE`, target
configuration and BROM version. Use it to confirm cabling/root before uploading
anything.

### `manual`

Uses the paths passed on the command line. In the TUI, missing paths are
selected from discovered files or typed in, and the tool waits for an explicit
Enter before arming USB. This is the recommended first hardware test.

### `auto`

Polls for BROM/Preloader devices. On insertion it:

1. synchronizes and reads `HW_CODE`;
2. reads the target config (SBC/SLA/DAA);
3. selects an explicit DA, a profile DA, or a matching DA from scanned
   directories;
4. sends an auth bundle when configured;
5. runs the configured exploit if a complete profile/payload exists;
6. uploads DA1, jumps to it, then starts DA2 over XFlash V5 or DA v6 XML.

Without `--once`, the next device is serviced after the current one leaves.
`Ctrl-C` stops the loop.

## Profiles

Profiles describe SoC-specific data that cannot be guessed safely: register
addresses, exploit parameters and default asset paths. They are JSON files in
`./profiles`, the repository `profiles/` directory, or
`~/.config/mtk-termux/profiles`. See [`docs/profiles.md`](docs/profiles.md)
and [`profiles/example.json`](profiles/example.json).

Minimal profile:

```json
{
  "name": "mt6765-demo",
  "hw_code": "0x0766",
  "hw_version": "0xCA00",
  "da": "MTK_AllInOne_DA.bin",
  "preloader": "preloader.bin",
  "exploit": "none"
}
```

Relative paths are resolved against the profile file. A DA container is
selected by `HW_CODE`/`HW_VERSION`; if the container has no matching entry the
session fails instead of uploading a wrong loader.

### Asset discovery

Without explicit paths, DA/preloader/auth files are looked for in the current
directory, `~/mtk`, `~/Downloads`, `~/storage/downloads`,
`/sdcard/Download`, `/sdcard/mtk`, and any `--assets-dir`. DA matching reads
the container index, so a random `.bin` with a DA-like name is rejected.
`--profiles-dir` replaces the default profile locations rather than adding to
them.

### Preloader and EMI

A preloader image is parsed for the `MTK_BLOADER_INFO_v` marker and the
EMI/DRAM blob used by XFlash `INIT_EXT_RAM`. Very old XFlash-era preloaders
start with that marker at offset 0; those images are sent whole. Newer images
with an `MMM` header have the `MTK_BIN` region extracted. If no EMI region is
recognized, the DA path still works, but XFlash booting may need an explicit
EMI/DRAM image from the matching firmware. `--mode validate` reports whether
an EMI blob was found.

## Exploits and authentication

- **Kamakiri** is implemented as a host-side primitive: watchdog write, BROM
  heap shaping reads, payload upload via `0xE0`, and a control-transfer
  trigger. It requires a profile with `watchdog`, `brom_payload_addr`, `var1`
  and a matching payload. A wrong payload normally resets the target.
- **HeapB8** requires a firmware/DA-specific heap profile and a DA2 memory
  backend. The repository ships the orchestration layer and validation, not a
  universal payload. The session refuses to auto-run HeapB8 without a backend.
- **SLA/DAA:** supply a valid `.auth` bundle and, when the BROM requests a
  challenge, an SLA signer. Unsigned DA uploads are rejected by secure Boot
  ROMs. `--allow-unsigned-da` only bypasses the local auth-failure check; it
  cannot make the target accept an unsigned loader.

No exploit is selected unless the profile has a complete set of parameters.
`--exploit none` forces the stock/auth path.

## RPMB

`storage.rpmb_storage` implements JEDEC 512-byte frames with HMAC-SHA-256
authentication using only the standard library:

```python
from storage.rpmb_storage import RpmbManager

manager = RpmbManager(backend, key=key)      # backend.transmit(frame) -> frame
counter = manager.get_write_counter()
data = manager.read_blocks(address=0, count=2)
next_counter = manager.write_blocks(address=0, data=payload)
```

The frame carries one 256-byte data block, so multi-block calls issue one
authenticated request per block. Addresses count 256-byte blocks (not 512-byte
frames); a call is limited to 256 blocks and the 16-bit address space.

**Programming an RPMB key is irreversible.** `program_key()` / `provision_key()`
raise unless `confirm=True` is passed explicitly, and a second programming
attempt will fail on real hardware.

`DA2RpmbBackend` expects a DA2 extension opcode that accepts one frame and
returns one frame. Stock DA2 loaders may not implement it; provide your own
`RpmbBackend` if yours does not.

## Parsers

```python
from parsers.scatter_gpt import parse_scatter_file, parse_gpt_file, read_gpt

scatter = parse_scatter_file("scatter.txt")
print(scatter.get("boot").start, scatter.get("boot").size)

gpt = parse_gpt_file("disk.img", sector_size=4096)
print(gpt.get("userdata").start)

with open("/dev/block/sda", "rb") as fh:
    table = read_gpt(fh)          # works on seekable block devices
```

Scatter parsing accepts text and XML variants and rejects overlapping
partitions within the same region (`EMMC_BOOT_1` and `EMMC_USER` are separate
address spaces). GPT parsing validates the header and entry-array CRCs and
supports 512-byte through 4096-byte sectors.

## Library example

```python
from pathlib import Path
from core.options import AppOptions
from core.session import DeviceSession
from termux_transport.usb_host import UsbHost

options = AppOptions(
    mode="manual",
    da=Path("MTK_AllInOne_DA.bin"),
    preloader=Path("preloader.bin"),
    auth=Path("device.auth"),
    exploit="none",
)

host = UsbHost()
device = host.wait_for_device(timeout=30)
if device is None:
    raise SystemExit("no BROM/Preloader device")

with DeviceSession(options, host=host) as session:
    result = session.run(device)
    print(result.hw_code, result.protocol, result.da2_booted)
```

After DA2 is up, `core.protocols.XFlashV5` / `core.protocols.DAXMLProtocol`
can be used for explicit read/write operations. There is no implicit flashing.

## Testing

```sh
cd mtk-termux
python3 -m unittest discover -v
```

The suite covers BROM framing, XFlash packets, DA XML upload/download, DA
container parsing, scatter/GPT validation, RPMB frames and multi-block
sequences, exploit sequencing, profile selection, session validation and TUI
rendering. It does not require a phone.

Hardware validation is still required before trusting a new device/profile:
start with `--mode scan`, then `--mode probe`, then `--mode manual --exploit
none`, and only then enable an exploit.

## Limitations

- No Android USB permission dialog can be automated; root is required.
- Vendor DA/Preloader/auth/payload files are not included.
- HeapB8 needs a device-specific payload and heap profile.
- The DA2 RPMB extension opcode is vendor-specific and not guaranteed.
- BROM/DA behavior varies by SoC and loader version; always keep a known-good
  firmware package and a recovery path.
- This environment has no MediaTek hardware, so real USB/BROM/DA flows have
  not been exercised here.

## Project layout

```
termux_transport/usb_host.py   sysfs/pyusb enumeration, root checks, hotplug
core/protocols.py              BROM, XFlash V5, DA v6 XML
core/exploits.py               Kamakiri / HeapB8 orchestration
core/da_loader.py              DA container and preloader EMI parsing
core/profiles.py               profiles and automatic asset selection
core/session.py                BROM -> auth/exploit -> DA1 -> DA2
parsers/scatter_gpt.py         scatter and EFI GPT parsing
storage/rpmb_storage.py        RPMB frames, auth, provisioning
ui/terminal_tui.py             Rich manual/auto TUI
ui/termux_cli.py               CLI entry point
profiles/                      profile JSON files
docs/                          usage, profile and security notes
tests/                         unit tests
```

## License

MIT. See [`LICENSE`](LICENSE).
