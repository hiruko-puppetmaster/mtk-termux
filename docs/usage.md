# Using mtk-termux

This guide walks through a complete, safe first run: installing the toolkit,
preparing your own MediaTek assets, entering Boot ROM (BROM), validating the
setup, booting DA1/DA2, and moving on to automatic mode. Read the
[safety section](#safety-and-legal-notes) before connecting a device.

The CLI never flashes a partition by itself. A successful session stops after
DA2 starts. Reads, writes, flashing and RPMB operations are explicit library
APIs.

## 1. What you need

| Item | Notes |
| --- | --- |
| Rooted Android + OTG | Magisk, KernelSU, or an equivalent rooted setup. The Termux app UID cannot open `/dev/bus/usb`. |
| Desktop Linux | Any distribution with USB access; a `plugdev`/udev rule is enough, uid 0 is not required. |
| Python 3.11+ | `python3 --version`. |
| `libusb-1.0` and `pyusb` | USB transport. |
| `rich` | Interactive TUI only; optional for headless modes. |
| MediaTek DA container | Usually `MTK_AllInOne_DA.bin` or `MTK_DA_V6.bin`, matching your SoC. |
| Preloader image | Optional but recommended; provides EMI/DRAM data for XFlash booting. |
| `.auth` bundle | Required on SLA/DAA-protected devices. |
| Exploit payload | Only if you deliberately use Kamakiri/HeapB8. Never auto-selected without complete profile values. |

The project does **not** ship vendor firmware, signed DAs, auth keys, or
payloads. Bring files that you are licensed to use.

## 2. Installation

### Rooted Termux

```sh
pkg update
pkg install python libusb clang make git
git clone https://github.com/hiruko-puppetmaster/mtk-termux.git
cd mtk-termux
python -m pip install -e ".[all]"
```

Check the install:

```sh
mtk-termux --version
mtk-termux --mode scan
```

From inside the repository you can also run `python -m ui.termux_cli ...`
without installing the console script.

If the package manager complains about externally managed environments, add
`--break-system-packages` to the pip command or work in a virtual environment
(`python -m venv .venv && . .venv/bin/activate`).

### Desktop Linux

```sh
sudo apt install python3 python3-venv libusb-1.0-0 git   # Debian/Ubuntu names
git clone https://github.com/hiruko-puppetmaster/mtk-termux.git
cd mtk-termux
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[all]"
```

To use your normal user account instead of `sudo`, install a udev rule:

```sh
sudo tee /etc/udev/rules.d/50-mtk-termux.rules >/dev/null <<'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", MODE="0660", GROUP="plugdev", TAG+="uaccess"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Replug the device after installing the rule. Membership in the `plugdev`
group (or `uaccess`) is required. `--no-root-check` skips the uid pre-check;
the real `O_RDWR` probe of `/dev/bus/usb/BBB/DDD` remains authoritative.

## 3. Prepare your assets

A practical working directory:

```
my-device/
├── MTK_AllInOne_DA.bin
├── preloader_<device>.bin
├── device.auth                  # only for SLA/DAA targets
├── scatter.txt
└── profiles/
    └── my-device.json
```

Asset behavior:

- Explicit `--da`, `--preloader` and `--auth` paths always win.
- Otherwise profiles are searched in `./profiles`, the repository
  `profiles/` directory, and `~/.config/mtk-termux/profiles`.
- Without a profile or explicit path, discovery scans the current directory,
  `~/mtk`, `~/Downloads`, `~/storage/downloads`, `/sdcard/Download`,
  `/sdcard/mtk`, and every `--assets-dir`.
- DA candidates are validated by parsing the container index, not by filename.
- `--profiles-dir PATH` **replaces** the default profile locations instead of
  adding to them.
- Relative `da`/`preloader`/`auth`/`payload` paths in a profile resolve against
  the profile file's directory.

Validate file parsing without USB access:

```sh
mtk-termux --mode validate \
  --da MTK_AllInOne_DA.bin \
  --preloader preloader_<device>.bin \
  --auth device.auth
```

Expected output resembles:

```
Validation OK
  da: MTK_AllInOne_DA.bin, entries=...
  preloader: preloader_<device>.bin, EMI=yes
```

`--dry-run` is equivalent and can be combined with any mode.

## 4. Enter BROM and verify the link

1. Power the phone completely off. Do not use reboot-to-BROM unless you have a
   reliable method.
2. Connect a data-capable OTG adapter/cable. Charge-only cables do not
   enumerate.
3. Hold the BROM key combination for your device (commonly Volume Down, or
   both volume keys) while plugging in the cable, then release.
4. BROM enumerates briefly as `0e8d:0003`; the Preloader as `0e8d:2000`.

Enumerate first:

```sh
mtk-termux --mode scan
mtk-termux --mode scan --json
```

The scan shows mode, VID:PID, bus/address and the usbfs path. On Termux, run
device-opening commands as uid 0:

```sh
su -c 'cd /path/to/mtk-termux && mtk-termux --mode scan'
```

Then handshake without uploading anything:

```sh
su -c 'cd /path/to/mtk-termux && mtk-termux --mode probe --wait 30'
```

`probe` prints `HW_CODE`, the raw target config and the SBC/SLA/DAA flags. If
this works, cabling, root, SELinux and libusb are all functional.

`--wait SECONDS` controls how long to wait for a device; `0` (the default)
waits forever. `Ctrl-C` exits with status 130.

## 5. First DA boot: manual mode

Start with no exploit:

```sh
su -c 'cd /path/to/mtk-termux && mtk-termux --mode manual \
  --da MTK_AllInOne_DA.bin \
  --preloader preloader_<device>.bin \
  --auth device.auth \
  --exploit none'
```

Headless manual mode waits for a device according to `--wait`, then runs:

1. BROM synchronization and `HW_CODE` read.
2. Target-config read (SBC/SLA/DAA).
3. DA container selection for the detected `HW_CODE`/`HW_VERSION`.
4. Auth upload when the target requires SLA/DAA.
5. DA1 upload and jump.
6. DA2 startup over XFlash V5 or DA v6 XML.

Successful output looks like:

```
HW_CODE: 0x0766
DA:      /path/to/MTK_AllInOne_DA.bin
protocol:XFLASH
DA1:     True
DA2:     True
```

The default `--mode tui` provides the same manual flow interactively. Missing
paths can be selected from discovered files or typed in, and the TUI waits for
an explicit Enter before arming USB. This is the recommended first hardware
test because you control the exact moment USB is opened.

If the target is secure and rejects the DA, supply a valid `.auth` bundle and a
matching signed DA. `--allow-unsigned-da` only disables a local check; the Boot
ROM itself will still reject unsigned uploads.

## 6. Automatic mode with a profile

A profile captures values that cannot be guessed safely: HW code, asset paths,
exploit choice and optional register/exploit parameters.

Minimal profile, `profiles/my-device.json`:

```json
{
  "name": "my-device",
  "hw_code": "0x0766",
  "da": "../MTK_AllInOne_DA.bin",
  "preloader": "../preloader_<device>.bin",
  "auth": "../device.auth",
  "exploit": "none"
}
```

Inspect what will be loaded:

```sh
mtk-termux --list-profiles
mtk-termux --list-profiles --profiles-dir ./profiles
```

Run automatic mode once:

```sh
su -c 'cd /path/to/mtk-termux && mtk-termux --mode auto --once'
```

Without `--once`, auto mode keeps polling and services the next device after
the current target leaves. Auto mode performs the same steps as manual mode,
but selects the DA/preloader/auth from an explicit path, matching profile, or
validated discovery result.

For a first auto run, keep `"exploit": "none"`. Enable Kamakiri or HeapB8 only
after manual DA boot is confirmed and only with a payload and profile that
match the exact SoC and BROM version. A wrong payload normally resets the
target.

## 7. Day-to-day commands

```sh
# Installed console script
mtk-termux --mode scan
mtk-termux --mode scan --json
mtk-termux --mode probe --wait 30
mtk-termux --mode manual --da DA.bin --preloader preloader.bin --auth device.auth
mtk-termux --mode auto --once
mtk-termux --mode validate --da DA.bin --preloader preloader.bin
mtk-termux --list-profiles
mtk-termux --help

# From a source checkout without installing
python -m ui.termux_cli --mode scan

# Elevate automatically through su (Termux)
mtk-termux --elevate --mode auto --once

# Debug logging
mtk-termux -v --mode probe --wait 30
```

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--mode tui\|auto\|manual\|scan\|probe\|validate` | Operation mode; default `tui`. |
| `--da PATH` | DA container, overrides profile/discovery. |
| `--preloader PATH` | Preloader/EMI image. |
| `--auth PATH` | `.auth`/certificate bundle. |
| `--payload PATH` | Exploit payload blob. |
| `--exploit auto\|kamakiri\|heapb8\|none` | Exploit strategy; start with `none`. |
| `--profiles-dir PATH` | Replace default profile search locations. |
| `--assets-dir PATH` | Add an asset search directory (repeatable). |
| `--wait SECONDS` | Device wait timeout; `0` waits forever. |
| `--once` | Stop after one device. |
| `--dry-run` | Validate without opening USB. |
| `--allow-unsigned-da` | Development-only local auth bypass. |
| `--no-root-check` | Skip the uid pre-check; usbfs permissions still decide. |
| `--elevate` | Re-exec through `su -c`. |
| `--list-profiles` | Print loaded profiles and exit. |
| `--json` | JSON output for scan. |
| `--no-color` | Disable Rich colors. |
| `-v` | Debug logging. |

Exit status: `0` success, `1` runtime/validation/no-device failure, `2`
permission or root/TUI setup failure, `130` interrupted.

## 8. Error handling and diagnostics

The CLI reports root, `su`, SELinux and usbfs diagnostics when opening a device
fails. Typical cases:

| Symptom | Check |
| --- | --- |
| `No BROM/Preloader device detected` | Data-capable cable, OTG adapter, key combination, BROM window. BROM is only visible briefly. |
| `Cannot open /dev/bus/usb/...` | Run through `su -c`, install the udev rule, check SELinux denials via `dmesg`/`logcat`, and make sure no other flasher has claimed the interface. |
| Device disappears after upload | Wrong DA entry for the SoC, wrong preloader/EMI, or an exploit reset. Re-enter BROM and retry with `--exploit none`. |
| `AuthError` / `0x1D0D` | Secure target needs a matching `.auth` bundle and signed DA. |
| DA rejected / checksum warning | DA container does not match `HW_CODE`/`HW_VERSION`; use the firmware package for this exact model. |
| XFlash boot fails but DA XML works | Preloader EMI extraction failed; supply the matching preloader/EMI image. `--mode validate` reports whether EMI was found. |
| Exploit resets the target | Payload or profile addresses are wrong. Exploits are not universal; use `--exploit none` and research the exact SoC/BROM. |

Useful commands while debugging:

```sh
dmesg | tail -50
lsusb                       # desktop Linux
su -c 'ls -l /dev/bus/usb'
su -c 'getenforce'          # SELinux enforcing/permissive
mtk-termux -v --mode probe --wait 30
```

Do not disable SELinux globally as a fix. Run the tool inside the root context,
or add a narrowly scoped policy.

## 9. After DA2: explicit operations only

A successful session leaves DA2 running. The CLI intentionally offers no
`flash` command. Use the library so every read, write or erase has an explicit
address and length:

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

Then use `core.protocols.XFlashV5` or `core.protocols.DAXMLProtocol` for
explicit device operations. Parsers are available for partition planning:

```python
from parsers.scatter_gpt import parse_scatter_file, parse_gpt_file, read_gpt

scatter = parse_scatter_file("scatter.txt")
print(scatter.get("boot").start, scatter.get("boot").size)

gpt = parse_gpt_file("disk.img", sector_size=4096)
print(gpt.get("userdata").start)

with open("/dev/block/sda", "rb") as fh:
    table = read_gpt(fh)
```

Scatter validation rejects overlapping partitions inside the same region;
`EMMC_BOOT_1` and `EMMC_USER` are separate address spaces. GPT parsing
validates header and entry-array CRCs and supports 512–4096-byte sectors.

RPMB is also library-only. Addresses count 256-byte blocks; every write is
authenticated and consumes a write counter. **Programming an RPMB key is
irreversible**; `program_key()`/`provision_key()` require `confirm=True`.

## 10. Updating and testing

From a source checkout:

```sh
cd mtk-termux
git pull
python -m pip install -e ".[all]"     # refresh entry points after changes
python3 -m unittest discover -v       # 79 hardware-free tests
```

If you installed with `pip` without `-e`, reinstall after updating. The test
suite does not require a phone and covers protocol framing, parsers, RPMB,
profiles, sessions and TUI rendering.

## 11. Safety and legal notes

- Use the toolkit only on hardware you own or are explicitly authorized to
  service. Unlocking, flashing and RPMB changes can void warranties and
  permanently brick devices.
- Keep a known-good full firmware package and a recovery path before any write.
- Test in this order: `scan` → `probe` → `manual --exploit none` → `auto`
  → exploit/RPMB.
- Never run an exploit payload you do not trust. It executes with the Boot ROM's
  privileges and can reset or brick the target.
- No tool can recover a lost RPMB key or undo key programming.
- The authors are not affiliated with MediaTek and provide no vendor files.
- This environment had no MediaTek hardware during development, so treat the
  first hardware run as validation, not production use.
