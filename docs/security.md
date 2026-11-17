# Security notes

This toolkit talks directly to a phone's Boot ROM and Download Agent. A wrong
payload, a mismatched DA entry, or an interrupted write can leave a device
unbootable. Read this before using auto mode.

## Scope

- Use the tool only on hardware you own or are explicitly authorized to
  service.
- No firmware, signed DA images, `.auth` bundles, SLA keys, or exploit payloads
  are included. Obtain them from your own firmware package or vendor repair
  tooling and respect their licenses.
- The project is not affiliated with MediaTek or any vendor tool.

## Root and USB

`/dev/bus/usb` is normally accessible only to uid 0. Running through `su` gives
the tool broad access to USB devices. Prefer a dedicated root shell, close
other flashers, and do not pipe untrusted commands into `su`.

On Android, SELinux may still block usbfs access even as root. A permissive
domain or a targeted policy may be required. Do not disable SELinux globally
unless you understand the consequences.

## Authentication

- Secure Boot (SBC) / SLA / DAA targets reject unsigned loaders.
- An `.auth` bundle is not a bypass; it is a signed authorization tied to the
  target.
- `--allow-unsigned-da` only suppresses a local error after an auth failure.
  It cannot make the Boot ROM accept an unsigned DA.
- Never share device-specific auth bundles or keys.

## Exploits

- Kamakiri and HeapB8 parameters are SoC, BROM-version, and sometimes
  firmware-version specific.
- A payload mismatch usually resets the target. Repeated attempts in a tight
  loop are not useful; power-cycle and re-check the profile.
- HeapB8 staging writes to addresses supplied by the caller. Validate the
  heap window and payload address; the class refuses obviously out-of-window
  payloads but cannot verify that the addresses are correct for your target.
- Disable exploits (`--exploit none`) when you only need to boot a stock,
  signed DA.

## Flashing

- The session stops after DA2 startup. There is no implicit erase or write.
- When using the library APIs, double-check partition offsets, sizes and the
  target storage before writing.
- Keep a full backup and a known-good firmware package. Have a recovery path
  (vendor service tool, EDL test point, or hardware programmer) before
  modifying boot-critical partitions.

## RPMB

Programming the RPMB authentication key is irreversible. Once a key is
programmed, the RPMB area is bound to it, and a wrong or lost key can make
protected data inaccessible. `program_key()` and `provision_key()` require
`confirm=True` for this reason. Verify the key, the target eMMC and your backup
before confirming.

## Reporting problems

Include the mode, command-line flags (without secrets), `--mode scan` output,
root/SELinux diagnostics, DA container name and `HW_CODE`. Never attach auth
bundles, private keys, or full device dumps to public reports.
