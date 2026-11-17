# SoC profiles

Profiles are JSON files loaded from `./profiles`, the repository `profiles/`
directory, and `~/.config/mtk-termux/profiles`. `--profiles-dir PATH` loads
profiles from that directory instead of the default locations. Invalid JSON or
invalid fields are reported by `--list-profiles` and `--mode validate`; a bad
profile is skipped rather than silently guessed.

Relative `da`, `preloader`, `auth` and `payload` paths are resolved against the
profile file's directory.

## Fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | no | Human-readable profile name. Defaults to `0x<HW_CODE>`. |
| `enabled` | bool | no | Set `false` to keep a template in `profiles/` without loading it. Default `true`. |
| `hw_code` | int/string | **yes** | SoC HW code, for example `"0x0766"`. |
| `hw_sub_code` | int/string | no | HW sub-code used for closer matching. |
| `hw_version` | int/string | no | HW version from the target/DA entry. |
| `sw_version` | int/string | no | Software version from the DA entry. |
| `da` | path | no | DA container to use. |
| `preloader` | path | no | Preloader/EMI image. |
| `auth` | path | no | `.auth` bundle or root certificate. |
| `payload` | path | no | Exploit payload blob. |
| `exploit` | string | no | `auto`, `kamakiri`, `heapb8` or `none`. Default `auto`. |
| `watchdog` | address | Kamakiri | Watchdog register base. |
| `brom_payload_addr` | address | Kamakiri | BROM payload load address. |
| `var1` | int | Kamakiri | Control-transfer trigger value (0..255). |
| `blacklist_addr` | address | no | Optional patch/blacklist address. |
| `heap_base` | address | HeapB8 | Base of the groomed heap window. |
| `heap_size` | int | HeapB8 | Heap window size in bytes. |
| `dpc_addr` | address | HeapB8 | Device-specific DPC target. |
| `payload_addr` | address | HeapB8 | Payload address inside the heap window. |
| `notes` | string | no | Free-form notes shown by tooling. |

Addresses accept integers or strings such as `"0x10007000"`.

All integer-looking strings are parsed with base detection, so decimal and
`0x` hexadecimal are both accepted.

## Minimal profile

```json
{
  "name": "mt6765-demo",
  "hw_code": "0x0766",
  "da": "MTK_AllInOne_DA.bin",
  "preloader": "preloader.bin",
  "exploit": "none"
}
```

With `exploit: "none"` the session uses the auth/stock-DA path only.
Set `"enabled": false` while a profile is still a template; disabled profiles
are skipped by the loader and are not shown by `--list-profiles`.

## Kamakiri template

Only fill these values from research/firmware that matches the exact SoC and
BROM version. Wrong values can reset the target and will not be retried
automatically.

```json
{
  "name": "my-device",
  "hw_code": "0x0000",
  "da": "MTK_AllInOne_DA.bin",
  "payload": "kamakiri_payload.bin",
  "exploit": "kamakiri",
  "watchdog": "0x00000000",
  "brom_payload_addr": "0x00000000",
  "var1": "0x00"
}
```

## HeapB8 template

HeapB8 additionally needs a DA2 memory backend at runtime. The profile alone
is not enough, and the session refuses to auto-run it without a backend.

```json
{
  "name": "my-device-heapb8",
  "hw_code": "0x0000",
  "da": "MTK_AllInOne_DA.bin",
  "payload": "heapb8_payload.bin",
  "exploit": "heapb8",
  "heap_base": "0x00000000",
  "heap_size": "0x00000000",
  "dpc_addr": "0x00000000",
  "payload_addr": "0x00000000",
  "var1": "0x00"
}
```

## Matching rules

- A candidate must have the same `hw_code`.
- Exact `hw_sub_code` and exact `hw_version` matches score higher.
- A profile whose `hw_version` is greater than the detected version is
  considered incompatible during ranking.
- If an explicit or profile DA is opened, its entry table must contain a
  matching `HW_CODE`; otherwise the session fails with `DaError`.
- Discovery scans common Termux download locations and any `--assets-dir`.
  DA files are validated by parsing their index, not just by filename.
