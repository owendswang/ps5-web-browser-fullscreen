# PS5 Web Browser Fullscreen

The payload opens the PS5 web browser in fullscreen mode (1920x1080) while keeping the analog-stick pointer, X click, circle back and localhost access. It patches ShellUI RAM only; its persistent data is `/data/web-browser-fullscreen.ini`.

## Usage

Requires a supported jailbroken PS5 with an elfldr running at port 9021.

```sh
PS5_HOST=your_ps5_ip
nc "$PS5_HOST" 9021 < web-browser-fullscreen.elf
```
Or send it with `netcatGUI.exe` from Windows. Or load it via [`Payload Manager`](https://github.com/itsPLK/ps5-payload-manager) from itsPLK.  

To restore the ordinary layout:

```sh
nc "$PS5_HOST" 9021 < web-browser-restore.elf
```

After applying or restoring, close and reopen the browser for the layout change to take effect.

A system notification reports success, failure or an INI-save warning after each run. Detailed errors remain in the payload output. Failures may also create an INI containing diagnostics without reusable offsets.

Reapply after rebooting or changing the system language. The INI survives reboot. A successful built-in reference needs no cache and does not create or refresh its INI profile. For compatibility feedback when an INI is generated, post `/data/web-browser-fullscreen.ini` in [Issues](https://github.com/owendswang/ps5-web-browser-fullscreen/issues).

## Build

Install [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk#quick-start) first.
For a Git checkout, initialize Hermes with `git submodule update --init --recursive`.

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```
Outputs: `web-browser-fullscreen.elf` and `web-browser-restore.elf`.

Generated tables and JSC hook bytes are included. Optional regeneration: `make opcodes` uses the Hermes submodule; `make jsc-hook` requires Python 3 and an x86-64 GNU C/binutils toolchain.

The JSC path uses the PS5's system `libSceJsc`; its project-authored hook has no additional source submodule or bundled JavaScriptCore library.

## How it works

1. Detect the loaded RNPS engine. If both libraries exist, inspect the actual bundle format. Firmware numbers do not choose the engine.
2. Try that engine's exact-firmware reference, then a validated INI, then dynamic discovery. References are in `src/reference_profiles.h` and `src/jsc_reference_profiles.h`.
3. Hermes derives HBC patches from current bundles and locates them through native anchors, with scan fallback. A missing browser module triggers one open/home cycle using `http://127.0.0.1:8888/` before retry.
4. JSC resolves exports, checks ELF/SELF segment metadata and the loaded function prologue, and finds bounded executable/readable padding. Hook operands are relocated to the discovered layout; no heap scan or firmware-specific kernel offsets are needed.
5. Validate native identities and live bytes before writing. Read back writes and attempt rollback on failure. A built-in reference hit skips cache loading and profile saving. If the reference is absent or rejected, retain INI/discovery fallback and atomically save a newly verified layout after success and detach; identical records are not rewritten.

Both paths request 1920 x 1080, hide the browser header and bypass selected-size clamps. JSC updates cached and future Haul modules; a shared RAM toggle restores already compiled wrappers. Restore removes its entry hook but retains callback storage until ShellUI exits. Unknown structures or insufficient safe padding are refused. `make profile-tool` builds a host INI checker/reference exporter that detects the engine and firmware automatically.

Both paths keep the ordinary browser input/network mode. Shared card clamp helpers are also affected. `Result=2` means the requested operation succeeded but an INI update failed. Diagnostic saving is best effort; write errors remain in payload output.

## Credits

- [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk), John Tornblom and contributors: build/runtime foundation and browser API reference; GPLv3-or-later.
- [Hermes v0.12.0](https://github.com/facebook/hermes/tree/v0.12.0), Meta Platforms, Inc. and affiliates: official HBC v89 opcode definitions; MIT. The submodule pins commit `7d3e091b59ff5e5a9e722718c01d81dab52d4300`. Upstream files are unmodified; the full MIT notice is preserved in `src/hbc_opcodes.h` and [the upstream license](https://github.com/facebook/hermes/blob/7d3e091b59ff5e5a9e722718c01d81dab52d4300/LICENSE).
- [PS5 Web File Manager](https://github.com/owendswang/ps5-web-file-manager): home-UI navigation implementation reference; GPLv3-or-later.
- [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv), John Tornblom and contributors: SELF container header layout reference; GPLv3-or-later. No pager/decryption patch is included.
- [PS5 Payload Manager](https://github.com/itsPLK/ps5-payload-manager): ordinary browser-launch API reference; GPLv3.
- [hermes-dec](https://github.com/P1sec/hermes-dec), P1 Security / Marin Moulinier: offline research tool, AGPLv3-or-later. No hermes-dec source is distributed here; release opcode metadata is generated directly from the official Hermes definitions.

## License

Project-authored source is GPL-3.0-or-later, following the SDK. See [LICENSE](LICENSE). The Hermes submodule and generated opcode metadata retain their MIT license. Third-party copyright and license notices must be preserved.
