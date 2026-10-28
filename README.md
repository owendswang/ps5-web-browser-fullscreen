# PS5 Web Browser Fullscreen

Make the PS5 web browser fullscreen (1920x1080) while keeping the analog-stick pointer, X click, circle back and localhost access. Changes are applied in memory; system files are not modified.

## Usage

Requires a supported jailbroken PS5 with an elfldr running at port 9021.

```sh
PS5_HOST=your_ps5_ip
nc "$PS5_HOST" 9021 < web-browser-fullscreen.elf
```
Alternatively, use `netcatGUI.exe` on Windows or [Payload Manager](https://github.com/itsPLK/ps5-payload-manager).

To restore the ordinary layout:

```sh
nc "$PS5_HOST" 9021 < web-browser-restore.elf
```

After applying or restoring, close and reopen the browser for the layout change to take effect.

A system notification reports the result. Reapply after rebooting or changing the system language.

Cache and diagnostics are saved to `/data/web-browser-fullscreen.ini` when needed. Include the complete file, if present, when reporting compatibility issues in [Issues](https://github.com/owendswang/ps5-web-browser-fullscreen/issues). See the release notes for compatibility details.

## Build

Install [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk#quick-start) first.
For a Git checkout, initialize Hermes with `git submodule update --init --recursive`.

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```
Outputs: `web-browser-fullscreen.elf` and `web-browser-restore.elf`.

For diagnostic test builds:

```sh
make test
```

Outputs: `web-browser-fullscreen-test.elf`, `web-browser-restore-test.elf` and `web-browser-inspect-test.elf`. Send them in the same way. Test builds provide additional discovery and diagnostics and may take longer to run.

## How it works

1. Detect the browser's scripting engine and try built-in offsets, then cached offsets, then dynamic discovery.
2. If initialization is needed, open the browser and return home once before retrying.
3. Validate and patch the layout in memory, then verify the changes. Successfully discovered offsets are cached for future runs; built-in offsets need no cache.

The patch removes browser chrome and size limits while preserving ordinary browser controls and networking. Some shared card sizing is also affected. Unsupported layouts are rejected, with diagnostics saved when possible.

## Credits

- [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk), John Tornblom and contributors: build/runtime foundation and browser API reference; GPLv3-or-later.
- [Hermes](https://github.com/facebook/hermes), Meta Platforms, Inc. and affiliates: bytecode definitions; MIT. Included as an unmodified submodule with its license notices preserved.
- [PS5 Web File Manager](https://github.com/owendswang/ps5-web-file-manager): home-UI navigation implementation reference; GPLv3-or-later.
- [ftpsrv](https://github.com/ps5-payload-dev/ftpsrv), John Tornblom and contributors: SELF format reference; GPLv3-or-later.
- [PS5 Payload Manager](https://github.com/itsPLK/ps5-payload-manager): ordinary browser-launch API reference; GPLv3.
- [hermes-dec](https://github.com/P1sec/hermes-dec), P1 Security / Marin Moulinier: offline research tool; AGPLv3-or-later. Not bundled.
- [zlib](https://zlib.net/), Jean-loup Gailly and Mark Adler: optional diagnostic compression; zlib license. Not linked by default.

## License

GPL-3.0-or-later, following the SDK. See [LICENSE](LICENSE). Hermes and its generated opcode metadata retain their MIT license. Third-party copyright and license notices must be preserved.
