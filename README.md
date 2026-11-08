# Cwtch platform for Hermes Agent

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) gateway platform for [Cwtch](https://cwtch.im/), the peer-to-peer messenger from the [Open Privacy Research Society](https://openprivacy.ca/) that runs over Tor. Each Cwtch profile is a Tor v3 onion service, and contacts know each other only by that 56-character address: there are no accounts, phone numbers or servers.

Hermes runs its own Cwtch profile. You add the bot's address as a contact in your Cwtch app and talk to it like any other contact.

## How it works

Cwtch has no daemon or server API. The plugin loads Cwtch's C library, libCwtch, in a small child process (`bridge.py`) that also starts its own Tor, so neither runs inside the gateway process and both stop when the gateway stops. The adapter talks to the child over its stdin/stdout.

## Requirements

- Hermes Agent 0.23.0 or newer.
- **libCwtch** for your OS. The Cwtch desktop release ships it:
  - Linux tarball: `lib/libCwtch.so` (system installs: `<prefix>/lib/cwtch/libCwtch.so`)
  - Windows: `libCwtch.dll` in the Cwtch install directory
  - macOS: `Cwtch.app/Contents/Frameworks/libCwtch.x64.dylib` or `libCwtch.arm64.dylib`

  You can also build it from [cwtch.im/autobindings](https://git.openprivacy.ca/cwtch.im/autobindings) (`go run generate/generate_bindings.go && make linux`). This repository does not ship it.
- **tor**. The same Cwtch release ships one (`lib/Tor/tor` on Linux, the `Tor` folder on Windows, `Cwtch.app/Contents/MacOS/Tor/tor` on macOS); without it libCwtch uses the first suitable `tor` on `PATH`.
- No Python packages.

## Install

```bash
hermes plugins install cwtch-platform --enable
hermes gateway setup        # pick Cwtch
hermes gateway restart
```

`cwtch-platform` is the name in the Hermes plugin catalog; `just-a-dev20/hermes-cwtch-platform` installs straight from this repository.

## Configure

The profile password is the only secret; the setup wizard stores it in `~/.hermes/.env`:

```
CWTCH_PROFILE_PASSWORD=<a strong password>
```

Everything else can go in `config.yaml`:

```yaml
gateway:
  platforms:
    cwtch:
      enabled: true
      extra:
        lib_path: /opt/cwtch/lib/libCwtch.so
        tor_path: /opt/cwtch/lib/Tor/tor
        allowed_users: [<your Cwtch address>]
```

| `extra` key | Environment variable | Description |
|---|---|---|
| `lib_path` | `CWTCH_LIB_PATH` | Path to libCwtch (`.so`, `.dll` or `.dylib`). Required. |
| `tor_path` | `CWTCH_TOR_PATH` | Path to the `tor` binary (default: `tor` on `PATH`) |
| `app_dir` | `CWTCH_APP_DIR` | The bot's Cwtch data directory (default: `<HERMES_HOME>/cwtch`). Use a directory of its own, not your personal Cwtch folder. |
| `profile_name` | `CWTCH_PROFILE_NAME` | Display name of the bot's profile when it is first created (default: `Hermes`) |
| `allowed_users` | `CWTCH_ALLOWED_USERS` | Cwtch addresses allowed to talk to the bot |
| `allow_all_users` | `CWTCH_ALLOW_ALL_USERS` | `true` lets every contact talk to the bot (dev only, disables the allowlist) |
| `auto_accept` | `CWTCH_AUTO_ACCEPT` | Accept every contact request (default: `true`). `false` accepts only `allowed_users` and ignores everyone else. |
| `home_channel` | `CWTCH_HOME_CHANNEL` | Cwtch address for cron / notification delivery |

The environment variables work too and take precedence over `config.yaml`.

## Connect to the bot

1. Start the gateway: `hermes gateway run`.
2. On first start the plugin creates the bot's profile and logs its address:
   `Cwtch: profile <56-character address> loaded; add this address in Cwtch to talk to the bot`.
   The address is also stored in `<app_dir>/hermes-profile.json`.
3. In your Cwtch app, add a contact with that address and send a message. The first connection waits for Tor to bootstrap and publish the bot's onion service, which takes a minute or two on a cold start.

Your own Cwtch address (for `allowed_users`) is shown in the Cwtch app under your profile.

## Authorization

By default all contacts are denied. Either add your Cwtch address to `allowed_users`, or use DM pairing: send any message to the bot, and approve the code it replies with by running `hermes pairing approve cwtch <CODE>`.

Contact requests are accepted automatically so that pairing replies can reach new contacts. Accepting a request does not authorize anyone; Hermes still checks every message. With `auto_accept: false` the bot ignores everyone who is not in `allowed_users`.

## Cron delivery

`deliver="cwtch"` sends to `home_channel`; `deliver="cwtch:<address>"` sends to a specific contact. Delivery goes through the running gateway. The bot's profile can be open in only one process, so `hermes send` from another process cannot reach Cwtch.

## Limitations

- Direct conversations only. Cwtch groups are not bridged; a group invite reaches the agent as a short note.
- Text only. Images, voice notes and files cannot be sent or received. A file someone offers reaches the agent as a note with its name; the plugin does not download it. Quoted replies arrive as their text.
- Both sides must be online. Cwtch has no servers to hold messages: the bot receives only while the gateway and its Tor are running, and you receive its replies while your Cwtch app is online.
- No typing indicator, reactions or message editing.

## What the plugin does on your machine

- Starts one child process per configured profile (`python -I bridge.py`) that runs as long as the platform is connected and exits when the gateway disconnects it.
- Loads the libCwtch library you point it at (`ctypes`) inside that child. libCwtch starts a `tor` process, which connects to the Tor network; all Cwtch traffic goes over Tor, peer to peer.
- Stores the bot's Cwtch profile, contacts and message history under `app_dir`, encrypted with `CWTCH_PROFILE_PASSWORD`.
- Reads the password and its other settings only through Hermes (the profile's secret scope and `config.yaml`). The child gets the password over its stdin and a minimal environment (PATH and similar host variables, none of the gateway's secrets).
- Shortens contact addresses in its own log lines. With PII redaction enabled, the model sees hashed addresses.
- No telemetry, no self-updates, and no network access other than libCwtch's Tor.

## Troubleshooting

**"libCwtch not found"**: check that `lib_path` points at the library file itself.

**"cannot load libCwtch"**: the file is not a libCwtch build for this OS and CPU (for example an x64 `.dylib` on Apple Silicon).

**"did not load (wrong CWTCH_PROFILE_PASSWORD, or the profile was deleted)"**: the password does not open the profile recorded in `hermes-profile.json`. Restore the old password, or delete `app_dir` to start over with a new bot address.

**Gateway status stays "retrying"**: Tor has not finished bootstrapping. Check the network, and look for `libCwtch reported: Error connecting to Tor` in `hermes logs` (a missing or too-old `tor`).

**Messages not received**: make sure your address is in `allowed_users` or approved via pairing, and that both your Cwtch app and the gateway are online.

## Development

The tests need a Hermes Agent checkout and its Python environment:

```bash
HERMES_AGENT_HOME=../hermes-agent python -m pytest tests
```

They run the bridge over a stand-in for libCwtch and the adapter against a scripted bridge process, so neither libCwtch nor Tor is needed.

## License

MIT
