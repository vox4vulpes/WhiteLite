# WhiteLite

**Status: Alpha.** Actively evolving, run in production at your own risk.

Self-hosted OpenVPN + Telegram bot, with a WebRTC-based fallback tunnel (via
[olcRTC](https://github.com/openlibrecommunity/olcrtc)) for when a provider
whitelists only "legitimate" video-call services (Jitsi/Telemost/WbStream) and
blocks regular VPN protocols.

Inspired by the write-up at https://www.pvsm.ru/vpn/449328.

> Built with AI assistance (Claude Code / Anthropic's Claude) — code, bot
> features, and this README were written collaboratively with an AI agent.

## What's here

- **`ovpn-server`** — `kylemanna/openvpn` in Docker, the primary VPN.
- **`vpn-bot`** — a Telegram bot (`vpn_bot.py`) that manages both the OpenVPN
  server and on-demand WebRTC fallback tunnels, entirely through chat commands.
- **`olcrtc-image/`** — a thin Docker wrapper around the [olcRTC](https://github.com/openlibrecommunity/olcrtc)
  binary, used by the bot to spin up fallback tunnels.

## Bot commands

- `/new` — generate a new OpenVPN client profile and receive the `.ovpn` file.
- `/white [jitsi-server]` — spin up a WebRTC fallback tunnel disguised as a
  Jitsi call. Defaults to whatever `/white -default` was last set to.
- `/white -default <domain>` — persist a default Jitsi server for plain `/white`.
- `/white -best_ms` — scan a public list of Jitsi servers, pick the one with
  the lowest latency, and use it.
- `/white -best_mb` — same, but ranks by real download throughput (20+ MB per
  host) instead of latency.
- `/white -best_all` — runs both scans and combines them into a single score
  (placement in each test counts as points; the speed test is weighted 2x).
- Add `-test` to any `-best_*` flag to see the scan results without deploying
  a tunnel.
- Add `-checkoff` to any `-best_*` scan (or `/whitesub -setup`) to skip the
  real anonymous-XMPP-login check (see below) for a faster but less reliable
  scan.
- `/whitesub -setup [N]` — runs both scans, shows the full ranked list, and
  waits for a reply with the position numbers you've manually confirmed work
  on your network; saves the best N of those as a pool (default N=5), without
  deploying anything yet.
- `/whitesub [N]` — deploys N tunnels from that saved pool and immediately
  sends a `sub.md`-format subscription file, plus an `https` link serving the
  same content (importable in olcbox: add configuration → import from file,
  or enter link/URI). The link uses a self-signed cert — enable
  `Allow insecure requests` in olcbox when adding it by link. The link is
  stable across `/whitesub` calls (same token), so olcbox's subscription
  auto-refresh will pick up the latest deploy without re-pasting anything.
- `/list` — every client ever issued (OpenVPN certs + live White/Jitsi
  containers), sorted by traffic/activity within each group.
- `/monitor` — OpenVPN bandwidth and connected-client stats.
- Send an existing client's name (e.g. `user_ab12cd` or `olcrtc-1a2b3c4d`) to
  get its config re-sent; reply to that message to give it a friendly name
  shown in `/list`.

Admin-only commands (`/white`, `/list`, `/whitesub`) are gated by
`ADMIN_TELEGRAM_ID`.

### Candidate filtering for `-best_*` scans

The public Jitsi server list used by the scans includes hosts that pass a
plain HTTP reachability check but don't actually work as an olcRTC tunnel
(bare IPs with no TLS SAN, misconfigured/expired domains with a mismatched
cert, servers with anonymous XMPP login disabled, etc.). Every scan therefore:

1. drops bare IPs (can't pass TLS hostname verification),
2. drops hosts on a persisted denylist (`bot-data/jitsi_denylist.json`),
3. by default, actually spins up the real `olcrtc` binary against each
   remaining candidate for a few seconds to confirm it can join the room —
   any host that fails is added to the denylist automatically, so future
   scans skip it for free.

Step 3 is what `-checkoff` disables.

## Setup

1. Install Docker and the compose plugin:
   ```sh
   apt-get update && apt-get install -y docker.io docker-compose-v2
   ```
2. Copy `.env.example` to `.env` and fill in your own values:
   ```sh
   cp .env.example .env
   # BOT_TOKEN=<from @BotFather>
   # ADMIN_TELEGRAM_ID=<your Telegram numeric user ID>
   # OVPN_PORT=1194
   # PUBLIC_HOST=<your server's public IP or domain, for the /whitesub link>
   # SUB_HTTPS_PORT=8443
   ```
3. Initialize the OpenVPN PKI (first run only) — see the
   [kylemanna/openvpn](https://github.com/kylemanna/openvpn) docs, or restore
   an existing `openvpn-data/` volume. After moving to a new server, update
   `openvpn-data/ovpn_env.sh`: set `OVPN_CN` and `OVPN_SERVER_URL` to the new
   server's IP/hostname, otherwise generated `.ovpn` files will point at the
   old one.
4. Build the `olcrtc` binary and drop it into `olcrtc-image/` (it's not
   vendored here):
   ```sh
   git clone --recurse-submodules https://github.com/openlibrecommunity/olcrtc
   cd olcrtc && mage build
   cp build/olcrtc-linux-amd64 ../olcrtc-image/
   ```
   Then build the wrapper image: `docker build -t olcrtc-server:latest olcrtc-image/`
5. Start everything:
   ```sh
   docker compose up -d
   ```
6. Talk to your bot on Telegram — `/start` for the command list.

## Data persistence

The bot stores its own state (client name aliases, White-tunnel metadata,
default Jitsi server, the Jitsi denylist, the `/whitesub -setup` pool, the
`/whitesub` link token and last-generated subscription text, the self-signed
TLS cert for that link) under `/data` inside the container, backed by the
`./bot-data` volume — keep it around across rebuilds/restarts.

## Security notes

- `openvpn-data/` contains the full PKI (CA + server + every client private
  key). Never commit or share it.
- `bot-data/white_configs.json` contains the encryption keys of active White
  tunnels. Never commit or share it.
- `.env` contains a live Telegram bot token. Never commit or share it.
- `bot-data/whitesub_token.json` and `bot-data/whitesub_last.txt` are the
  subscription link's secret token and its current content (tunnel keys
  included) — treat like any other secret in `bot-data/`.
- The `/whitesub` link is served over HTTPS on `SUB_HTTPS_PORT` (default
  `8443`) using a self-signed cert generated on first run — this only
  protects the channel in transit, not the identity of the server (olcbox
  connects with certificate validation disabled for this specific link, by
  design). Anyone who obtains the link/token can fetch the current pool of
  tunnel configs; there's no built-in rotation, so treat leaking it like
  leaking the `.txt` file itself.
