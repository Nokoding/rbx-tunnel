# rbx-tunnel

A high-performance iOS SOCKS5 network tunnel dylib for Roblox traffic redirection via `crossover.proxy.rlwy.net:50156`.

## Features

- **TCP Interception**: Redirects all `connect()` calls through SOCKS5 proxy
- **UDP Support**: Wraps outgoing UDP packets with SOCKS5 headers via UDP ASSOCIATE
- **DNS Proxying**: Forces all hostname resolution through the SOCKS5 proxy via `getaddrinfo()` interception
- **Low-Level Hooking**: Uses fishhook for symbol rebinding without Substrate/MSHook dependency
- **Enterprise Ready**: Target package: `com.roblox.roblox` (filter via tweak metadata)

## Build

Requires Theos environment with iOS SDK (arm64):

```bash
make
```

Output: `.theos/obj/debug/rbxtunnel.dylib`

## Installation

1. Download the compiled dylib
2. Inject into Roblox IPA using **Feather** on iPad
3. Sign with your Enterprise Certificate
4. Install on device
5. Launch Roblox—all traffic now routes through the SOCKS5 proxy

## Technical Details

- **Language**: Objective-C / C
- **Target**: iOS 14.0+, arm64
- **Hooks**: `connect()`, `sendto()`, `recvfrom()`, `getaddrinfo()`, `freeaddrinfo()`
- **SOCKS5 Handshake**: `0x05 0x01 0x00` (version, auth methods, no-auth)
- **Proxy Host**: `crossover.proxy.rlwy.net:50156` (hardcoded)
