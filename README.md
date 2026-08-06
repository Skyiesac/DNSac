# DNS Resolver in Python

A recursive DNS resolver built from scratch in Python.

It manually parses DNS packets, follows DNS referrals from root servers, caches responses, and serves DNS queries over UDP. It handles real DNS queries with caching, TCP fallback, and EDNS0 support.

---

## Features

- **Full DNS Protocol Support** — A, AAAA, CNAME, MX, NS, TXT records while preserving unsupported records
- **Recursive Resolution** — Starts from root servers and traverses TLD and authoritative name servers
- **Smart Caching** — TTL-aware with a thread-safe key-value store
- **UDP + TCP Fallback** — Automatically retries over TCP when UDP responses are truncated
- **EDNS0 Support** — Supports larger UDP packets and the DNSSEC OK (DO) bit
- **Concurrent Processing** — 64 worker threads using `ThreadPoolExecutor`
- - **Defensive Packet Parsing**
  - Compression-pointer loop detection
  - Packet bounds checking
  - DNS transaction ID validation
  - Recursive lookup depth limits
  - Request timeout handling
- **Root Server Rotation** — Automatically switches to another root server if one times out

---

# Architecture

```text
                         ┌─────────────────────┐
                         │     DNS Client      │
                         │   dig / nslookup    │
                         └──────────┬──────────┘
                                    │
                                    │ UDP :2053
                                    ▼
                ┌───────────────────────────────────┐
                │        Local DNS Resolver         │
                │                                   │
                │  ┌─────────────────────────────┐  │
                │  │ UDP Server                  │  │
                │  │ ThreadPoolExecutor          │  │
                │  └──────────────┬──────────────┘  │
                │                 │                 │
                │  ┌──────────────▼──────────────┐  │
                │  │ DNS Packet Parser           │  │
                │  │ Header / Questions          │  │
                │  │ Records / Compression       │  │
                │  └──────────────┬──────────────┘  │
                │                 │                 │
                │  ┌──────────────▼──────────────┐  │
                │  │ TTL Cache                  │  │
                │  └──────────────┬──────────────┘  │
                │                 │                 │
                │  ┌──────────────▼──────────────┐  │
                │  │ Iterative Resolver          │  │
                │  └──────────────┬──────────────┘  │
                └─────────────────┼─────────────────┘
                                  │
                     DNS queries to port 53
                                  │
          ┌───────────────────────▼──────────────────────┐
          │                                              │
          ▼                                              ▼
 ┌──────────────────┐                         ┌──────────────────┐
 │   Root Servers   │ ───── referrals ─────▶ │   TLD Servers    │
 └──────────────────┘                         │  .com, .org ...  │
                                              └────────┬─────────┘
                                                       │
                                                       │ referral
                                                       ▼
                                              ┌──────────────────┐
                                              │ Authoritative DNS│
                                              │     Servers      │
                                              └──────────────────┘
```



DNS packet flow :

```text
Client query
     │
     ▼
Parse DNS packet
     │
     ▼
Validate request
     │
     ▼
Check cache
     │
     ├── Cache hit ──────► Return cached answer
     │
     └── Cache miss
              │
              ▼
       Query root server
              │
              ▼
       Follow referrals
              │
              ▼
       Query authoritative server
              │
              ▼
       Store response in cache
              │
              ▼
       Send response to client

```

---

# Key Components

## 1. Buffer Layer

- `BytePacketBuffer` — Handles binary packet parsing
- Compression pointer support
- Bounds checking and security validations

---

## 2. Protocol Layer

- `DnsHeader` — 12-byte header parsing and serialization
- `DnsQuestion` — Query encoding and decoding
- `DnsRecord` — Supports A, AAAA, CNAME, MX, NS, TXT, and more
- `DnsPacket` — Complete packet assembly and disassembly

---

## 3. Resolution Layer

- `recursive_lookup()` — Walks the DNS hierarchy
- `lookup()` — Queries a single DNS server with retries
- TTL-based cache
- Automatic TCP fallback for large responses

---

## 4. Server Layer

- `handle_query()` — Processes incoming DNS requests
- Thread pool for concurrent clients
- Proper DNS error codes:
  - `SERVFAIL`
  - `FORMERR`
  - `NXDOMAIN`

---

# Quick Start

```bash
# Run the server
python dns_server.py

# Test with dig
dig @127.0.0.1 -p 2053 google.com

# Or use nslookup
nslookup -port=2053 google.com 127.0.0.1
```

---

# Demo

 DNS Queries------------------------------------------------------------------------------------------Server

<p align="center">
  <img src="https://github.com/user-attachments/assets/31026fcc-39d3-49cf-bee5-bd678dca8acd" alt="DNS Resolver Demo" width="100%">
</p>

---

# Performance

| Feature | Value |
|---------|-------|
| Concurrency | 64 worker threads |
| Cache | TTL-aware (30s–3600s) |
| Retries | 3 attempts per server |
| TCP Fallback | Automatic for truncated responses |

---

# How DNS Resolution Works

For a query such as:

```text
example.com → ?
```

The resolver performs the following steps:

1. Receives the query from a client.
2. Checks the local cache.
3. If the answer is not cached, contacts a root DNS server.
4. Receives a referral to the `.com` name servers.
5. Contacts a `.com` TLD server.
6. Receives a referral to the authoritative server for `example.com`.
7. Contacts the authoritative server.
8. Receives the final answer.
9. Stores the response in the cache using its TTL.
10. Sends the answer back to the client.

---

# Contributing

Contributions are always welcome!

- ⭐ Give the repository a star if you like it.
- 🐛 Open an issue if you find a bug.
- 🔧 Submit a Pull Request to fix bugs or add new features.

---
