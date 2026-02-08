# QuicDraw (H3)

```bash
    -----------
    QuicDraw(H3): HTTP/3 Fuzzing and Racing (Client)
    -----------
               _         _
              (_)       | |                          ______
    __ _ _   _ _  ___ __| |_ __ __ ___      __  /\  /\___ /
   / _` | | | | |/ __/ _` | '__/ _` \ \ /\ / / / /_/ / |_ \
  | (_| | |_| | | (_| (_| | | | (_| |\ V  V / / __  / ___) |
   \__, |\__,_|_|\___\__,_|_|  \__,_| \_/\_/  \/ /_/ |____/
      |_|    _______
         \  |QFS____| -------------------- HTTP/3
          \ |_//
            |_|

    GitHub: https://github.com/cyberark/QuicDrawH3
    License: Apache-2.0 License
    Author: Maor Abutbul <CyberArk Labs>
    -----------
```

QuicDraw is a security research tool designed for fuzzing and racing HTTP/3 servers.
QuicDraw implements the `Quic-Fin-Sync` on HTTP/3 (over QUIC), for race-condition testing.

The tool was originally published as part of CyberArk Labs' research: "[Racing and Fuzzing HTTP/3: Open-sourcing QuicDraw(H3)](https://www.cyberark.com/resources/threat-research-blog/racing-and-fuzzing-http-3-open-sourcing-quicdraw)"

## TOC

- [QuicDraw](#quicdraw-h3)
  - [Main Features](#main-features)
  - [Quick Start](#quick-start)
    - [Install using pip](#install-using-pip)
    - [Build and install locally by cloning the source (optional)](#build-and-install-locally-by-cloning-the-source-optional)
  - [Usage](#usage)
    - [Print Help](#print-help)
    - [Normal HTTP/3 (over QUIC) Requests](#normal-http3-over-quic-requests)
    - [Log TLS Secrets to file `-l SECRETS_LOG`](#log-tls-secrets-to-file--l-secrets_log)
    - [Verbose logging `-v`](#verbose-logging--v)
    - [Testing Race-Conditions in HTTP3 applications `-tr TOTAL_REQUESTS`](#testing-race-conditions-in-http3-applications--tr-total_requests)
      - [Racing example](#racing-example)
    - [Fuzzing HTTP3 applications `-d` DATA `-w` WORDLIST](#fuzzing-http3-applications--d-data--w-wordlist)
      - [Fuzzing Example](#fuzzing-example)
- [QuicDraw-UI](#quicdraw-ui)
  - [Install quicdraw-ui using pip (PyPi)](#install-quicdraw-ui-using-pip-pypi)
  - [Example 1: Simple HTTP/3 Request](#example-1-simple-http3-request)
  - [Example 2: Fuzzing with a Wordlist](#example-2-fuzzing-with-a-wordlist)
- [Contributing](#contributing)
- [Limitations](#limitations)
- [Known issues](#known-issues)
- [License](#license)
- [Contact](#contact)
  - [Contact Via LinkedIn](#contact-via-linkedin)

##  Main Features

- Implements the `Quic-Fin-Sync` on HTTP3 (over QUIC), for race-condition testing.
- Supports fuzzing multiple requests with the `FUZZ` and wordlist (`-w` argument) mechanisms.
- Custom HTTP headers functionality (`-H` argument).
  - Note: Custom headers are converted to lowercase since we have seen issues with some server implementations.
- Supports SSLKEYLOGFILE (`-l` argument) for TLS decryption/inspection via packet analyzers such as Wireshark.
- Based on aioquic (http3_client)
  - [aioquic](https://github.com/aiortc/aioquic) is a library for the QUIC network protocol in Python.
  - It features a minimal TLS 1.3 implementation, a QUIC stack, and an HTTP/3 stack.

## Quick Start

Prerequisite:

- python >=3.9
- pip3

### Install using pip

The easiest way to install QuicDraw is to run:

```bash
pip install quicdraw
```

#### Runninig (after pip install)

```bash
quicdraw -h
```

### Build and install locally by cloning the source (optional)

If there are no wheels for your system or if you wish to build QuicDraw from source.

Clone the repository:

```bash
git clone https://github.com/cyberark/quicdrawh3.git
python3 -m build
pip install .\dist\quicdraw-<VERSION>.tar.gz
```

Install module dependencies. (You may prefer to do this within a [Virtual Environment](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/))

---

## Usage

### Print Help

```bash
quicdraw -h
```

### Normal HTTP/3 (over QUIC) Requests

### An HTTP/3 GET Request

```bash
quicdraw <https://http3_server.com/path>
```

### An HTTP/3 POST Request

HTTP POST requests are determined by using the `-d` argument followed by the HTTP POST data to be sent.

```bash
quicdraw <https://http3_server.com/path> -d '{"key":"value"}'
```

### Log TLS Secrets to file `-l SECRETS_LOG`

log secrets to a file, for use with Wireshark

To inspect the traffic in wireshark: Open Wireshark → Edit → Preferences → Protocols → TLS
and set “(Pre)-Master-Secret log filename” to the full path of secrets.log

### Verbose logging `-v`

Using the verbose (`-v`) output will log (print) the request data to be sent and the HTTP response content.

In the case of GET requests (no `-d` argument supplied), the request URL (:path) will be logged (printed).

### Testing Race-Conditions in HTTP3 applications `-tr TOTAL_REQUESTS`

To use the same request multiple times (using the `Quic-Fin-Sync` / `single-packet`), use the `-tr/--total-requests` argument.

Note: If a WORDLIST (`-w`) argument is specified, this argument (`-tr TOTAL_REQUESTS`) is overridden by the wordlist number of lines.

### Racing example

#### Repeat the same request 12 times (`-tr 12`) (using `Quic-Fin-Sync`)

```bash
quicdraw <https://http3_server.com/path> -d '{"key":"value"}' -H 'Authorization: bearer eyJ...' -tr 12
```

#### Repeat the same request 12 times (`-tr 12`), use `Quic-Fin-Sync` and log (`-l`) TLS secrets

```bash
quicdraw <https://http3_server.com/path> -d '{"key":"value"}' -H 'Authorization: bearer eyJ...' -H 'content-type: application/json' -l /m2a/ssl_key_log_file.log -tr 12
```

#### Repeat the same request 12 times (`-tr 12`), use `Quic-Fin-Sync`, log (`-l`) TLS secrets, and print verbose (`-v`) output including HTTP response content

```bash
quicdraw <https://http3_server.com/path> -d '{"key": "value"}' -H 'Authorization: bearer eyJ...' -H 'content-type: application/json' -l /m2a/ssl_key_log_file.log -tr 12 -v
```

### Fuzzing HTTP3 applications `-d` DATA `-w` WORDLIST

Fuzzing in QuicDraw is based on a simple concept, like other web fuzzers ([Ffuf](https://github.com/ffuf/ffuf), [Wfuzz](https://github.com/xmendez/wfuzz)),
go over the data section (`-d`), and replace any reference to the `FUZZ` keyword with the value given in the wordlist (`-w`) as the payload.

To define fuzzing, use the wordlist (`-w`/`--wordlist`) argument with the `FUZZ` keyword anywhere in the DATA (`-d argument`) section.

Note: If the payload (`-d`) does not include the `FUZZ` keyword, the same data will be sent according to the _number of lines_ in the wordlist file.

### Fuzzing Example

#### Use `Quic-Fin-Sync`, go over the data section (`-d`), and replace any reference to the `FUZZ` keyword with the value given in the wordlist file (`-w`) as the payload

```bash
quicdraw <https://http3_server.com/path> -w path/to/wordlist -d '{"example_key":"FUZZ"}'
```

---

# QuicDraw-UI

```bash
    -----------
    QuicDraw-UI: HTTP/3 Request Editor - A GUI for QuicDraw(H3): HTTP/3 Fuzzing and Racing (Client)
    -----------
               _         _
              (_)       | |                            __  ______
    __ _ _   _ _  ___ __| |_ __ __ ___      __        / / / /  _/
   / _` | | | | |/ __/ _` | '__/ _` \ \ /\ / / _____ / / / // /
  | (_| | |_| | | (_| (_| | | | (_| |\ V  V / /____// /_/ // /
   \__, |\__,_|_|\___\__,_|_|  \__,_| \_/\_/        \____/___/
      |_|    _______
         \  |QFS____| -------------------- HTTP/3
          \ |_//
            |_|
```

## Install quicdraw-ui using pip (PyPi)

The easiest way to install QuicDraw-UI is to run:

```bash
pip install quicdraw[ui]
quicdraw-ui -h
```

## Example 1: Simple HTTP/3 Request

Send a basic request to an HTTP/3 server:

```bash
python quicdraw-ui/quicdraw-ui.py https://www.cyberark.com
```

**HTTP/3 Request Editor:**
![HTTP/3 Request Editor](screenshots\QD-UI_basic_1.png "HTTP/3 Request Editor")

**Advanced Tab**

![Advanced Tab](screenshots\QD-UI_basic_3.png "Advanced Tab")

The following options can be set by the advanced tab

| Option              | Description                      |
| ------------------- | -------------------------------- |
| `-l, --secrets-log` | TLS secrets file (for Wireshark) |
| `-v, --verbose`     | Verbose output                   |

**Results Tab:**

![Results Tab](screenshots\QD-UI_basic_2.png "Results Tab")

---

## Example 2: Fuzzing with a Wordlist

To fuzz an HTTP/3 endpoint, you need:

1. **A wordlist file** (`-w`) - contains payloads to test (one per line)
2. **The `FUZZ` keyword** in your data - gets replaced by each wordlist entry

```bash
python quicdraw-ui/quicdraw-ui.py https://www.cyberark.com -w path/to/wordlist -d '{"example_key":"FUZZ"}'
```

![Fuzzing Example](screenshots/fuzzing.png)

The `FUZZ` keyword in `{"example_key":"FUZZ"}` will be replaced with each line from your wordlist file.

---

## Command-Line Options

| Option                  | Description                                           |
| ----------------------- | ----------------------------------------------------- |
| `-d, --data`            | POST body data (use `FUZZ` for wordlist substitution) |
| `-H, --header`          | Custom header (repeatable)                            |
| `-w, --wordlist`        | Fuzzing wordlist file                                 |
| `-tr, --total-requests` | Number of concurrent requests (race testing)          |
| `-l, --secrets-log`     | TLS secrets file (for Wireshark)                      |
| `-v, --verbose`         | Verbose output                                        |

---

# Contributing

We welcome contributions of all kinds to this repository.
For instructions on how to get started and descriptions of our development workflows, please see our [contributing guide](CONTRIBUTING.md)

# Limitations

- The `Quic-Fin-Sync` is mostly effective in POST requests (using the `-d` argument).
  - GET requests will benefit from the mechanism, but according to our tests, only a few requests "fit" on a single QUIC packet.
- The fuzzing mechanism (`FUZZ` and `--wordlist/-w`) only works in POST messages data **or** in the GET request URL (:path) argument.
- Currently, the fuzzing mechanism only works **once**, meaning if the data argument is supplied (`-d`), we assume fuzzing on the POST data, supplying the `FUZZ` keyword in the URL (:path) will result in sending the URL (:path) as-is (including the `FUZZ` keyword).
- We do not support multiple different domains in the current version. (For different paths, you can use the FUZZ keyword in the URL's path part)

---

# Known issues

- On DNS error - the following error returned: "socket.gaierror: [Errno 11001] getaddrinfo failed"

# License

Copyright (c) 2025 CyberArk Software Ltd. All rights reserved
This repository is licensed under the Apache-2.0 License - see [`LICENSE`](LICENSE) for more details.

# Contact

Feel free to contact us via GitHub issues if you have any feature requests or project issues.

## Contact Via LinkedIn

[Maor Abutbul](https://il.linkedin.com/in/maor-abutbul)
