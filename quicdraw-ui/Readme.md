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

    GitHub: https://github.com/cyberark/QuicDrawH3
    License: Apache-2.0 License
    Author: Maor Abutbul <CyberArk Labs>
    -----------
```

QuicDraw is a security research tool designed for fuzzing and racing HTTP/3 servers.
QuicDraw implements the `Quic-Fin-Sync` on HTTP/3 (over QUIC), for race-condition testing.

The tool was originally published as part of CyberArk Labs' research: "[Racing and Fuzzing HTTP/3: Open-sourcing QuicDraw(H3)](https://www.cyberark.com/resources/threat-research-blog/racing-and-fuzzing-http-3-open-sourcing-quicdraw)"

## TOC

## Quick Start

Prerequisite:

- python >=3.9
- pip3

### Install using pip

```
pip install -r requirements.txt
```

## Run quicdraw-ui

```
python quicdraw-ui/quicdraw-ui.py https://cyberark.com
```
