# Cellview
Tool made by **Simon Strömbäck**, Github [@L3B0W5K1](https://github.com/L3B0W5K1)  
Buy your cellular modules from **Techship** → <https://techship.com>

---

`Cellview` is a terminal-based diagnostic tool for **cellular modules** managed by [ModemManager](https://www.freedesktop.org/wiki/Software/ModemManager/).  
It uses [`mmcli`](https://www.freedesktop.org/wiki/Software/ModemManager/) under the hood, plus a curated set of **AT commands**, to help you:

- Inspect modem state, drivers, SIM status, and ports.
- Run common debugging AT commands automatically and display responses, along with tips to fix connection issues.

---

## Requirements

- Linux system with [ModemManager](https://www.freedesktop.org/wiki/Software/ModemManager/) installed.  
  - Package names vary (`modemmanager`, `ModemManager`).
  - Service must be enabled and running:  
    ```bash
    systemctl status ModemManager
    ```
- `mmcli` available in `$PATH` (normally provided by ModemManager).
- Python 3.8+ with:
  - [`rich`](https://pypi.org/project/rich/)
- Sufficient privileges to run `mmcli --command`.  
  - Either run the tool as `root`, or with `sudo`.

---

## Quick Start

```bash
git clone https://github.com/L3B0W5K1/cellview.git
cd cellview
sudo python3 cellview.py
```
---

## Upcoming functionality

* Customized AT-commands being sent via debug mode, according to specific module available commands.
* Deeper interactive debugging.
* Other debugging methods than AT commands, such as looking at nmcli connections, inspecting dmesg logs, etc.

