#!/usr/bin/env python3
import subprocess
import time
import re
import glob
import os
import unicodedata
import random
import signal
import shutil
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.text import Text

console = Console()

# ---------------------------
# Visual / animation constants
# ---------------------------
H_WAVES = ["~~~ ~~~ ~~~", " ~~~ ~~~ ~~", "~ ~~~ ~~~ ~", "~~ ~~~ ~~~ "]
TOWER_LINES = [
    r"       \    /           ",
    r"        \  /            ",
    r"  _______\/_______      ",
    r"        /||\            ",
    r"       / /\ \           ",
    r"      / /  \ \          ",
    r"       /\  /\           ",
    r"      /  \/  \          ",
    r"     /\  /\  /\         ",
    r"    /  \/  \/  \        ",
    r"   /\  /\  /\  /\       ",
    r"  /  \/  \/  \/  \      "
]
TOWER_WIDTH = max(len(line) for line in TOWER_LINES)

ANTENNA_LINES = [
    r"      ____            ",
    r"     |  _||         ",
    r"     |  _||         ",
    r"     |  _||         ",
    r"     |  _||         ",
    r"     |  _||         ",
    r"     |  _||         ",
    r"     | __|/         ",
    r"     | |            ",
    r"     |_|            ",
    r"____/___\_          ",
    r"  /_______\         "
]

CABLE_LINES = [
    r" /",
    r" \         ________",
    r"  \_______/        \__________________",
]

WAVE_ROWS = [2, 4, 6]
CONNECTED_STATES = {"registered", "connected", "attached"}
NETWORK_DRIVERS = {"qmi_wwan", "cdc_mbim", "rndis_host"}
SERIAL_DRIVERS = {"option", "qcserial", "qcserial2"}
GAP_WIDTH = 12
BLINK_PERIOD = 8
_ansi_re = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

# ---------------------------
# Interactive prompt state
# ---------------------------
INTERACTIVE_PROMPT = {
    "active": False,       # are we currently asking a question?
    "question": "",      # the question text
    "response": None,      # raw response string
    "show_response": False, # if true, keep response visible in dashboard
    # NOTE: `display_in_dashboard` controls whether the question is rendered inside the live dashboard.
    # We'll keep it False so prompts are shown next to the input (console.input) instead of inside Live.
    "display_in_dashboard": False,
    "debugging": False     # when true, live updates are suppressed
}

# ---------------------------
# Utility functions
# ---------------------------

def strip_ansi(s: str) -> str:
    if not s:
        return ""
    return _ansi_re.sub("", s)


def display_width(s: str) -> int:
    s = strip_ansi(s)
    w = 0
    for ch in s:
        o = ord(ch)
        if o == 0:
            continue
        if o < 32 or (0x7f <= o < 0xa0):
            continue
        if unicodedata.combining(ch):
            continue
        ea = unicodedata.east_asian_width(ch)
        if ea in ("W", "F"):
            w += 2
        else:
            w += 1
    return w


def truncate_to_width(s: str, max_w: int) -> str:
    s = s or ""
    s = strip_ansi(s)
    out = []
    w = 0
    for ch in s:
        ch_w = 0
        o = ord(ch)
        if o == 0:
            ch_w = 0
        elif o < 32 or (0x7f <= o < 0xa0):
            ch_w = 0
        elif unicodedata.combining(ch):
            ch_w = 0
        else:
            ea = unicodedata.east_asian_width(ch)
            ch_w = 2 if ea in ("W", "F") else 1
        if w + ch_w > max_w:
            break
        out.append(ch)
        w += ch_w
    return "".join(out)


def pad_left(s: str, total_w: int) -> str:
    cur = display_width(s)
    if cur >= total_w:
        return s
    return " " * (total_w - cur) + s


def pad_right(s: str, total_w: int) -> str:
    cur = display_width(s)
    if cur >= total_w:
        return s
    return s + " " * (total_w - cur)


def pad_center(s: str, total_w: int) -> str:
    cur = display_width(s)
    if cur >= total_w:
        return s
    left = (total_w - cur) // 2
    right = total_w - cur - left
    return " " * left + s + " " * right


def run_cmd(cmd, timeout=1):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""


def run_cmd_full(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as e:
        return 255, "", str(e)

# ---------------------------
# ModemManager / system helpers
# ---------------------------

def check_modemmanager_active():
    rc, out, err = run_cmd_full(["systemctl", "is-active", "ModemManager.service"], timeout=1)
    is_active = out.strip() == "active"
    if is_active:
        return True, "active"
    _, st_out, st_err = run_cmd_full(["systemctl", "status", "ModemManager.service", "--no-pager"], timeout=2)
    status_text = (st_out + st_err).strip() or "ModemManager service not running (no additional info)"
    return False, status_text


def get_usb_drivers_global():
    drivers = []
    for path in glob.glob("/sys/bus/usb/devices/*"):
        drv_link = os.path.join(path, "driver")
        if os.path.islink(drv_link):
            drivers.append(os.path.basename(os.readlink(drv_link)))
    return sorted(set(drivers))


def get_drivers_for_device(device_path):
    drivers = []
    try:
        if device_path and os.path.exists(device_path):
            drv = os.path.join(device_path, "driver")
            if os.path.islink(drv):
                drivers.append(os.path.basename(os.readlink(drv)))
            for child in glob.glob(os.path.join(device_path, "*")):
                child_drv = os.path.join(child, "driver")
                if os.path.islink(child_drv):
                    drivers.append(os.path.basename(os.readlink(child_drv)))
            parent = os.path.dirname(device_path)
            for _ in range(3):
                pd = os.path.join(parent, "driver")
                if os.path.islink(pd):
                    drivers.append(os.path.basename(os.readlink(pd)))
                parent = os.path.dirname(parent)
    except Exception:
        pass
    if not drivers:
        drivers = get_usb_drivers_global()
    return sorted(set(drivers))


def classify_drivers(drivers):
    net = []
    ser = []
    for d in drivers:
        if d in NETWORK_DRIVERS:
            net.append(d)
        if d in SERIAL_DRIVERS:
            ser.append(d)
    parts = []
    if net:
        parts.append("Net:" + ",".join(net))
    if ser:
        parts.append("Ser:" + ",".join(ser))
    combined = "; ".join(parts) if parts else "Unknown"
    return net, ser, combined


def detect_form_factor(device_path):
    if not device_path:
        return "unknown"
    p = device_path.lower()
    if "usb" in p:
        return "usb-dongle"
    if "pci" in p or "pcie" in p:
        return "mPCIe/M.2"
    return "internal"


def extract_operator(out_text):
    for line in out_text.splitlines():
        low = line.lower()
        if "operator name" in low:
            parts = line.split(":", 1)
            if len(parts) > 1:
                return parts[1].strip().strip("'\"")
        if re.search(r"\boperator\b\s*:", low) and "operator id" not in low:
            parts = line.split(":", 1)
            if len(parts) > 1:
                return parts[1].strip().strip("'\"")
    m = re.search(r"operator[:=]\s*'?\"?([A-Za-z0-9 \-+]+)'?\"?", out_text, re.I)
    if m:
        return m.group(1).strip()
    return ""

# ---------------------------
# mmcli -m any parsing helpers
# ---------------------------

def parse_mmcli_any_sections(out_text: str) -> dict:
    """
    Parse mmcli -m any output for Status and System key: value pairs.
    Returns a dict with keys lowercased, e.g. 'state', 'failed reason', 'power state',
    'device', 'physdev', 'drivers', 'plugin', 'primary port', 'ports'
    """
    result = {}
    last_key = None
    for line in (out_text or "").splitlines():
        if '|' not in line:
            continue
        part = line.split('|', 1)[1]
        m = re.match(r'\s*([A-Za-z0-9 \-]+):\s*(.*)$', part)
        if m:
            key = m.group(1).strip().lower()
            val = m.group(2).strip()
            result[key] = val
            last_key = key
        else:
            # continuation line (no key)
            cont = part.strip()
            if last_key:
                # append with a space
                result[last_key] = (result.get(last_key, "") + " " + cont).strip()
    return result


def check_sim_and_system(mmcli_out: Optional[str] = None) -> dict:
    """
    Return parsed info for the modem from mmcli -m any.
    Keys returned: state, failed_reason, power_state, device, physdev, drivers (list),
    plugin, primary_port, ports (list).
    """
    if mmcli_out is None:
        mmcli_out = run_cmd(["mmcli", "-m", "any"])
    parsed = parse_mmcli_any_sections(mmcli_out)
    info = {}
    info['state'] = parsed.get('state')
    info['failed_reason'] = parsed.get('failed reason') or parsed.get('failed_reason') or parsed.get('fail reason')
    info['power_state'] = parsed.get('power state')
    info['device'] = parsed.get('device') or parsed.get('physdev')
    drivers = parsed.get('drivers') or ""
    info['drivers'] = [d.strip() for d in re.split(r'[,\s]+', drivers) if d.strip()] if drivers else []
    info['plugin'] = parsed.get('plugin')
    info['primary_port'] = parsed.get('primary port')
    ports_raw = parsed.get('ports') or ""
    # ports may be split across commas and parentheses like: "cdc-wdm0 (qmi), ttyUSB0 (ignored), wwan0 (net)"
    ports = []
    if ports_raw:
        # split on comma, extract port name before first space or before '('
        for p in re.split(r',', ports_raw):
            p = p.strip()
            if not p:
                continue
            m = re.match(r'([^\s(]+)', p)
            if m:
                ports.append(m.group(1).strip())
            else:
                ports.append(p)
    info['ports'] = ports
    return info


def find_network_interface_from_ports(info: dict) -> Optional[str]:
    """
    Return the best candidate network interface from info['ports'] or primary_port, preferring 'wwan*' or '(net)'.
    """
    # prefer primary_port if looks like wwan*
    prim = info.get('primary_port')
    if prim and prim.startswith('wwan'):
        return prim
    # search ports for net-like ports or wwan
    for p in info.get('ports', []):
        if p.startswith('wwan') or 'wwan' in p:
            return p
    # fallback: pick first port that looks like cdc-wdm or wwan
    for p in info.get('ports', []):
        if p.startswith('cdc-') or p.startswith('wwan'):
            return p
    return None


def ping_interface(iface: str, count: int = 3, dest: str = "8.8.8.8") -> bool:
    """Ping dest from interface iface. Returns True if any reply (rc==0)."""
    if not iface:
        return False
    # prefer to run ping directly; may need sudo for specifying interface
    rc, out, err = run_cmd_full(["ping", "-I", iface, "-c", str(count), dest], timeout=8)
    return rc == 0

# ---------------------------
# Cable animation
# ---------------------------

def compute_bit_positions(cable_lines):
    positions_per_row = []
    for line in cable_lines:
        positions = []
        for i, ch in enumerate(line):
            if ch in "-_":
                positions.append(i)
        for i, ch in enumerate(line):
            if ch in ("/", "\\"):
                for j in range(i + 1, min(len(line), i + 40)):
                    if line[j] == " ":
                        positions.append(j)
                    else:
                        break
        positions = sorted(set(positions))
        positions_per_row.append(positions)
    return positions_per_row

BIT_POSITIONS = compute_bit_positions(CABLE_LINES)


def animate_cable(bits_positions, step, connected: bool):
    animated = []
    rng = random.Random(step)
    for row_idx, base_line in enumerate(CABLE_LINES):
        chars = list(base_line)
        positions = bits_positions[row_idx]
        if positions:
            if connected:
                npos = len(positions)
                base = (step * 1) % npos
                count = min(3, max(1, npos // 4 + 1))
                spacing = max(1, npos // max(1, count))
                for b in range(count):
                    idx = (base + b * spacing) % npos
                    pos = positions[idx]
                    chars[pos] = rng.choice(["1", "0"])
                if rng.random() < 0.08:
                    pos = positions[rng.randrange(npos)]
                    chars[pos] = rng.choice(["1", "0"])
            else:
                mid_idx = len(positions) // 2
                pos = positions[mid_idx]
                chars[pos] = "X"
        animated.append("".join(chars))
    return animated

# ---------------------------
# Modem/art builder
# ---------------------------

def build_modem_art_lines(info: dict, box_inner_w: int, cable_override: list = None) -> list:
    inner_w = box_inner_w
    content_w = inner_w - 2
    model_line = truncate_to_width(info.get("model", "Unknown"), content_w)
    state_line = truncate_to_width(f"State: {info.get('state','Unknown')}", content_w)
    signal_line = truncate_to_width(f"Signal: {info.get('signal','')}", content_w)
    driver_line = truncate_to_width(f"Driver: {info.get('driver_display','')}", content_w)
    ff = info.get("form_factor", "unknown")
    if ff == "usb-dongle":
        form_line = "[usb dongle]"
    elif ff == "mPCIe/M.2":
        form_line = "[mPCIe/M.2]"
    else:
        form_line = "[internal]"
    form_line = truncate_to_width(form_line, content_w)
    lines = []
    lines.append("  +" + "-" * inner_w + "+")
    lines.append("  |" + " " + pad_center("Modem", content_w) + " " + "|")
    lines.append("  |" + " " + pad_center(model_line, content_w) + " " + "|")
    lines.append("  |" + " " + pad_center(state_line, content_w) + " " + "|")
    lines.append("  |" + " " + pad_right(signal_line, content_w) + " " + "|")
    lines.append("  |" + " " + pad_right(driver_line, content_w) + " " + "|")
    lines.append("  |" + "O" + pad_center(form_line, content_w) + " " + "|")
    lines.append("  /" + "-" * inner_w + "+")
    cable = cable_override if cable_override is not None else CABLE_LINES
    lines.extend(cable)
    return lines

# ---------------------------
# Dashboard builder
# ---------------------------

def build_dashboard(info: dict, wave_index: int, step: int) -> Text:
    connected = bool(info.get("connected", False))
    raw_provider = (info.get("operator") or "").strip()
    provider_known = bool(raw_provider)
    provider_text = raw_provider if provider_known else "APN unknown"
    animated_cable = animate_cable(BIT_POSITIONS, step, connected)
    content_candidates = [
        info.get("model", ""),
        f"State: {info.get('state','')}",
        f"Signal: {info.get('signal','')}",
        f"Driver: {info.get('driver_display','')}",
    ]
    content_w_plain = max(display_width(s) for s in content_candidates)
    content_w = max(10, content_w_plain)
    inner_w = min(max(12, content_w + 2), 60)
    modem_lines = build_modem_art_lines(info, inner_w, cable_override=animated_cable)
    cable_len = len(animated_cable)
    cable_start = len(modem_lines) - cable_len
    MODEM_BOX_STR_WIDTH = len(modem_lines[0])
    MODEM_BOX_DISPLAY_W = display_width(modem_lines[0])
    GAP_WAVE = GAP_WIDTH
    ANTENNA_COL_WIDTH = max(display_width(line.rstrip()) for line in ANTENNA_LINES)
    TOWER_COL_WIDTH = TOWER_WIDTH
    val = info.get("signal_val", 0)
    if val > 90:
        wave_color = "green"
    elif val > 70:
        wave_color = "yellow"
    else:
        wave_color = "red"
    total_rows = max(len(modem_lines), len(TOWER_LINES), len(ANTENNA_LINES))
    if len(modem_lines) < total_rows:
        pad_line = " " * MODEM_BOX_STR_WIDTH
        modem_lines = modem_lines + [pad_line] * (total_rows - len(modem_lines))
    dashboard_lines = []
    blink_on = (step % BLINK_PERIOD) < (BLINK_PERIOD // 2)
    blink_style = "bold magenta" if blink_on else "white"
    for i in range(total_rows):
        left_raw = modem_lines[i] if i < len(modem_lines) else ""
        left_clipped = truncate_to_width(left_raw, MODEM_BOX_DISPLAY_W)
        left_str = pad_right(left_clipped, MODEM_BOX_DISPLAY_W)
        left_t = Text(left_str)
        if cable_start <= i < cable_start + cable_len:
            for idx, ch in enumerate(left_clipped):
                if ch in ("1", "0") and connected:
                    try:
                        left_t.stylize("green", idx, idx + 1)
                    except Exception:
                        pass
                elif ch == "X" and not connected:
                    try:
                        left_t.stylize("red", idx, idx + 1)
                    except Exception:
                        pass
        antenna_raw = ANTENNA_LINES[i] if i < len(ANTENNA_LINES) else ""
        antenna_str = pad_right(antenna_raw.rstrip(), ANTENNA_COL_WIDTH)
        antenna_t = Text(antenna_str)
        if i in WAVE_ROWS:
            if connected:
                wave_text = H_WAVES[wave_index % len(H_WAVES)]
                if display_width(wave_text) > GAP_WAVE:
                    wave_text = truncate_to_width(wave_text, GAP_WAVE)
                middle_str = pad_center(wave_text, GAP_WAVE)
                middle_t = Text(middle_str, style=wave_color)
            else:
                middle_t = Text(pad_center("X", GAP_WAVE), style="red")
        else:
            middle_t = Text(" " * GAP_WAVE)
        right_raw = TOWER_LINES[i] if i < len(TOWER_LINES) else ""
        tower_str = pad_right(right_raw, TOWER_COL_WIDTH)
        tower_t = Text(tower_str)
        if provider_known and i in (0, 1, 2):
            tower_t = Text(tower_str, style=blink_style)
        if i == 1:
            if provider_known:
                base = Text(tower_str, style=blink_style)
                base.append("  ")
                base.append(provider_text, style="bold magenta")
                tower_t = base
            else:
                base = Text(tower_str)
                base.append("  ")
                base.append(provider_text, style="dim")
                tower_t = base
        if provider_known and i in (3, 4, 5):
            left_idx = None
            right_idx = None
            for idx, ch in enumerate(tower_str):
                if ch in ("/", "\\"):
                    if left_idx is None:
                        left_idx = idx
                    right_idx = idx
            if left_idx is not None:
                try:
                    tower_t.stylize(blink_style, left_idx, left_idx + 1)
                except Exception:
                    pass
            if right_idx is not None and right_idx != left_idx:
                try:
                    tower_t.stylize(blink_style, right_idx, right_idx + 1)
                except Exception:
                    pass
        dashboard_lines.append(left_t + antenna_t + middle_t + tower_t)
    # Add interactive prompt area (if active) -- only if explicitly requested to be shown inside dashboard
    if INTERACTIVE_PROMPT.get("active") and INTERACTIVE_PROMPT.get("display_in_dashboard"):
        q = INTERACTIVE_PROMPT.get("question", "")
        dashboard_lines.append(Text(""))
        dashboard_lines.append(Text(q, style="bold yellow"))
        if INTERACTIVE_PROMPT.get("show_response") and INTERACTIVE_PROMPT.get("response") is not None:
            dashboard_lines.append(Text(f"You typed: {INTERACTIVE_PROMPT.get('response')}", style="bold green"))
    # Status lines
    if info.get("error"):
        error_line = Text(f"Error: {info['error']}", style="red")
    else:
        error_line = Text("Status: OK", style="green")
    device_line = None
    if info.get("device_path"):
        dp = info["device_path"]
        if len(dp) > 100:
            dp = "..." + dp[-97:]
        device_line = Text(f"Device: {dp}", style="dim")
    body = Text("\n").join(dashboard_lines)
    pieces = [body]
    if device_line:
        pieces.append(device_line)
    pieces.append(error_line)
    pieces.append(Text(""))
    pieces.append(Text("Tool made by Simon Strömbäck, Github @L3B0W5K1", style="dim"))
    pieces.append(Text("Buy your cellular modules from Techship at https://techship.com", style="dim"))
    return Text("\n").join(pieces)

# ---------------------------
# AT debug helpers
# ---------------------------

AT_COMMANDS = [
    "AT+CFUN?",
    "AT+CSQ",
    "AT+CGATT?",
    "AT+CREG?",
    "AT+COPS?",
]


def analyze_at_response(cmd: str, resp: str) -> str:
    r = resp or ""
    lr = r.lower()
    if cmd.startswith("AT+CFUN"):
        # look for CFUN: <n> or "+CFUN: n"
        m = re.search(r"\+?cfun[: ]\s*(\d)", lr)
        if m:
            if m.group(1) == '0':
                return "Module reports CFUN=0 -> module is powered down / not functioning correctly. Try power-cycling or checking firmware."
            elif m.group(1) in ('1','4'):
                return "CFUN indicates RF on (1) or minimal (4). If you have no network, check antenna and SIM/APN settings."
        if "error" in lr:
            return "CFUN command returned an error. Ensure the modem accepts AT commands and isn't busy (try resetting or checking permissions)."
    if cmd.startswith("AT+CSQ"):
        m = re.search(r"(\d+),(\d+)", r)
        if m:
            rssi = int(m.group(1))
            if rssi == 99:
                return "CSQ reports 99 (unknown). SIM/antenna may be missing or modem can't measure signal."
            else:
                return f"Signal RSSI={rssi} (0..31). Low values indicate weak signal."
    if cmd.startswith("AT+CGATT"):
        if "+cgatt: 1" in lr or "cgatt: 1" in lr or "attached" in lr:
            return "Modem is GPRS-attached."
        if "+cgatt: 0" in lr or "cgatt: 0" in lr:
            return "Modem is not GPRS-attached. Check PDP context/APN and network registration."
    if cmd.startswith("AT+CREG"):
        if "+creg: 0,1" in lr or "+creg: 0,5" in lr:
            return "Registered to network."
        if "+creg:" in lr and ("0,2" in lr or ",2" in lr):
            return "Searching or denied. Check SIM, network, and operator settings."
    if cmd.startswith("AT+COPS"):
        if "+cops:" in lr and ("0" in lr or "2" in lr or "3" in lr):
            return "COPS response indicates selection state - check if operator is as expected."
    return "No specific tip for this response. Review the response above for clues."

# ---------------------------
# ModemManager debug process helpers
# ---------------------------

def systemctl_available() -> bool:
    return shutil.which("systemctl") is not None


def stop_modemmanager_service():
    """Stop the systemd ModemManager service (best-effort). Returns (success_bool, detail_str).

    IMPORTANT: This will *stop* the service but will never disable it. The code never calls
    'systemctl disable' and will attempt to re-enable if it finds the service disabled.
    """
    if not systemctl_available():
        return False, "systemctl not found"
    rc, out, err = run_cmd_full(["sudo", "systemctl", "stop", "ModemManager.service"], timeout=5)
    time.sleep(0.3)
    rc2, out2, err2 = run_cmd_full(["sudo", "systemctl", "is-active", "ModemManager.service"], timeout=1)
    active = (out2.strip() == "active")
    return (not active), out + err + out2 + err2


def start_modemmanager_service():
    """Start the systemd ModemManager service. Returns (success_bool, detail_str)."""
    if not systemctl_available():
        return False, "systemctl not found"
    rc, out, err = run_cmd_full(["sudo", "systemctl", "start", "ModemManager.service"], timeout=5)
    time.sleep(0.3)
    rc2, out2, err2 = run_cmd_full(["sudo", "systemctl", "is-active", "ModemManager.service"], timeout=1)
    return (out2.strip() == "active"), out + err + out2 + err2


def ensure_modemmanager_enabled():
    """Check if ModemManager.service is disabled and try to re-enable it. Returns (ok, message).
    We never want the program to disable the service; this function tries to detect and fix accidental 'disabled' state.
    """
    if not systemctl_available():
        return True, "systemctl not available"
    rc, out, err = run_cmd_full(["systemctl", "is-enabled", "ModemManager.service"], timeout=2)
    enabled = out.strip()
    if enabled == "disabled":
        # Try to re-enable (best-effort). Use sudo to enable if available.
        sudo = shutil.which("sudo")
        if sudo:
            rc2, out2, err2 = run_cmd_full([sudo, "systemctl", "enable", "ModemManager.service"], timeout=5)
            if rc2 == 0:
                return True, "Service was disabled; re-enabled successfully"
            else:
                return False, f"Service disabled and could not be re-enabled: {out2} {err2}"
        return False, "Service disabled and sudo not available to re-enable"
    return True, "Service enabled or static"


def start_modemmanager_debug_process(logfile="/tmp/modemmanager-debug.log"):
    """
    Stop systemd service, then start /usr/sbin/ModemManager --debug in background.
    Returns (proc, None) on success; (None, error_str) on failure.

    IMPORTANT: This version does NOT open or write any logfile. Output from the debug
    ModemManager instance is discarded (redirected to /dev/null). This avoids permission
    errors and ensures we don't create files.
    """
    # Safety: ensure service isn't disabled (we don't want to leave it disabled accidentally)
    ok, msg = ensure_modemmanager_enabled()
    if not ok:
        return None, f"ModemManager service disabled or not correct state: {msg}"

    # Attempt to stop systemd-managed service first (best-effort)
    try:
        stop_modemmanager_service()
    except Exception:
        pass

    # Binary check
    if not os.path.exists("/usr/sbin/ModemManager"):
        return None, "ModemManager binary not found at /usr/sbin/ModemManager"

    # Determine command: run directly as root, otherwise via sudo (if available)
    if os.geteuid() == 0:
        cmd = ["/usr/sbin/ModemManager", "--debug"]
    else:
        sudo_path = shutil.which("sudo")
        if sudo_path:
            cmd = [sudo_path, "/usr/sbin/ModemManager", "--debug"]
        else:
            return None, "Not running as root and sudo not available; can't start ModemManager --debug"

    try:
        # start in its own process group so we can kill the whole group later
        # Redirect output to DEVNULL so we do not open any logfile.
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setpgrp
        )
    except PermissionError:
        return None, "Permission denied launching ModemManager --debug (run script as root or via sudo)."
    except Exception as e:
        return None, f"Failed to start ModemManager --debug: {e}"

    # Give it a brief moment to initialise
    time.sleep(0.5)
    return proc, None



def stop_modemmanager_debug_process(proc, fd=None):
    """Stop the background debug-mode process (if any) and close fd."""
    if not proc:
        return
    try:
        # Kill the process group first (SIGINT then SIGTERM fallback)
        os.killpg(proc.pid, signal.SIGINT)
    except Exception:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            pass
    try:
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        if fd:
            fd.close()
    except Exception:
        pass

# ---------------------------
# Wait helpers for modem enumeration
# ---------------------------

def wait_for_modem_any(timeout_seconds=12, poll_interval=0.5):
    """Wait until 'mmcli -m any' shows something that looks like a modem. Returns True if found."""
    # run a couple of scans to encourage modemmanager to poll hardware
    try:
        run_cmd(["sudo","mmcli","-S"])
    except Exception:
        pass
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            run_cmd(["sudo","mmcli","-S"])
        except Exception:
            pass
        out = run_cmd(["mmcli", "-m", "any"], timeout=2)
        low = (out or "").lower()
        if not out:
            time.sleep(poll_interval)
            continue
        if "couldn't find modem" in low or "no modems were found" in low or ("error" in low and "/modem/" not in out.lower() and "model" not in low):
            time.sleep(poll_interval)
            continue
        if "/modem/" in out.lower() or "model" in low or "state" in low:
            return True
        time.sleep(poll_interval)
    return False

# ---------------------------
# Updated run_debug_sequence (use mmcli -m any and wait)
# ---------------------------

def run_debug_sequence(_: Optional[str] = None):
    """Start ModemManager in --debug in background, wait for modem to appear, run AT commands via mmcli -m any,
    then stop debug-mode and restart systemd service. Returns True if user wants to restart cellview.

    Note: If starting the debug-mode process fails (e.g. no sudo, permission issue), this function
    will NOT abort — it will proceed to execute the AT command checks without a debug-mode process.
    """
    console.print("\nEntering debug mode (pre-checks + mmcli --command).", style="bold yellow")

    # First, gather mmcli -m any output and parse Status/System fields
    mm_out = run_cmd(["mmcli", "-m", "any"])
    if not mm_out:
        console.print("No mmcli output available (mmcli -m any returned empty). Continuing to debug checks.", style="dim")
        parsed_info = {}
    else:
        parsed_info = check_sim_and_system(mm_out)
    # Print the parsed key facts
    console.print("\n-- Modem summary from mmcli -m any --", style="dim")
    for k in ("state", "failed_reason", "power_state", "device", "plugin", "drivers", "primary_port", "ports"):
        v = parsed_info.get(k)
        if v is None:
            continue
        console.print(f"{k}: {v}")

    # If SIM missing, skip debug (no point)
    fr = (parsed_info.get('failed_reason') or "").lower()
    if 'sim' in fr:
        console.print("\nDetected SIM issue (failed reason contains 'sim'). Skipping debug sequence.", style="red")
        console.print("Resolve SIM/reader issues (SIM inserted, proper PIN, etc.) before running debug.", style="dim")
        return False

    # If there is a network interface and it responds to ping, skip debug
    net_iface = find_network_interface_from_ports(parsed_info)
    if net_iface:
        console.print(f"\nDetected network interface candidate: {net_iface}", style="dim")
        try:
            ok = ping_interface(net_iface, count=3, dest="8.8.8.8")
        except Exception:
            ok = False
        if ok:
            console.print(f"Interface {net_iface} can reach the internet (ping succeeded). Skipping debug.", style="green")
            return False
        else:
            console.print(f"Interface {net_iface} did not respond to ping. Proceeding to debug.", style="yellow")
    else:
        console.print("\nNo network interface found in mmcli 'ports' output. Proceeding to debug.", style="dim")

    # Start ModemManager --debug in background (output discarded)
    proc_or_none, err_or_none = start_modemmanager_debug_process(logfile="/tmp/modemmanager-debug.log")
    if proc_or_none is None:
        console.print(f"Failed to start ModemManager in debug mode: {err_or_none}", style="red")
        console.print("Proceeding to run AT commands without a debug-mode ModemManager instance.", style="yellow")
        # continue — do not return; AT commands are still useful even without debug-mode
    else:
        console.print("ModemManager started in debug mode (background). Debug output is discarded.", style="cyan")

        # Wait for modem to be enumerated (gives ModemManager time to detect device)
        wait_for_modem_seconds = 30
        console.print(f"Waiting up to {wait_for_modem_seconds}s for modem to appear...", style="dim")
        found = wait_for_modem_any(timeout_seconds=wait_for_modem_seconds)
        if found:
            console.print("Modem detected by ModemManager.", style="green")
        else:
            console.print("Modem not detected within wait window. Will still attempt AT commands and retry per-command.", style="yellow")

    # Use mmcli -m any for AT commands and retry each command a few times if 'couldn't find modem'
    try:
        for cmd in AT_COMMANDS:
            console.print(f"\n> Sending: {cmd}", style="bold")
            attempts = 0
            max_attempts = 10
            attempt_delay = 1.0
            combined = ""
            while attempts < max_attempts:
                attempts += 1
                rc, out, err = run_cmd_full(["sudo", "mmcli", "-m", "any", "--command", cmd], timeout=8)
                combined = "".join([out or "", err or ""]).strip()
                low = (combined or "").lower()
                # success condition: we have something that isn't 'couldn't find modem' or similar
                if combined and "couldn't find modem" not in low and "no modems were found" not in low:
                    break
                # else show retry and backoff a bit
                console.print(f"(attempt {attempts}/{max_attempts} - modem not ready or no endpoint; sleeping {attempt_delay:.1f}s)", style="dim")
                time.sleep(attempt_delay)
                attempt_delay = min(attempt_delay * 1.6, 8.0)
            if not combined:
                combined = f"(no response after {attempts} tries, rc={rc})"
            console.print(Text(combined))
            tip = analyze_at_response(cmd, combined)
            console.print(Text(f"Tip: {tip}"), style="cyan")
    finally:
        # Stop debug-mode daemon (if we started one) and restart the system service BEFORE asking the user.
        console.print("\nStopping debug-mode ModemManager (if any) and restoring system service...", style="yellow")
        try:
            stop_modemmanager_debug_process(proc_or_none, None)
        except Exception:
            pass
        ok, out = start_modemmanager_service()
        if ok:
            console.print("ModemManager system service restarted.", style="green")
        else:
            console.print("Failed to restart ModemManager system service (you may need to run it manually).", style="red")

    # After service restoration, ask whether to restart the dashboard
    res = console.input("\nWere the issues resolved? Start cellview again? (yes/no): ").strip().lower()
    return res == "yes"


# ---------------------------
# Main loop
# ---------------------------

def parse_mmcli():
    """Existing UI parse helper (keeps using mmcli -m any for dashboard)."""
    mm_active, mm_status = check_modemmanager_active()
    if not mm_active:
        return {
            "model": "Unknown",
            "state": "Unknown",
            "connected": False,
            "signal": "0%",
            "signal_val": 0,
            "error": "ModemManager not running, start it to get cellview to work.",
            "drivers_list": [],
            "driver_display": "Unknown",
            "device_path": "",
            "form_factor": "unknown",
            "operator": "",
            "at_response": None
        }
    out = run_cmd(["mmcli", "-m", "any"])
    if not out:
        drivers_list = get_usb_drivers_global()
        _, _, combined = classify_drivers(drivers_list)
        return {
            "model": "Unknown",
            "state": "Unknown",
            "connected": False,
            "signal": "0%",
            "signal_val": 0,
            "error": "Not connecting (state: Unknown)",
            "drivers_list": drivers_list,
            "driver_display": combined,
            "device_path": "",
            "form_factor": "unknown",
            "operator": ""
        }
    model = "Unknown"
    state_display = "Unknown"
    signal_raw = ""
    device_path = ""
    driver_from_mmcli = ""
    error_txt = ""
    mo = re.search(r"model\s*:\s*'?(.+?)'?(:?\n|\r|$)", out, re.I)
    if mo:
        model = mo.group(1).strip()
    else:
        mo2 = re.search(r"Model:\s*(.+)", out, re.I)
        if mo2:
            model = mo2.group(1).strip()
    so = re.search(r"state\s*:\s*'?(.+?)'?(:?\n|\r|$)", out, re.I)
    if so:
        state_display = so.group(1).strip()
    else:
        so2 = re.search(r"^\s*state\s*[:|]\s*(.+)$", out, re.I | re.M)
        if so2:
            state_display = so2.group(1).strip()
    state_norm = ""
    if state_display:
        m = re.match(r'\s*([A-Za-z0-9_-]+)', state_display)
        state_norm = m.group(1).lower() if m else state_display.strip().lower()
    else:
        state_norm = ""
    out_lower = out.lower()
    connected_by_content = any(k in out_lower for k in CONNECTED_STATES)
    connected = (state_norm in CONNECTED_STATES) or connected_by_content
    srch = re.search(r"signal quality\s*:\s*'?(.+?)'?(:?\n|\r|$)", out, re.I)
    if srch:
        signal_raw = srch.group(1).strip()
    else:
        m = re.search(r"(\d+)%", out)
        if m:
            signal_raw = m.group(0)
    md = re.search(r"device\s*:\s*(/\S+)", out, re.I)
    if md:
        device_path = md.group(1).strip()
    dr = re.search(r"drivers?\s*:\s*([^\n\r|]+)", out, re.I)
    if dr:
        driver_from_mmcli = dr.group(1).strip()
    dr2 = re.search(r"driver\s*:\s*([^\n\r|]+)", out, re.I)
    if dr2 and not driver_from_mmcli:
        driver_from_mmcli = dr2.group(1).strip()
    er = re.search(r"error\s*:\s*([^\n\r]+)", out, re.I)
    if er:
        error_txt = er.group(1).strip()
    drivers_list = []
    if driver_from_mmcli and driver_from_mmcli.lower() not in ("unknown", "n/a", ""):
        drivers_list = [d.strip() for d in re.split(r'[,\s]+', driver_from_mmcli) if d.strip()]
    if not drivers_list and device_path:
        drivers_list = get_drivers_for_device(device_path)
    if not drivers_list:
        drivers_list = get_usb_drivers_global()
    _, _, combined_driver_str = classify_drivers(drivers_list)
    m = re.search(r"(\d+)%", signal_raw)
    sig_val = int(m.group(1)) if m else 0
    bars = int(sig_val / 10) if sig_val > 0 else 0
    signal_bar = f"{'▇'*bars}{' '*(10-bars)} {sig_val}%"
    form = detect_form_factor(device_path)
    operator = extract_operator(out)
    error_msg = None if connected else (error_txt or f"Not connecting (state: {state_display})")
    return {
        "model": model,
        "state": state_display,
        "connected": connected,
        "signal": signal_bar,
        "signal_val": sig_val,
        "error": error_msg,
        "drivers_list": drivers_list,
        "driver_display": combined_driver_str,
        "device_path": device_path,
        "form_factor": form,
        "operator": operator
    }


def main():
    wave_index = 0
    step = 0
    info = parse_mmcli()

    live = Live(build_dashboard(info, wave_index, step), refresh_per_second=6, console=console)
    try:
        live.start()
        live_running = True
    except Exception:
        # If start() fails for some reason, continue but mark not running
        live_running = False

    try:
        while True:
            info = parse_mmcli()
            connected = info.get("connected", False)

            # If not connected and not already asking, prepare the prompt state (but do NOT show it inside Live)
            if not connected and not INTERACTIVE_PROMPT["active"] and INTERACTIVE_PROMPT["response"] is None:
                INTERACTIVE_PROMPT["active"] = True
                INTERACTIVE_PROMPT["question"] = "No connection. Start debug? (yes/no):"
                INTERACTIVE_PROMPT["show_response"] = False
                INTERACTIVE_PROMPT["display_in_dashboard"] = False

            # If interactive prompt was activated and we haven't collected a response yet,
            # stop the live renderer (if running), then call console.input() so the user's typing
            # is visible and not overwritten by Live background updates.
            if INTERACTIVE_PROMPT.get("active") and INTERACTIVE_PROMPT.get("response") is None:
                # stop live updates while asking for input so the user's typing remains visible
                if live_running:
                    try:
                        live.stop()
                    except Exception:
                        pass
                    live_running = False

                try:
                    response = console.input(INTERACTIVE_PROMPT.get("question") + " ").strip().lower()
                except KeyboardInterrupt:
                    response = "no"

                INTERACTIVE_PROMPT["response"] = response
                INTERACTIVE_PROMPT["show_response"] = True

            # If we have a response, act on it
            if INTERACTIVE_PROMPT.get("response") in ("yes", "no"):
                resp = INTERACTIVE_PROMPT["response"]
                if resp == "yes":
                    # make sure Live is stopped while we run the debug sequence
                    INTERACTIVE_PROMPT['debugging'] = True
                    if live_running:
                        try:
                            live.stop()
                        except Exception:
                            pass
                        live_running = False

                    console.print("Starting debug sequence...", style="bold yellow")
                    restart = run_debug_sequence(None)
                    INTERACTIVE_PROMPT['debugging'] = False

                    if restart:
                        console.print("Restarting cellview...", style="bold green")
                        # reset prompt state and recreate live
                        INTERACTIVE_PROMPT.update({
                            "active": False, "question": "", "response": None,
                            "show_response": False, "display_in_dashboard": False
                        })
                        wave_index = 0
                        step = 0
                        info = parse_mmcli()
                        # create a fresh Live instance and start it
                        try:
                            live = Live(build_dashboard(info, wave_index, step), refresh_per_second=6, console=console)
                            live.start()
                            live_running = True
                        except Exception:
                            live_running = False
                        continue
                    else:
                        console.print("Not restarting. Exiting.", style="bold red")
                        return
                else:
                    # user said no -> clear prompt and continue monitoring
                    INTERACTIVE_PROMPT.update({
                        "active": False, "question": "", "response": None,
                        "show_response": False, "display_in_dashboard": False
                    })
                    # If Live isn't running, recreate and start it so dashboard continues
                    if not live_running:
                        try:
                            live = Live(build_dashboard(info, wave_index, step), refresh_per_second=6, console=console)
                            live.start()
                            live_running = True
                        except Exception:
                            live_running = False
                    else:
                        # if it was running (unlikely here), refresh immediately to avoid artifacts
                        try:
                            live.update(build_dashboard(info, wave_index, step))
                        except Exception:
                            pass

            # If reconnected, clear prompt state and ensure live is running
            if connected:
                INTERACTIVE_PROMPT.update({
                    "active": False, "question": "", "response": None,
                    "show_response": False, "display_in_dashboard": False
                })
                if not live_running:
                    try:
                        live = Live(build_dashboard(info, wave_index, step), refresh_per_second=6, console=console)
                        live.start()
                        live_running = True
                    except Exception:
                        live_running = False

            wave_index = (wave_index + 1) % len(H_WAVES)
            step += 1

            # Only update dashboard when not in the middle of showing a persistent response or debugging
            if live_running and not INTERACTIVE_PROMPT.get("active") and not INTERACTIVE_PROMPT.get("debugging"):
                try:
                    live.update(build_dashboard(info, wave_index, step))
                except Exception:
                    # fall back if update fails
                    pass

            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if live_running:
                live.stop()
        except Exception:
            pass



if __name__ == "__main__":
    main()
