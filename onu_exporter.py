#!/usr/bin/env python3

import json
import logging
import math
import os
import re
import shlex
import subprocess

try:
    import dotenv
    import requests
    import paho.mqtt.publish as publish
except ImportError as e:
    dotenv = None
    requests = None
    publish = None
    print(f"Missing dependency: {e.name}. Please install it using pip.")
    exit(1)

formatter = logging.Formatter(
    "%(levelname)s [%(module)s:%(lineno)d] > %(message)s",
)
logger = logging.getLogger("onu_exporter")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

dotenv.load_dotenv()

DEBUG: bool = os.getenv("ONU_DEBUG", "false").lower() in ("true", "1", "yes", "y", 1, "on")
ONU_HOST: str = os.getenv("ONU_HOST", "192.168.11.1")
ONU_PORT: int = int(os.getenv("ONU_PORT", 443))
ONU_USER: str = os.getenv("ONU_USER")
ONU_PASS: str = os.getenv("ONU_PASS")

ONU_TEMP_SCALE: str = os.getenv("ONU_TEMP_SCALE", "C").upper()
ONU_MAC: str = ""

MQTT_HOST: str = os.getenv("MQTT_HOST")
MQTT_PORT: int = int(os.getenv("MQTT_PORT", 1883))
MQTT_USER: str = os.getenv("MQTT_USER")
MQTT_PASS: str = os.getenv("MQTT_PASS")
DISCOVERY_PREFIX: str = os.getenv("MQTT_DISCOVERY_PREFIX", "homeassistant")

DEVICE_ID: str = os.getenv("DEVICE_ID", "onu_stick")
DEVICE_NAME: str = os.getenv("DEVICE_NAME", "XGSPON ONU Stick")
DEVICE_MODEL: str = os.getenv("DEVICE_MODEL")
DEVICE_MANUFACTURER: str = os.getenv("DEVICE_MANUFACTURER", "Unknown")
# DEVICE_SW_VERSION: str = os.getenv("DEVICE_SW_VERSION", "8311 [basic] - v2.8.0 (f4e4db3)")
# DEVICE_HW_VERSION: str = os.getenv("DEVICE_HW_VERSION", "1.0 [bfw]")
DEVICE_SW_VERSION: str = ""
DEVICE_HW_VERSION: str = os.getenv("DEVICE_HW_VERSION", "")
ENTITY_PREFIX = DEVICE_ID
ETH_UNIT: str = "Mbit/s"
ONU_PON_SERIAL: str = ""

ENTITY_DEFINITIONS = {
    "temp_cpu0": {"name": "CPU 0", "unit": f"°{ONU_TEMP_SCALE}", "device_class": "temperature", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2},
    "temp_cpu1": {"name": "CPU 1", "unit": f"°{ONU_TEMP_SCALE}", "device_class": "temperature", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2},
    "temp_optic": {"name": "Optical", "unit": f"°{ONU_TEMP_SCALE}", "device_class": "temperature", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2},
    "rx_power": {"name": "RX Power", "unit": "dBm", "device_class": "signal_strength", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2},
    "tx_power": {"name": "TX Power", "unit": "dBm", "device_class": "signal_strength", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2},
    "tx_bias": {"name": "TX Bias", "unit": "mA", "device_class": "current", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2},
    "voltage": {"name": "Module Voltage", "unit": "V", "device_class": "voltage", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2},
    "eth_speed": {"name": "Ethernet Speed", "unit": ETH_UNIT, "device_class": "data_rate", "platform": "sensor", "state_class": "measurement", "icon": "mdi:ethernet", "suggested_display_precision": 0},
    "active_bank": {"name": "Active Firmware Bank", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:memory"},
    "ploam_status": {"name": "PLOAM Status", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:signal"},
    "pon_mode": {"name": "PON Mode", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:network"},
    "mac_address": {"name": "Management MAC Address", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:ethernet-cable"},
    "ip_address": {"name": "Management IP Address", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:ip-network"},
    "cpu_load": {"name": "CPU Load Average", "unit": None, "device_class": None, "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2, "icon": "mdi:cpu-32-bit"},
    "memory_total": {"name": "Memory Total", "unit": "GB", "device_class": "data_size", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2, "icon": "mdi:memory"},
    "memory_used": {"name": "Memory Used", "unit": "GB", "device_class": "data_size", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2, "icon": "mdi:memory"},
    "memory_available": {"name": "Memory Available", "unit": "GB", "device_class": "data_size", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 2, "icon": "mdi:memory"},
    "memory_percent": {"name": "Memory Usage", "unit": "%", "device_class": "power_factor", "platform": "sensor", "state_class": "measurement", "suggested_display_precision": 0, "icon": "mdi:memory"},
    "uptime": {"name": "Uptime", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:clock"},
    "soc_model": {"name": "SoC Model", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:chip"},
    "soc_arch": {"name": "SoC Architecture", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:chip"},
}
session = requests.Session()

def dBm(mw):
    """Converts milliwatts to dBm."""
    if mw is None or mw <= 0:
        return "-inf"
    return f"{10 * math.log10(mw):.2f}"

def temperature(temp_c):
    if temp_c is None:
        return "N/A"
    return f"{temp_c:.2f}" if ONU_TEMP_SCALE == "C" else f"{(temp_c * 9/5) + 32:.2f}"

def pon_state(status_code):
    """Translates PON state code to a human-readable string."""
    states = {
        0: "O0, Power-up state",
        10: "O1, Initial state",
        11: "O1.1, Off-sync state",
        12: "O1.2, Profile learning state",
        20: "O2, Stand-by state",
        23: "O2.3, Serial number state",
        30: "O3, Serial number state",
        40: "O4, Ranging state",
        50: "O5, Operation state",
        51: "O5.1, Associated state",
        52: "O5.2, Pending state",
        60: "O6, Intermittent LOS state",
        70: "O7, Emergency stop state",
        71: "O7.1, Emergency stop off-sync state",
        72: "O7.2, Emergency stop in-sync state",
        81: "O8.1, Downstream tuning off-sync state",
        82: "O8.2, Downstream tuning profile learning state",
        90: "O9, Upstream tuning state",
    }
    return states.get(status_code, f"Unknown ({status_code})")

def request_reboot(token) -> bool:
    """Request a reboot of the ONU device using authenticated GET."""
    reboot_url = f"https://{ONU_HOST}:{ONU_PORT}/cgi-bin/luci/admin/system/reboot"
    session.cookies.set("sysauth", token)
    resp = session.get(reboot_url, verify=False)
    if resp.status_code == 403:
        logger.warning("Auth token expired or invalid")
        return False
    if resp.status_code == 200:
        logger.info("Reboot command sent successfully")
        return True
    else:
        logger.error(f"Failed to send reboot command, status code: {resp.status_code}")
        return False

def parse_temperatures(data, scale):
    logger.debug(f"Temperature scale set to: {scale}")
    pattern = r"([\d.]+)\s*°C\s*\(([\d.]+)\s*°F\)"
    matches = re.findall(pattern, data["temperature"])
    ret = []
    if len(matches) >= 3:
        index = 0 if scale == "C" else 1
        ret.append(float(matches[0][index]))
        ret.append(float(matches[1][index]))
        ret.append(float(matches[2][index]))
    if not ret:
        ret = (None, None, None)
    return tuple(ret)

def get_all_onu_data():
    """
    Fetches all system and GPON metrics from the device in a single SSH session for efficiency.
    """
    ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {ONU_USER}@{ONU_HOST}"

    # A unique delimiter to separate command outputs
    delimiter = "---Boundary-ONU-exporter---"

    # List of all commands to be executed
    commands = [
        "pon psg",                                      # 0: PLOAM Status
        "cat /sys/class/thermal/thermal_zone0/temp",    # 1: CPU0 Temp
        "cat /sys/class/thermal/thermal_zone1/temp",    # 2: CPU1 Temp
        "xxd -p /sys/class/pon_mbox/pon_mbox0/device/eeprom50", # 3: EEPROM 50 Hex
        "xxd -p /sys/class/pon_mbox/pon_mbox0/device/eeprom51", # 4: EEPROM 51 Hex
        "cat /sys/class/net/eth0_0/speed",              # 5: Ethernet Speed
        "uci get gpon.ponip.pon_mode",                  # 6: PON Mode
        ". /lib/8311.sh && get_8311_module_type",       # 7: Module Type
        ". /lib/8311.sh && active_fwbank",              # 8: Active Firmware Bank
        "uptime",                                       # 9: Uptime and Load
        "free -m",                                      # 10: Memory Usage
        "cat /proc/cpuinfo",                            # 11: CPU/SoC Info
        "cat /etc/8311_version",                        # 12: Firmware Version
        ". /lib/8311.sh && get_8311_lct_mac",           # 13: MAC Address
        ". /lib/8311.sh && get_8311_gpon_sn",           # 14: PON Serial Number
    ]

    # Chain commands together with a separator (;) and the delimiter
    chained_command = f"; echo '{delimiter}'; ".join(commands)

    all_data = {}
    try:
        # Execute the single, chained command
        full_output = run_ssh_command(ssh_cmd, chained_command)
        if not full_output:
            raise IOError("No output received from SSH command.")

        # Split the combined output into individual command results
        outputs = full_output.split(delimiter)
        # strip each output or shlex.split() to handle any extra spaces/newlines
        outputs = [output.strip() for output in outputs]

        logger.debug(f"Received {len(outputs)} outputs from SSH command chain\n\n{outputs}\n")

        # ADDED: Check if we received the expected number of outputs for robustness
        if len(outputs) < len(commands):
            logger.error(f"Command chain did not execute as expected. Expected {len(commands)} outputs, got {len(outputs)}.")
            logger.debug(f"Full command output: {full_output}")
            raise ValueError("Mismatch in command output count, aborting parse.")

        # --- Parse GPON Status ---
        ploam_match = re.search(r"current=(\d+)", outputs[0])
        all_data["ploam_status"] = pon_state(int(ploam_match.group(1)) if ploam_match else 0)
        cpu0_temp = (int(outputs[1]) / 1000) if outputs[1].isdigit() else None
        cpu1_temp = (int(outputs[2]) / 1000) if outputs[2].isdigit() else None

        eep50_hex, eep51_hex = outputs[3], outputs[4]
        optic_temp, voltage, tx_bias, tx_mw, rx_mw = None, None, None, None, None
        vendor_name, vendor_pn, vendor_rev = "", "", ""
        if eep50_hex:
            eep50 = bytes.fromhex(eep50_hex.replace('\n', ''))
            vendor_name = eep50[20:36].decode('utf-8', 'ignore').strip()
            vendor_pn = eep50[40:56].decode('utf-8', 'ignore').strip()
            vendor_rev = eep50[56:60].decode('utf-8', 'ignore').strip()
        if eep51_hex:
            eep51 = bytes.fromhex(eep51_hex.replace('\n', ''))
            if len(eep51) >= 106:
                optic_temp = eep51[96] + eep51[97] / 256
                voltage = ((eep51[98] << 8) + eep51[99]) / 10000
                tx_bias = ((eep51[100] << 8) + eep51[101]) / 500
                tx_mw = ((eep51[102] << 8) + eep51[103]) / 10000
                rx_mw = ((eep51[104] << 8) + eep51[105]) / 10000
        all_data["rx_power"] = dBm(rx_mw)
        all_data["tx_power"] = dBm(tx_mw)
        all_data["tx_bias"] = round(tx_bias, 2)
        all_data["temp_cpu0"] = temperature(cpu0_temp)
        all_data["temp_cpu1"] = temperature(cpu1_temp)
        all_data["temp_optic"] = temperature(optic_temp)
        all_data["voltage"] = voltage
        eth_speed = int(outputs[5]) if outputs[5].isdigit() else None
        all_data["eth_speed"] = eth_speed
        all_data["pon_mode"] = (outputs[6] or "xgspon").upper().replace("PON", "-PON")
        module_type = outputs[7] or "bfw"
        all_data["active_bank"] = outputs[8] or "A"

        # --- Parse System Metrics ---
        global ONU_MAC

        all_data["ip_address"] = ONU_HOST
        ONU_MAC = all_data["mac_address"] = outputs[13]
        uptime_output = outputs[9]
        load_match = re.search(r"load average:\s*([\d.]+)", uptime_output)
        all_data["cpu_load"] = float(load_match.group(1)) if load_match else 0.0
        all_data["uptime"] = parse_uptime(uptime_output)

        mem_output = outputs[10]
        mem_match = re.search(r"Mem:\s*(\d+)\s*(\d+)\s*(\d+)", mem_output)
        if mem_match:
            total, used, available = map(float, mem_match.groups())
            all_data["memory_total"] = total / 1024
            all_data["memory_used"] = used / 1024
            all_data["memory_available"] = available / 1024
            all_data["memory_percent"] = (used / total) * 100 if total > 0 else 0.0

        cpuinfo_output = outputs[11]
        system_type_match = re.search(r"system type\s*:\s*(.*)", cpuinfo_output)
        machine_match = re.search(r"machine\s*:\s*(.*)", cpuinfo_output)
        all_data["soc_arch"] = system_type_match.group(1).strip() if system_type_match else "unknown"
        all_data["soc_model"] = machine_match.group(1).strip().rstrip('-SFP-PON') if machine_match else "unknown"

        version_output = outputs[12]
        fw_version = re.search(r"FW_VERSION=(.*)", version_output)
        fw_revision = re.search(r"FW_REVISION=(.*)", version_output)
        fw_variant = re.search(r"FW_VARIANT=(.*)", version_output)

        pon_serial = outputs[14].strip() if outputs[14] else "unknown"
        global DEVICE_MODEL, DEVICE_HW_VERSION, DEVICE_SW_VERSION, ONU_PON_SERIAL

        # all_data["module_info"] = f"{vendor_name} {vendor_pn} {vendor_rev} ({module_type})"

        DEVICE_MODEL = f"{vendor_name} {vendor_pn}"
        DEVICE_HW_VERSION = f"{vendor_rev} [{module_type}]"
        DEVICE_SW_VERSION = f"8311 [{fw_variant.group(1).strip() if fw_variant else 'unknown'}] - {fw_version.group(1).strip() if fw_version else 'unknown'} ({fw_revision.group(1).strip() if fw_revision else 'unknown'})"
        ONU_PON_SERIAL = pon_serial

        return all_data

    except Exception as e:
        logger.exception(f"Failed to get all system data via SSH: {e}")
        return {} # Return empty dict on failure

def parse_uptime(uptime_str):
    """Parse uptime string like 'up 1:27' or 'up 2 days, 4:15' into a human-readable format."""
    try:
        match = re.match(r".*up\s+(((\d+)\s*day[s]?,\s*)?(\d+):(\d{2}))", uptime_str)
        if match:
            days = int(match.group(3)) if match.group(3) else 0
            hours = int(match.group(4))
            minutes = int(match.group(5))
            parts = []
            if days > 0:
                parts.append(f"{days} d")
            if hours > 0:
                parts.append(f"{hours} h")
            if minutes > 0:
                parts.append(f"{minutes} m")
            return ", ".join(parts) or "less than a minute"
        return "unknown"
    except Exception as e:
        logger.error(f"Failed to parse uptime: {e}")
        return "unknown"

def run_ssh_command(ssh_base_cmd, command):
    """Helper to run a command over SSH and return its output."""
    cmd = f"{ssh_base_cmd} '{command}'"
    logger.debug(f"Running SSH command: {cmd}")
    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL, text=True, timeout=10)
        return output.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error(f"Failed to run command '{command}': {e}")
        return None

def publish_sensor(key, value):
    meta = ENTITY_DEFINITIONS[key]
    object_id = f"{ENTITY_PREFIX}_{key}"

    state_topic = f"{DISCOVERY_PREFIX}/sensor/{object_id}/state"
    config_topic = f"{DISCOVERY_PREFIX}/sensor/{object_id}/config"

    payload = {
        "name": meta["name"],
        # Sometimes HASS MQTT integration doesnt respect object and unique id. IDK why.
        "unique_id": object_id,
        "object_id": object_id,
        "state_topic": state_topic,
        "unit_of_measurement": meta["unit"],
        "device_class": meta["device_class"],
        "state_class": meta["state_class"],
        "platform": meta["platform"],
        "force_update": True,
        "device": {
            "identifiers": [DEVICE_ID],
            "name": DEVICE_NAME,
            "manufacturer": DEVICE_MANUFACTURER,
            "model": DEVICE_MODEL,
            "sw_version": DEVICE_SW_VERSION,
            "hw_version": DEVICE_HW_VERSION,
            "connections": [("mac", ONU_MAC)],
            "sn": ONU_PON_SERIAL,
        },
    }
    if "icon" in meta:
        payload["icon"] = meta["icon"]
    if "suggested_display_precision" in meta:
        payload["suggested_display_precision"] = meta["suggested_display_precision"]

    try:
        auth_param = {"username": MQTT_USER, "password": MQTT_PASS}
        logger.debug(f"Publishing config and state for {object_id}: {value}")
        publish.single(config_topic, payload=json.dumps(payload), hostname=MQTT_HOST, port=MQTT_PORT,
                       auth=auth_param, retain=True)
        publish.single(state_topic, payload=str(value), hostname=MQTT_HOST, port=MQTT_PORT,
                       auth=auth_param, retain=True)
    except Exception as e:
        logger.error(f"MQTT publish failed for {key}: {e}")

def main():

    try:
            all_data = get_all_onu_data()
    except Exception as e:
        logger.exception("Script execution failed")
    else:
        for key, val in all_data.items():
            publish_sensor(key, val)
        # logger.info(f"Published MQTT device config and entity states, go to the HASS UI: 'Settings > Devices and services > Devices' and search for '{DEVICE_NAME}'")

if __name__ == "__main__":
    # requests.packages.urllib3.disable_warnings()
    if DEBUG:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled via .env")
    main()