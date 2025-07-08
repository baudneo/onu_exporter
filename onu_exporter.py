#!/usr/bin/env python3

import json
import logging
import os
import re
import shlex
import subprocess

try:
    import dotenv
    import requests
    import paho.mqtt.publish as publish
except ImportError as e:
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

DEBUG = os.getenv("ONU_DEBUG", "false").lower() in ("true", "1", "yes", "y", 1, "on")
ONU_HOST = os.getenv("ONU_HOST", "192.168.11.1")
ONU_PORT = int(os.getenv("ONU_PORT", 443))
ONU_USER = os.getenv("ONU_USER")
ONU_PASS = os.getenv("ONU_PASS")

MQTT_HOST = os.getenv("MQTT_HOST")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_USER = os.getenv("MQTT_USER")
MQTT_PASS = os.getenv("MQTT_PASS")
DISCOVERY_PREFIX = os.getenv("MQTT_DISCOVERY_PREFIX", "homeassistant")

DEVICE_ID = os.getenv("DEVICE_ID", "onu_stick")
DEVICE_NAME = os.getenv("DEVICE_NAME", "XGSPON ONU Stick")
DEVICE_MODEL = os.getenv("DEVICE_MODEL")
DEVICE_MANUFACTURER = os.getenv("DEVICE_MANUFACTURER", "Unknown")
DEVICE_SW_VERSION = os.getenv("DEVICE_SW_VERSION", "8311 [basic] - v2.8.0 (f4e4db3)")
DEVICE_HW_VERSION = os.getenv("DEVICE_HW_VERSION", "1.0 [bfw]")

ONU_MAC = ""
ENTITY_PREFIX = DEVICE_ID

ENTITY_DEFINITIONS = {
    "temp_cpu0": {"name": "CPU 0", "unit": "°C", "device_class": "temperature", "platform": "sensor", "state_class": "measurement"},
    "temp_cpu1": {"name": "CPU 1", "unit": "°C", "device_class": "temperature", "platform": "sensor", "state_class": "measurement"},
    "temp_optic": {"name": "Optical", "unit": "°C", "device_class": "temperature", "platform": "sensor", "state_class": "measurement"},
    "rx_power": {"name": "RX Power", "unit": "dBm", "device_class": "signal_strength", "platform": "sensor", "state_class": "measurement"},
    "tx_power": {"name": "TX Power", "unit": "dBm", "device_class": "signal_strength", "platform": "sensor", "state_class": "measurement"},
    "tx_bias": {"name": "TX Bias", "unit": "mA", "device_class": "current", "platform": "sensor", "state_class": "measurement"},
    "voltage": {"name": "Module Voltage", "unit": "V", "device_class": "voltage", "platform": "sensor", "state_class": "measurement"},
    "eth_speed": {"name": "Ethernet Speed", "unit": "Mbit/s", "device_class": "data_rate", "platform": "sensor", "state_class": "measurement", "icon": "mdi:ethernet"},

    "active_bank": {"name": "Active Firmware Bank", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:memory"},
    "status": {"name": "PON PLOAM Status", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:signal"},
    "pon_mode": {"name": "PON Mode", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:network"},
    "mac": {"name": "Management MAC Address", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:ethernet-cable"},
    "ip": {"name": "Management IP Address", "unit": None, "device_class": None, "platform": "text", "state_class": None, "icon": "mdi:ip-network"},
}

session = requests.Session()


def get_token():
    login_url = f"https://{ONU_HOST}:{ONU_PORT}/cgi-bin/luci/"
    payload = {"luci_username": ONU_USER, "luci_password": ONU_PASS}
    session.post(login_url, data=payload, verify=False, allow_redirects=False)
    cookies = session.cookies.get_dict()
    token = cookies.get("sysauth")
    if not token:
        raise Exception("No sysauth token received")
    logger.info("Authenticated with ONU device")
    return token


def get_data(token):
    status_url = f"https://{ONU_HOST}:{ONU_PORT}/cgi-bin/luci/admin/8311/gpon_status"
    session.cookies.set("sysauth", token)
    resp = session.get(status_url, verify=False)
    if resp.status_code == 403:
        logger.warning("Auth token expired or invalid")
        return None
    resp.raise_for_status()
    return resp.json()


def parse_metrics(data):
    global DEVICE_MODEL

    values = {}
    try:
        t_match = re.findall(r"([\d.]+)\s*°C\s*\([\d.]+\s*°F\)", data["temperature"])
        if len(t_match) >= 3:
            values["temp_cpu0"] = float(t_match[0])
            values["temp_cpu1"] = float(t_match[1])
            values["temp_optic"] = float(t_match[2])

        p_match = re.match(r"(-?\d+\.\d+)\s*dBm\s*/\s*(-?\d+\.\d+)\s*dBm\s*/\s*(\d+\.\d+)\s*mA", data["power"])
        if p_match:
            values["rx_power"] = float(p_match.group(1))
            values["tx_power"] = float(p_match.group(2))
            values["tx_bias"] = float(p_match.group(3))

        v_match = re.match(r"(-?\d+(\.\d+)?)\s*V", data["voltage"])
        if v_match:
            values["voltage"] = float(v_match.group(1))
        eth_speed_match = re.match(r"(\d+)\s*Mbps", data["eth_speed"])
        if eth_speed_match:
            values["eth_speed"] = int(eth_speed_match.group(1))
        values["active_bank"] = data["active_bank"].strip()
        values["status"] = data["status"].strip()
        values["pon_mode"] = data["pon_mode"].strip()
        values["mac"] = ONU_MAC
        values["ip"] = ONU_HOST
        if "module_info" in data and data["module_info"]:
            mod_inf = data["module_info"].strip()
            if not DEVICE_MODEL:
                logger.info(f"Setting DEVICE_MODEL from 'module_info': {mod_inf}")
                DEVICE_MODEL = str(mod_inf)
            else:
                logger.info(f"'module_info' found but DEVICE_MODEL already set: {DEVICE_MODEL}, unset DEVICE_MODEL to instead use the 'module_info' value ({mod_inf})")
            del mod_inf
    except Exception as e:
        logger.exception("Failed to parse metrics")
    return values


def get_eth_mac():
    try:
        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {ONU_USER}@{ONU_HOST} 'ip -json addr'"
        logger.debug(f"Running SSH command: {ssh_cmd}")
        output = subprocess.check_output(shlex.split(ssh_cmd), stderr=subprocess.DEVNULL, text=True)
        data = json.loads(output)

        for iface in data:
            if iface.get("addr_info"):
                for addr in iface["addr_info"]:
                    if addr.get("family") == "inet" and addr.get("local") == ONU_HOST:
                        mac = iface.get("address")
                        logger.info(f"Found ONU interface: '{iface['ifname']}' with MAC: {mac} for IP: {ONU_HOST}")
                        return mac
    except Exception as e:
        logger.exception(f"Failed to get MAC address via SSH: {e}")
    return None


def publish_sensor(key, value):
    meta = ENTITY_DEFINITIONS[key]
    object_id = f"{ENTITY_PREFIX}_{key}"

    state_topic = f"{DISCOVERY_PREFIX}/sensor/{object_id}/state"
    config_topic = f"{DISCOVERY_PREFIX}/sensor/{object_id}/config"

    payload = {
        "name": meta["name"],
        "unique_id": object_id,
        "state_topic": state_topic,
        "unit_of_measurement": meta["unit"],
        "device_class": meta["device_class"],
        "state_class": meta["state_class"],
        "platform": meta["platform"],
        "device": {
            "identifiers": [DEVICE_ID],
            "name": DEVICE_NAME,
            "manufacturer": DEVICE_MANUFACTURER,
            "model": DEVICE_MODEL,
            # "model_id": "TEST MODEL ID", #  <--- DEVICE_MODEL (model_id) for model string
            "sw_version": DEVICE_SW_VERSION,
            "hw_version": DEVICE_HW_VERSION,
        },
    }
    if "icon" in meta:
        payload["icon"] = meta["icon"]
    if meta["platform"] == "sensor":
        payload["suggested_display_precision"] = 2
    if ONU_MAC:
        payload["device"]["connections"] = [("mac", ONU_MAC)]

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
    global ONU_MAC

    try:
        token = get_token()
        data = get_data(token)
        if data:
            ONU_MAC = get_eth_mac()
            values = parse_metrics(data)
            for key, val in values.items():
                publish_sensor(key, val)
    except Exception as e:
        logger.exception("Script execution failed")
    else:
        logger.info(f"Published MQTT device config and entity states, go to the HASS UI: 'Settings > Devices and services > Devices' and search for '{DEVICE_NAME}'")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    if DEBUG:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled via .env")
    main()