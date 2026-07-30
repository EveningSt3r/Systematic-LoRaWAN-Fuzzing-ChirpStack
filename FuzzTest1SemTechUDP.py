import socket
import json
import base64
import os
import struct
import time
# socket sends UDP packets
# json lets us build JSON structures
# base64 needed to decode lorawan frames in base64
# os generates random bytes
# time is self explanatory

TARGET = ("127.0.0.1", 1700) 
# Creates a tuple of the localhost address and the port that the gateway bridge listens
# Creates a UDP socket
# AF_INET means IPv4 addressing
# SOCK_DGRAM = UDP (SOCK_STREAM is TCP)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# This is needed because of our send_packet and send_raw definitions.

"""
Creates a binary header with a JSON body and sends it over UDP
The header is formatted in x bytes with the semtech udp header usually being 12 bytes
The JSON body of the header is formatted as a dictionary or dict

json.dumps(json_body) as a method converts it from a python dict then to a json string
.encode() converts a string to bytes, then concatenated with the header
Sleep 100 ms between sends


TO TEST: remove sleep to stress test method
"""
def send_packet(header, json_body):
    try:
        payload = header + json.dumps(json_body).encode()
        sock.sendto(payload, TARGET)
        print(f"[SENT] {payload[:80]}...")
        time.sleep(0.1)
    except Exception as e:
        print(f"[ERROR] {e}")

"""
For cases where the full packet is already constructed as raw bytes.
Used when either the header or body cannot be passed through
send_packet's json.dumps() serialization step.
"""

def send_raw(header, raw_body):
    """For cases where the body is already bytes, not a dict"""
    try:
        payload = header + raw_body
        sock.sendto(payload, TARGET)
        print(f"[SENT RAW] header + {raw_body[:40]}")
        time.sleep(0.1)
    except Exception as e:
        print(f"[ERROR] {e}")

"""
This function builds a valid 12 byte semtech udp binary header
Byte 0 = Protocol version (always 0x02 for our purposes)
Bytes 1-2 is a random token used to match ACK responses
Byte 3 = Packet Type 
    0x00 = PUSH_DATA (uplink frame to gateway)
    0x02 = PULL_DATA (gateway asking for downlink)
    0x05 = TX_ACK (gateway downlink confirmation)
Bytes 4-11 is the Gateway_EUI (We have it constant)

Test different gateway ID (todo)
"""
def valid_header(packet_type=0x00):
    token = os.urandom(2) # cryptographically random 2 bytes
    gateway_eui = bytes.fromhex("2e6496d3493d6632") # convert to raw bytes
    return bytes([0x02]) + token + bytes([packet_type]) + gateway_eui


"""
Generate 20 random bytes and base 64 encode them.
b64.encode converts bytes to base 64
.decode converts bytes to a utf-8 string for json

Replace this with a real frame later
"""
def valid_base64_frame(): 
    return base64.b64encode(os.urandom(20)).decode()


# TEST 1: BAD JSON BODY
"""
We send bad json bodies with random headers.
"""
def fuzz_1_malformed_jsonbody():
    print("\n Fuzz Test 1: Malformed Body")
    cases = [
        b'not a json string',
        b'{"rxpk": }',
        b'{"rxpk": null}',
        b'{"rxpk":, []}',
        b'',
        b'null',
        b'[]',
        b'0',
        b'{"rxpk": 0}'
        b'{"rxpk", "rxpk"}'
    ]
    for case in cases:
        send_raw(valid_header(), case)
        # print the sent header and the first 40 bytes of the
        # malformed body
        


"""
datr means data rate. "SP12BW125" would mean spreading factor 12 bandwidth 125 khz for example.
Chirpstack proccesses this with a regex to get
the spreading factor number and bandwidth number separately.
If the regex receives unexpected input it may:
      - Return None and cause a nil pointer dereference
      - Panic on type mismatch
      - Enter catastrophic backtracking (regex DoS)

To test
try unicode characters, emoji, negative numbers embedded in string:
      "SF-1BW-125"
      "SF12BW125; DROP TABLE gateways;"   — SQL injection style
      "\xFF\xFE" * 100                    — invalid UTF-8 bytes
"""
def fuzz_2_datr_field():
    print("\n[FUZZ] Test 2: datr field (regex parsing)")
    cases = [
        "", # empty string
        "SF99BW999999", # overflow int
        "A" * 10000, # extremely long string
        "SF12BW125\x00injection", # null byte 
        None, # null string
        12345, # integer type mismatch
    ]
    for datr in cases:
        body = {
            "rxpk": [{
                "data": valid_base64_frame(),  # random but valid-looking frame
                "freq": 867.1,                 # valid frequency (EU868 band)
                "datr": datr,                  # THIS is what we're fuzzing
                "modu": "LORA",                # modulation type
                "codr": "4/5",                 # coding rate
                "rssi": -60,                   # signal strength
                "lsnr": 7,                     # signal to noise ratio
                "size": 20,                    # frame size in bytes
                "tmst": 1000,                  # timestamp
                "chan": 0,                     # channel number
                "rfch": 0,                     # radio frequency chain
                "stat": 1                      # CRC status (1 = OK)
            }]
        }
        send_packet(valid_header(), body)


""" 
The 'freq' field contains the frequency in MHz eg 867.1
Chirpstack multiplies this by a million to convert to hz
We are testing unidentified values

Check: nan, extremely large float 867.1e308
{"nested": object} tuple or object

"""
def fuzz_3_frequency():
    print("\n[FUZZ] Test 3: freq field (arithmetic overflow)")
    cases = [
        9999999999999999,
        -1,
        0,
        "867.1",
        None,
    ]
    for freq in cases:
        body = {
            "rxpk": [{
                "data": valid_base64_frame(),  # random but valid-looking frame
                "freq": freq,                  # test field
                "datr": "SF12BW125",           # valid datr field
                "modu": "LORA",                # modulation type
                "codr": "4/5",                 # coding rate
                "rssi": -60,                   # signal strength
                "lsnr": 7,                     # signal to noise ratio
                "size": 20,                    # frame size in bytes
                "tmst": 1000,                  # timestamp
                "chan": 0,                     # channel number
                "rfch": 0,                     # radio frequency chain
                "stat": 1                      # CRC status (1 = OK)
            }]
        }
        send_packet(valid_header(), body) 

""" 
Fuzz the 12-byte semtech udp binary header before chirpstack gets to it
The Chirpstack library has a function that reads this header and may crash if it gets unexpected values
before reaching a JSON parsing function

Test: bytes[0xFF...] (invalid packet version should be 0x02)
bytes[...0xAA] (invalid packet type)
packets with 4 bytes, 1 bytes, long zero bytes

Test: EUI types, completely empty, PULL_DATA type with rxpk body, 
PUSH_DATA type with PULL type, etc
"""
def fuzz_4_binary_header():
    print("\n [FUZZ] Test 4: Binary Header corruption")
    gateway_eui = bytes.fromhex("2e6496d3493d6632")

    cases = [
        bytes([0xFF, 0x00, 0x01, 0x02]) + gateway_eui,
        bytes([0x00, 0x01, 0x02, 0xAA]) + gateway_eui,
        bytes([0x02, 0x00, 0x01, 0x00]), # no gateway
        bytes([0x01]),
        bytes(1000),
        # Test None with if header is none sock.sendto(valid_body, TARGET)
    ]
    valid_body = json.dumps({"rxpk": []}).encode()
    for header in cases:
        send_raw(header, valid_body)
        print(f"[SENT] malformed header ({len(header)} bytes) + valid body")
        # time.sleep(0.1)

def fuzz_5_gateway_flood(count=500):
    """
    Sends many packets each claiming to be from a different gateway EUI.
    Chirpstack maintains an in-memory cache of known gateways.
    Each new EUI gets registered as a new entry. If the cache has no
    size limit, flooding with random EUIs could exhaust memory.
    If the cache has cleanup logic, there may be a race condition between
    a packet arriving and its gateway entry being cleaned up.
 
    count=500 means we send 500 packets with 500 different gateway identities.
 
    Test:
      - Increase count to 10000 or 100000 to stress test harder
      - Add a valid LoRaWAN frame in the body to see if flooded gateways
        can successfully deliver frames
      - Measure memory usage of Docker container during flood:
          docker stats chirpstack-chirpstack-gateway-bridge-1
    """
    print(f"\n[FUZZ] Test 5: Gateway EUI flood ({count} random EUIs)")


    valid_body = json.dumps({"rxpk": []}).encode()

    for i in range(count):
        token = os.urandom(2) # random 2-byte token
        fake_eui = os.urandom(8) # random 8-byte gateway EUI, use a different one every time
        # manually build header since valid_header() uses a fixed EUI
        header = bytes([0x02]) + token + bytes([0x00]) + fake_eui
        send_raw(header, valid_body)
        if i % 100 == 0:
            print(f"[SENT] {i}/{count} packets")  # progress indicator every 100
    time.sleep(1)  # wait 1 second after flood to observe effects
 

"""
MHDR is byte 0. 
Bits 1-0 is the major
'unexpected major' error -> What values make it crash?
"""
def fuzz_6_mhdr():
    mhdr_values = [
        0x00, # valid
        0x01, # 1-3 invalid
        0x02,
        0x03,
        0xFF, # all bits set
        0x80, #confirmed data down (invalid)

        # test all the hex values

    ]

    for mhdr in mhdr_values:
        # Build a minimal LoRaWAN frame with specific MHDR byte
        frame = bytearray(20)
        frame[0] = mhdr          # set MHDR to our test value
        frame[1:5] = bytes.fromhex("e11a1800")  # DevAddr (your device)
        # rest stays as zero bytes:
        encoded = base64.b64encode(bytes(frame)).decode()
        body = {
            "rxpk": [{
                "data": encoded,
                "freq": 867.1,
                "datr": "SF12BW125",           # valid datr field
                "modu": "LORA",                # modulation type
                "codr": "4/5",                 # coding rate
                "rssi": -60,                   # signal strength
                "lsnr": 7,                     # signal to noise ratio
                "size": 20,                    # frame size in bytes
                "tmst": 1000,                  # timestamp
                "chan": 0,                     # channel number
                "rfch": 0,                     # radio frequency chain
                "stat": 1                      # CRC status (1 = OK)
                }]
            }
        send_packet(valid_header(), body)
        print(f"[MHDR] Sent MHDR=0x{mhdr:02X}")



# main - run all tests
 
if __name__ == "__main__":
    print("=" * 60)
    print("LoRaWAN Semtech UDP Fuzzer")
    print(f"Target: {TARGET[0]}:{TARGET[1]}")
    print("Watch Docker logs in another terminal:")
    print("docker logs -f chirpstack-docker-chirpstack-gateway-bridge-1")
    print("=" * 60)
 
    # Run each test in sequence
    # Comment out any you don't want to run
    fuzz_1_malformed_jsonbody()
    fuzz_2_datr_field()
    fuzz_3_frequency()
    fuzz_4_binary_header()
    fuzz_5_gateway_flood()
    fuzz_6_mhdr()
 
    print("\n[DONE] All fuzz tests complete.")
    print("Check Docker logs for panics, fatals, or unexpected behavior.")
    print("Run: docker ps  -- to check if any containers restarted.")

    input("\n Press Enter to exit...")
