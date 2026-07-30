import socket
import threading
# import os
import json
import base64

LISTEN_PORT = 1701        # simulator sends here
FORWARD_HOST = "127.0.0.1"
FORWARD_PORT = 1700       # chirpstack gateway bridge

listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listen_sock.bind(("0.0.0.0", LISTEN_PORT))

forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
forward_sock.bind(("0.0.0.0", 1702))  # bind so Windows can receive downlinks

print(f"[*] Intercepting UDP on port {LISTEN_PORT} → {FORWARD_PORT}")


    # Modify the packet here before forwarding.
    # data is raw Semtech UDP bytes.
    # Semtech UDP frame structure:
    #   Byte 0:       Protocol version (0x02)
    #   Bytes 1-2:    Random token
    #   Byte 3:       Packet type
    #                 0x00 = PUSH_DATA (uplink, this is what you want)
    #                 0x02 = PULL_DATA
    #                 0x05 = TX_ACK
    #   Bytes 4-11:   Gateway EUI (only in PUSH_DATA)
    #   Bytes 12+:    JSON payload (contains the actual LoRaWAN frame)


def mutate_packet(data: bytes) -> bytes:
    if len(data) < 12:
        return data

    packet_type = data[3]

    if packet_type == 0x00:
        header = data[:12]
        json_bytes = data[12:]

        try:
            packet_json = json.loads(json_bytes.decode("utf-8"))
            print(f"\n[INTERCEPTED] JSON: {packet_json}")

            if "rxpk" in packet_json:
                for rxpk in packet_json["rxpk"]:
                    if "data" in rxpk:
                        
                        # Decode the base64 LoRaWAN frame
                        frame = bytearray(base64.b64decode(rxpk["data"]))
                        print(f"[FRAME BYTES] {frame.hex()}")

                        # LoRaWAN frame structure:
                        # Byte 0:     MHDR
                        # Bytes 1-4:  DevAddr
                        # Byte 5:     FCtrl
                        # Bytes 6-7:  FCnt
                        # Bytes 8+:   FPort + FRMPayload
                        # Last 4:     MIC

                        # Flip a byte in the middle of FRMPayload

                        frame = bytearray(base64.b64decode(rxpk["data"]))
                        print(f"[ORIGINAL FRAME] {frame.hex()}")
                        
                        if len(frame) > 13:
                            target = len(frame) // 2  # middle byte
                            original = frame[target]
                            frame[target] ^= 0xFF
                            print(f"[MUTATED] Byte {target}: {original:#04x} → {frame[target]:#04x}")

                        # Re-encode and put back
                        rxpk["data"] = base64.b64encode(bytes(frame)).decode("utf-8")

            # Rebuild packet
            new_json = json.dumps(packet_json).encode("utf-8")
            data = header + new_json
            print(f"[FORWARDED] Modified frame sent")

        except Exception as e:
            print(f"[ERROR] Could not parse packet: {e}")

    return data

# Track simulator address for routing downlinks back
simulator_addr = None



def forward_uplinks():
    global simulator_addr
    while True:
        data, addr = listen_sock.recvfrom(4096)
        simulator_addr = addr
        data = mutate_packet(data)
        forward_sock.sendto(data, (FORWARD_HOST, FORWARD_PORT))

def forward_downlinks():
    while True:
        data, _ = forward_sock.recvfrom(4096)
        if simulator_addr:
            listen_sock.sendto(data, simulator_addr)

# Run both directions concurrently
threading.Thread(target=forward_uplinks, daemon=True).start()
threading.Thread(target=forward_downlinks, daemon=True).start()

# Keep alive
threading.Event().wait()