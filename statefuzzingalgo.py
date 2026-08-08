import json
import base64
import os
from datetime import datetime, timezone
import time
import urllib.request
import urllib.error
import re



from FuzzTest1SemTechUDP import (
    send_packet,
    send_raw,
    valid_header
)

from statefulFuzzer import (
    run_docker_cmd,
    get_redis_stream_length,
    poll_redis_for_new_entry,
    compute_join_request_mic,
    delete_device_session,
    get_device_state,
    POSTGRES_CONTAINER,
    DEV_EUI,
    JOIN_EUI,
    GW_EUI,
)


ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*m')
LOG_TS_RE = re.compile(r"^(\S+)")

used_nonces = []
violations = []

API_KEY = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJjaGlycHN0YWNrIiwiaXNzI"
    "joiY2hpcnBzdGFjayIsInN1YiI6IjBlZDhmZGJhLWM5NjktNGJiNi05YzlhLTIxM2U5NjczOTZlMiIsInR5cCI6ImtleSJ9.atuc08Li9FuAMvuil80H8mWCI_99HesBXg0FnfGGEH0"
)

FSM = {
    "states": {
        "S0": {
            "description": "No active session exists",
            "substates": {
                "S0a": {
                    "description": "Fresh - never joined, no DevNonce history",
                    "field_config": "no_session",
                    "sequence_origin": ["none"],
                    "valid_messages": ["JoinRequest"],
                    "invalid_messages": ["DataUp", "RejoinRequest"],
                    "transitions": {
                        "JoinRequest_valid": {
                            "trigger": "JoinRequest",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S1",
                        },
                        "JoinRequest_invalid_mic": {
                            "trigger": "JoinRequest",
                            "mic_state": "invalid",
                            "payload_state": "N/A",
                            "expected_cs_response": "reject",
                            "expected_error": "Invalid MIC",
                            "next_state": "S0",
                        },
                        "JoinRequest_zeroed_mic": {
                            "trigger": "JoinRequest",
                            "mic_state": "zeroed",
                            "payload_state": "N/A",
                            "expected_cs_response": "reject",
                            "expected_error": "Invalid MIC",
                            "next_state": "S0",
                        },
                    },
                },
                "S0b": {
                    "description": "Clear - previously joined, session deleted",
                    "field_config": "no_session_history",
                    "sequence_origin": ["deleted"],
                    "valid_messages": ["JoinRequest"],
                    "invalid_messages": ["DataUp", "RejoinRequest"],
                    "transitions": {
                        "JoinRequest_valid": {
                            "trigger": "JoinRequest",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S1",
                        },
                        "JoinRequest_invalid_mic": {
                            "trigger": "JoinRequest",
                            "mic_state": "invalid",
                            "payload_state": "N/A",
                            "expected_cs_response": "reject",
                            "expected_error": "Invalid MIC",
                            "next_state": "S0",
                        },
                        "JoinRequest_zeroed_mic": {
                            "trigger": "JoinRequest",
                            "mic_state": "zeroed",
                            "payload_state": "N/A",
                            "expected_cs_response": "reject",
                            "expected_error": "Invalid MIC",
                            "next_state": "S0",
                        },
                        "JoinRequest_previously_used_nonce": {
                            "trigger": "JoinRequest",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "reject",
                            "expected_error": "dev-nonce already used",
                            "next_state": "S0",
                        },
                        "JoinRequest_nonce_from_deleted_session": {
                            "trigger": "JoinRequest",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "reject",
                            "expected_error": "dev-nonce already used",
                            "next_state": "S0",
                        },
                        "JoinRequest_valid_new_nonce": {
                            "trigger": "JoinRequest",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S1",
                        },
                    },
                },
            },
        },
        "S1": {
            "description": "JoinRequest accepted by ChirpStack, JoinAccept sent, awaiting first uplink",
            "substates": {
                "S1a": {
                    "description": "Pending join - valid JoinRequest was accepted",
                    "field_config": "join_pending",
                    "sequence_origin": ["normal_join"],
                    "valid_messages": ["JoinRequest"],  # retransmit is valid
                    "invalid_messages": [
                        "DataUp",
                        "RejoinRequest",
                    ],  # no session confirmed yet
                    "transitions": {
                        "JoinRequest_retransmit": {
                            "trigger": "JoinRequest",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S1",  # stays pending
                        },
                        "JoinRequest_duplicate": {
                            "trigger": "JoinRequest",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "reject",
                            "expected_error": "dev-nonce already used",
                            "next_state": "S1",
                        },
                        "DataUp_before_join_confirmed": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "No device-session exists for dev_addr",
                            "next_state": "S1",
                        },
                        "DataUp_zeroed_mic_before_confirmed": {
                            "trigger": "DataUp",
                            "mic_state": "zeroed",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "No device-session exists for dev_addr",
                            "next_state": "S1",
                        },
                    },
                },
            },
        },
        "S2": {
            "description": "Active joined session",
            "substates": {
                "S2a": {
                    "description": "Valid MIC, fresh fcnt",
                    "field_config": "valid_mic_fresh_fcnt",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp", "RejoinRequest"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "DataUp_valid": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "normal",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S2",
                        },
                        "DataUp_invalid_mic": {
                            "trigger": "DataUp",
                            "mic_state": "invalid",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "Invalid MIC",
                            "next_state": "S2",
                        },
                        "DataUp_zeroed_mic": {
                            "trigger": "DataUp",
                            "mic_state": "invalid",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "Invalid MIC",
                            "next_state": "S2",
                        },
                    },
                },
                "S2b": {
                    "description": "Valid MIC Fcnt Frozen",
                    "field_config": "valid_mic_fcnt_frozen",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "DataUp_fcnt_frozen": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "normal",
                            "expected_cs_response": "accept_if_skip_fcnt_check",
                            "expected_error": "UPLINK_F_CNT_RESET",
                            "next_state": "S2",
                        }
                    },
                },
                "S2c": {
                    "description": "Valid MIC Fcnt replayed",
                    "field_config": "valid_mic_fcnt_replayed",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "DataUp_fcnt_frozen": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "normal",
                            "expected_cs_response": "accept_if_skip_fcnt_check",
                            "expected_error": "UPLINK_F_CNT_RETRANSMISSION",
                            "next_state": "S2",
                        }
                    },
                },
                "S2d": {
                    "description": "Valid MIC, fcnt max",
                    "field_config": "valid_mic_fcnt_max",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "DataUp_fcnt_max": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S2",
                        },
                        "DataUp_fcnt_overflow": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "unknown",
                            "expected_error": None,
                            "next_state": "S2",
                        },
                    },
                },
                "S2e": {
                    "description": "Valid MIC, oversized payload",
                    "field_config": "valid_mic_oversized_payload",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp", "RejoinRequest"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "DataUp_oversized": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "oversized",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "expected_downlink_error": "DOWNLINK_PAYLOAD_SIZE",
                            "next_state": "S2",
                        }
                    },
                },
                "S2f": {
                    "description": "Valid MIC, empty payload",
                    "field_config": "valid_mic_empty_payload",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp", "RejoinRequest"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "DataUp_empty_payload_fport_0": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "unknown",
                            "expected_error": None,
                            "next_state": "S2",
                        },
                        "DataUp_empty_payload_fport1": {
                            "trigger": "DataUp",
                            "mic_state": "valid",
                            "payload_state": "N/A",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S2",
                        },
                    },
                },
            },
        },
        "S3": {
            "description": "Rejoin Pending",
            "substates": {
                "S3a": {
                    "description": "Zeroed Mic Rejoin",
                    "field_config": "zeroed_mic_rejoin",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["ReJoinRequest"],
                    "invalid_messages": ["DataUp", "JoinRequest"],
                    "transitions": {
                        "ReJoin_Zero_MIC": {
                            "trigger": "ReJoinRequest",
                            "mic_state": "invalid",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "UPLINK_MIC",
                            "next_state": "S3",
                        }
                    },
                },
                "S3b": {
                    "description": "Old session DataUp during rejoin window",
                    "field_config": "old_session_DataUp",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "ReJoin_Old_Session": {
                            "trigger": "DataUp",
                            "mic_state": "zeroed",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "UPLINK_MIC",
                            "next_state": "S3",
                        }
                    },
                },
                "S3c": {
                    "description": "Duplicate Rejoin Request",
                    "field_config": "duplicate_rejoin_request",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["ReJoinRequest"],
                    "invalid_messages": ["DataUp", "JoinRequest"],
                    "transitions": {
                        "Duplicate_Rejoin": {
                            "trigger": "ReJoinRequest",
                            "mic_state": "zeroed",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "OTAA",
                            "next_state": "S3",
                        }
                    },
                },
                "S3d": {
                    "description": "New session DataUp during rejoin window",
                    "field_config": "new_session_rejoin",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["DataUp"],
                    "invalid_messages": ["JoinRequest"],
                    "transitions": {
                        "New_Session": {
                            "trigger": "DataUp",
                            "mic_state": "zeroed",
                            "payload_state": "normal",
                            "expected_cs_response": "reject",
                            "expected_error": "UPLINK_MIC",
                            "next_state": "S2",
                        }
                    },
                },
            },
        },
    }
}

GLOBAL_INVALIDS = {
    "malformed_json": {
        "description": "Valid Semtech UDP header, broken JSON body",
        "raw_body": b'{"rxpk": }',
        "expected_cs_response": "reject",
        "expected_error": None,  # caught by Gateway Bridge, never reaches ChirpStack
    },
    "empty_body": {
        "description": "Valid Semtech UDP header, empty body",
        "raw_body": b"",
        "expected_cs_response": "reject",
        "expected_error": None,
    },
    "null_body": {
        "description": "Valid Semtech UDP header, null JSON body",
        "raw_body": b"null",
        "expected_cs_response": "reject",
        "expected_error": None,
    },
    "unknown_packet_type": {
        "description": "Invalid Semtech UDP packet type byte 0xAA",
        "raw_body": None,  # None means header itself is malformed
        "header_override": bytes([0x02, 0x00, 0x01, 0xAA]) + bytes.fromhex(GW_EUI),
        "expected_cs_response": "reject",
        "expected_error": None,
    },
    "truncated_header": {
        "description": "Semtech UDP header truncated to 4 bytes, no gateway EUI",
        "raw_body": None,
        "header_override": bytes([0x02, 0x00, 0x01, 0x00]),
        "expected_cs_response": "reject",
        "expected_error": None,
    },
    "invalid_version": {
        "description": "Semtech UDP protocol version byte set to 0xFF",
        "raw_body": None,
        "header_override": bytes([0xFF, 0x00, 0x01, 0x00]) + bytes.fromhex(GW_EUI),
        "expected_cs_response": "reject",
        "expected_error": None,
    },
    "wrong_devaddr": {
        "description": "Valid Semtech UDP, DataUp with unregistered DevAddr",
        "raw_body": None,  # built by run_global_invalids
        "expected_cs_response": "reject",
        "expected_error": "No device-session exists for dev_addr",
    },
    "oversized_semtech": {
        "description": "Semtech UDP JSON body 10000 bytes",
        "raw_body": b'{"rxpk": [{"data": "' + b"A" * 10000 + b'"}]}',
        "expected_cs_response": "reject",
        "expected_error": None,
    },
}


def get_field_definitions(message_type: str, context: dict):  # return list
    """
    Returns field definitions for a given message type.
    context provides current runtime values (devaddr, fcnt etc.)
    Each field has:
      name      - field identifier
      type      - determines which mutations are generated
      value     - current valid value as bytes
      size      - expected byte size (None if variable)
    """

    if message_type == "JoinRequest":
        return [
            {"name": "mhdr", "type": "mhdr_join", "value": bytes([0x00]), "size": 1},
            {
                "name": "join_eui",
                "type": "eui",
                "value": JOIN_EUI[::-1],  # little-endian
                "size": 8,
            },
            {
                "name": "dev_eui",
                "type": "eui",
                "value": DEV_EUI[::-1],  # little-endian
                "size": 8,
            },
            {
                "name": "dev_nonce",
                "type": "nonce",
                "value": os.urandom(2),  # fresh nonce by default
                "size": 2,
            },
            {
                "name": "mic",
                "type": "mic",
                "value": bytes(4),  # will be computed or zeroed
                "size": 4,
            },
        ]

    elif message_type == "DataUp":
        return [
            {
                "name": "mhdr",
                "type": "mhdr_data",
                "value": bytes([0x80]),  # ConfirmedDataUp
                "size": 1,
            },
            {
                "name": "devaddr",
                "type": "devaddr",
                "value": bytes.fromhex(context["current_devaddr"].replace("\\x", "")),
                "size": 4,
            },
            {"name": "fctrl", "type": "fctrl", "value": bytes([0x00]), "size": 1},
            {
                "name": "fcnt",
                "type": "fcnt",
                "value": context["current_fcnt"].to_bytes(2, "little"),
                "size": 2,
            },
            {"name": "fport", "type": "fport", "value": bytes([0x01]), "size": 1},
            {
                "name": "payload",
                "type": "payload",
                "value": bytes.fromhex("aabbccddeeff"),
                "size": None,  # variable
            },
            {
                "name": "mic",
                "type": "mic",
                "value": bytes(4),  # zeroed — limitation documented
                "size": 4,
            },
        ]

    elif message_type == "RejoinRequest":
        return [
            {"name": "mhdr", "type": "mhdr_rejoin", "value": bytes([0xC0]), "size": 1},
            {
                "name": "rejoin_type",
                "type": "rejoin_type",
                "value": bytes([0x00]),
                "size": 1,
            },
            {
                "name": "net_id",
                "type": "fixed",
                "value": bytes([0x00, 0x00, 0x00]),
                "size": 3,
            },
            {"name": "dev_eui", "type": "eui", "value": DEV_EUI[::-1], "size": 8},
            {
                "name": "rjcount0",
                "type": "counter",
                "value": bytes([0x00, 0x00]),
                "size": 2,
            },
            {
                "name": "mic",
                "type": "mic",
                "value": bytes(4),  # zeroed — no JSIntKey available
                "size": 4,
            },
        ]

    else:
        raise ValueError(f"Unknown message type: {message_type}")


def mutate_field(field: dict, context: dict):  # return list
    """
    Generates all mutations for a single field based on its type.
    Returns list of (mutation_name, mutated_value_bytes) tuples.
    MIC field mutations are handled specially since they affect
    the whole frame not just one field.
    """
    ftype = field["type"]
    value = field["value"]
    size = field["size"] if field["size"] else len(value)
    mutations = []

    if ftype == "mhdr_join":
        # MHDR for join — MType bits 7-5, Major bits 1-0
        # defined MType values
        for mtype in [0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0]:
            mutations.append((f"mhdr_mtype_{mtype:#04x}", bytes([mtype])))
        # invalid major bits
        mutations.append(("mhdr_major_01", bytes([0x01])))
        mutations.append(("mhdr_major_10", bytes([0x02])))
        mutations.append(("mhdr_major_11", bytes([0x03])))
        mutations.append(("mhdr_all_ones", bytes([0xFF])))
        mutations.append(("mhdr_zero", bytes([0x00])))

    elif ftype == "mhdr_data":
        # ConfirmedDataUp=0x80, UnconfirmedDataUp=0x40
        # test both valid and invalid MType values
        for mtype in [0x40, 0x80, 0x00, 0x20, 0x60, 0xA0, 0xC0, 0xE0, 0xFF]:
            mutations.append((f"mhdr_mtype_{mtype:#04x}", bytes([mtype])))

    elif ftype == "mhdr_rejoin":
        mutations.append(("mhdr_valid", bytes([0xC0])))
        mutations.append(("mhdr_all_ones", bytes([0xFF])))
        mutations.append(("mhdr_zero", bytes([0x00])))

    elif ftype == "eui":
        # valid, zero, all-ones, random, non-reversed
        mutations.append(("eui_valid", value))
        mutations.append(("eui_zero", bytes(8)))
        mutations.append(("eui_all_ones", bytes([0xFF] * 8)))
        mutations.append(("eui_random", os.urandom(8)))
        mutations.append(("eui_not_reversed", value[::-1]))  # wrong endian

    elif ftype == "nonce":
        mutations.append(("nonce_fresh", os.urandom(2)))
        mutations.append(("nonce_zero", bytes([0x00, 0x00])))
        mutations.append(("nonce_max", bytes([0xFF, 0xFF])))
        # replayed nonce — stored from S0a run
        if context.get("used_nonces"):
            mutations.append(("nonce_replayed", context["used_nonces"][-1]))

    elif ftype == "devaddr":
        mutations.append(("devaddr_valid", value))
        mutations.append(("devaddr_zero", bytes(4)))
        mutations.append(("devaddr_all_ones", bytes([0xFF] * 4)))
        mutations.append(("devaddr_random", os.urandom(4)))
        mutations.append(("devaddr_not_reversed", value[::-1]))

    elif ftype == "fctrl":
        # flip each bit individually — 8 mutations
        for i in range(8):
            mutated = bytearray(value)
            mutated[0] ^= 1 << i
            mutations.append((f"fctrl_bit{i}_flip", bytes(mutated)))
        mutations.append(("fctrl_zero", bytes([0x00])))
        mutations.append(("fctrl_all_ones", bytes([0xFF])))

    elif ftype == "fcnt":
        current = context.get("current_fcnt", 0)
        mutations.append(("fcnt_zero", (0).to_bytes(2, "little")))
        mutations.append(
            ("fcnt_current_minus_1", max(0, current - 1).to_bytes(2, "little"))
        )
        mutations.append(("fcnt_current", current.to_bytes(2, "little")))
        mutations.append(
            ("fcnt_current_plus_1", min(65535, current + 1).to_bytes(2, "little"))
        )
        mutations.append(("fcnt_max", (65535).to_bytes(2, "little")))
        mutations.append(("fcnt_random", os.urandom(2)))

    elif ftype == "fport":
        mutations.append(("fport_0", bytes([0x00])))  # MAC command
        mutations.append(("fport_1", bytes([0x01])))  # normal app
        mutations.append(("fport_224", bytes([0xE0])))  # reserved start
        mutations.append(("fport_255", bytes([0xFF])))  # reserved end
        mutations.append(("fport_max_app", bytes([0xDF])))  # max app port

    elif ftype == "payload":
        mutations.append(("payload_normal", bytes.fromhex("aabbccddeeff")))
        mutations.append(("payload_empty", b""))
        mutations.append(("payload_one_byte", bytes([0x00])))
        mutations.append(("payload_max", os.urandom(51)))  # SF12 limit
        mutations.append(("payload_over_max", os.urandom(100)))  # over limit
        mutations.append(("payload_random", os.urandom(len(value))))

    elif ftype == "mic":
        # MIC mutations affect the last 4 bytes of the assembled frame
        # handled in build_frame, not here
        # return placeholder tuples that build_frame interprets
        mutations.append(("mic_zeroed", bytes(4)))
        mutations.append(("mic_all_ones", bytes([0xFF] * 4)))
        mutations.append(("mic_bit_flip", bytes([0xFF, 0x00, 0xFF, 0x00])))
        mutations.append(("mic_valid", None))  # None = compute real MIC

    elif ftype in ("fixed", "counter", "rejoin_type"):
        mutations.append(("value_valid", value))
        mutations.append(("value_zero", bytes(size)))
        mutations.append(("value_all_ones", bytes([0xFF] * size)))
        mutations.append(("value_random", os.urandom(size)))

    return mutations


def build_frame(message_type: str, field_overrides: dict, context: dict) -> bytes:

    fields = get_field_definitions(message_type, context)
    # get field definitions for message type

    # apply field overrides where notable
    for field in fields:
        if field["name"] in field_overrides:
            field["value"] = field_overrides[field["name"]]

    frame = bytes()
    mic_value = None
    # concatenate all field values except MIC which needs computing
    field_values = {}  # ← add this to track field values by name

    for field in fields:
        if field["name"] == "mic":
            mic_value = field["value"]
        else:
            frame += field["value"]
            field_values[field["name"]] = field["value"]  # ← store each field value

    # if mic_value is None it means compute a real MIC (JoinRequest only)
    # otherwise append whatever mic_value is (zeroed, all-ones, bit-flip)

    if mic_value is None and message_type == "JoinRequest":
        mhdr = field_values["mhdr"]
        dev_nonce = field_values["dev_nonce"]
        mic_value = compute_join_request_mic(mhdr, JOIN_EUI, DEV_EUI, dev_nonce)
        frame += mic_value
    else:
        if mic_value is None:
            mic_value = bytes(4)

        frame += mic_value

    return frame


def wrap_in_semtech_udp_json(frame, size):  # return dict
    body = {
        "rxpk": [
            {
                "data": base64.b64encode(frame).decode(),
                "freq": 867.1,
                "datr": "SF12BW125",  # valid datr field
                "modu": "LORA",  # modulation type
                "codr": "4/5",  # coding rate
                "rssi": -60,  # signal strength
                "lsnr": 7,  # signal to noise ratio
                "size": size,  # frame size in bytes
                "tmst": 1000,  # timestamp
                "chan": 0,  # channel number
                "rfch": 0,  # radio frequency chain
                "stat": 1,  # CRC status (1 = OK)
            }
        ]
    }
    return body


def get_device_state_parsed() -> dict:
    stdout, _ = run_docker_cmd(
        [
            "docker",
            "exec",
            POSTGRES_CONTAINER,
            "psql",
            "-U",
            "chirpstack",
            "--csv",  # output as CSV
            "--tuples-only",  # no header row
            "-c",
            f"SELECT dev_addr, f_cnt_up, skip_fcnt_check, "  # noqa: ISC004
            f"CASE WHEN device_session IS NULL THEN 'false' "
            f"ELSE 'true' END as session_exists "
            f"FROM device WHERE dev_eui = '\\x{DEV_EUI.hex()}';",
        ]
    )
    # \x00a7516c,0,2026-07-05 08:23:59.722569+00,t,true
    if not stdout.strip():
        return {}
    parts = stdout.strip().split(",")
    return {
        "current_devaddr": parts[0].strip().replace("\\x", ""),
        "current_fcnt": int(parts[1].strip()),
        "skip_fcnt_check": parts[2].strip() == "t",
        "session_exists": parts[3].strip() == "true",
    }


def get_current_context(used_nonces=None) -> dict:
    """
    Queries Postgres and Redis for current system state.
    Returns: current_devaddr, current_fcnt, session_exists,
             skip_fcnt_check, redis_gw_length, redis_dev_length
    """
    db = get_device_state_parsed()
    return {
        "current_devaddr": db.get("current_devaddr", ""),
        "current_fcnt": db.get("current_fcnt", 0),
        "session_exists": db.get("session_exists", False),
        "skip_fcnt_check": db.get("skip_fcnt_check", False),
        "redis_gw_length": get_redis_stream_length("gw:stream:frame"),
        "redis_dev_length": get_redis_stream_length("device:stream:frame"),
        "used_nonces": used_nonces or [],
        "last_join_nonce": None,
    }


def check_oracle(transition: dict, context_before: dict, timestamp) -> dict:
    """
    Checks all four oracle points after a frame is sent.
    Returns result dict containing:
      redis_oracle: bool (new entry appeared or not)
      log_oracle: str or None (error string found in logs)
      postgres_oracle: dict (state change detected or not)
      fsm_oracle: bool (next_state matches actual state)
      oracle_violation: bool (any deviation from expected)
      violation_category: str or None
        "unexpected_acceptance"
        "unexpected_rejection"
        "invalid_state_response"
        Queries Postgres and Redis for current system state.
            Returns: current_devaddr, current_fcnt, session_exists,
            skip_fcnt_check, redis_gw_length, redis_dev_length
    """

    # time stamp for log purposes

    log_lines = get_log_lines_after(timestamp)

    # expected error check in cs logs
    expected_error = transition.get("expected_error")
    log_error_found = None
    if expected_error:
        for line in log_lines:
            if expected_error in line:
                log_error_found = expected_error
                break

    # log context devaddr fcnt session etc
    context_after = get_current_context(context_before.get("used_nonces", []))

    # poll for postgres entry
    postgres_changed = (
        context_after["session_exists"] != context_before["session_exists"]
        or context_after["current_devaddr"] != context_before["current_devaddr"]
    )
    expected_next = transition.get("next_state")
    # s0 no session s1 session just created s2 session exists s3 session exists
    if expected_next == "S0":
        fsm_match = not context_after["session_exists"]
    elif expected_next in ("S1", "S2", "S3"):
        fsm_match = context_after["session_exists"]
    else:
        fsm_match = True

    # poll for redis entry
    redis_new_entry = poll_redis_for_new_entry(
        "gw:stream:frame", context_before["redis_gw_length"], timeout=3
    )

    # document acceptances and rejects
    expected_cs_response = transition.get("expected_cs_response")
    if redis_new_entry:
        actual_response = "accept"
    else:
        actual_response = "reject"

    if expected_cs_response == "accept_if_skip_fcnt_check":
        expected_cs_response = "accept" if context_before["skip_fcnt_check"] else "reject"

    oracle_violation = False
    violation_category = None

    if expected_cs_response == "accept" and actual_response == "reject":
        oracle_violation = True
        violation_category = "unexpected_rejection"
    elif expected_cs_response == "reject" and actual_response == "accept":
        oracle_violation = True
        violation_category = "unexpected_acceptance"

    elif expected_cs_response == "accept" and transition.get("expected_downlink_error"):
        downlink_error_found = any(
            transition["expected_downlink_error"] in line for line in log_lines
        )

        if downlink_error_found:
            oracle_violation = True
            violation_category = "invalid_state_response"

    elif not fsm_match:
        oracle_violation = True
        violation_category = "invalid_state_response"

    return {
        "redis_oracle": redis_new_entry,
        "actual_response": actual_response,
        "expected_cs_response": expected_cs_response,
        "log_error_found": log_error_found,
        "expected_error": expected_error,
        "postgres_changed": postgres_changed,
        "fsm_match": fsm_match,
        "oracle_violation": oracle_violation,
        "violation_category": violation_category,
        "context_after": context_after,
    }


def get_recent_chirpstack_logs(lines=50) -> str:
    stdout, _ = run_docker_cmd(
        ["docker", "logs", "--tail", str(lines), "chirpstack-docker-chirpstack-1"]
    )
    return stdout


def get_log_lines_after(timestamp: str) -> list[str]:
    """
    Returns ChirpStack log lines that appeared after timestamp.
    Used by check_oracle to isolate logs from current test.
    """

    cutoff = datetime.fromisoformat(timestamp)

    logs = get_recent_chirpstack_logs(20)
    # filtered dict
    filtered = []
    for line in logs.splitlines():
        clean_line = ANSI_ESCAPE_RE.sub("", line)
        m = LOG_TS_RE.match(clean_line)  # match date regex to first word
        if not m:
            continue

        ts = m.group(1)

        if ts.endswith("Z"):
            ts = ts[:-1] + "00:00"  # add timestamp

        if "." in ts:  # filter nanosecond
            head, rest = ts.split(".", 1)
            frac = rest[:6]
            tz = rest[rest.find("+") :] if "+" in rest else ""
            ts = f"{head}.{frac}{tz}"

        try:
            log_time = datetime.fromisoformat(ts)
        except ValueError:
            continue  # skip lines that still don't parse

        if log_time.tzinfo is None:
            log_time = log_time.replace(tzinfo=timezone.utc)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)

        if log_time > cutoff:
            filtered.append(clean_line)  # append clean line not original

    return filtered


# -----


def run_global_invalids(substate: str, context: dict):
    """
    Sends every global invalid message while in current substate.
    Checks oracle after each send.
    Prints result.
    """

    wrong_devaddr_frame = bytearray(19)
    wrong_devaddr_frame[0] = 0x80
    wrong_devaddr_frame[1:5] = bytes([0x00, 0x00, 0x00, 0x00])  # unregistered DevAddr
    wrong_devaddr_frame[5] = 0x00
    wrong_devaddr_frame[6:8] = bytes([0x00, 0x00])
    wrong_devaddr_frame[8] = 0x01
    wrong_devaddr_frame[9:15] = bytes.fromhex("aabbccddeeff")
    wrong_devaddr_frame[15:19] = bytes([0x00, 0x00, 0x00, 0x00])
    # iterate for invalid class then name
    for invalid_name, invalid in GLOBAL_INVALIDS.items():
        timestamp = datetime.now(timezone.utc).isoformat()
        # if header override send with that
        # if raw body, send with valid header and raw body
        if invalid.get("header_override"):
            valid_body = json.dumps({"rxpk": []}).encode()
            send_raw(invalid["header_override"], valid_body)
        elif invalid.get("raw_body") is not None:
            send_raw(valid_header(), invalid["raw_body"])

        if invalid_name == "wrong_devaddr":
            body = wrap_in_semtech_udp_json(bytes(wrong_devaddr_frame), len(wrong_devaddr_frame))
            send_packet(valid_header(), body)

        time.sleep(0.5)
        # transition proxy is the dict used to store oracle results
        transitionproxy = {
            "expected_cs_response": invalid["expected_cs_response"],
            "expected_error": invalid["expected_error"],
            "next_state": None,
        }
        oracle = check_oracle(transitionproxy, context, timestamp)
        status = (
            "VIOLATION:" + oracle["violation_category"]
            if oracle["oracle_violation"]
            else "MATCH"
        )
        # print frame literals
        print(
            f"[{substate}][GLOBAL_INVALID][{invalid_name}] "
            f"EXPECTED:{invalid['expected_cs_response']} "
            f"ACTUAL:{oracle['actual_response']} {status}"
        )


def run_transition(
    transition_name: str, transition: dict, context: dict, substate_name: str
):
    """
    Runs all field mutations for a single transition.
    For each mutation: builds frame, sends, checks oracle, prints.
    """
    fields = get_field_definitions(transition["trigger"], context)
    # get field definitions for transition ("DataUp" not "DataUp_invalid")
    for field in fields:
        # for key-value pair in dict
        for mutation_name, mutated_value in mutate_field(field, context):
            timestamp = datetime.now(timezone.utc).isoformat()
            # send frame with mutation
            frame = build_frame(transition["trigger"], {field["name"]: mutated_value}, context)
            body = wrap_in_semtech_udp_json(frame, len(frame))
            send_packet(valid_header(), body)
            time.sleep(0.5)
            oracle = check_oracle(transition, context, timestamp)
            # document violation if necesasry
            status = (
                "VIOLATION:" + oracle["violation_category"]
                if oracle["oracle_violation"]
                else "MATCH"
            )
            print(
                f"[{substate_name}][{transition_name}]"
                f"[{field['name']}:{mutation_name}] "
                f"EXPECTED:{oracle['expected_cs_response']} "
                f"ACTUAL:{oracle['actual_response']} {status}"
            )
            # document violation in global dict for processing
            if oracle["oracle_violation"]:
                violations.append(
                    {
                        "state": substate_name,
                        "transition": transition_name,
                        "field": field["name"],
                        "mutation": mutation_name,
                        "category": oracle["violation_category"],
                        "expected": oracle["expected_cs_response"],
                        "actual": oracle["actual_response"],
                    }
                )

        # check oracle
        # print results

    return 0


def run_substate(state_name: str, substate_name: str, substate: dict, context: dict):
    """
    Runs all transitions and global invalids for a single substate.
    """
    print(f"\n[RUN] {state_name}/{substate_name}")
    run_global_invalids(substate_name, context)
    for transition_name, transition in substate["transitions"].items():
        run_transition(transition_name, transition, context, substate_name)


def run_fsm():
    """
    Top-level loop. Iterates all states and substates in order.
    Calls navigate_to_substate then run_substate for each.
    Prints summary at end.
    """
    context_dict = get_current_context()
    for state_name, state in FSM["states"].items():
        for substate_name, substate in state["substates"].items():
            context_dict = navigate_to_substate(state_name, substate_name, context_dict)
            run_substate(state_name, substate_name, substate, context_dict)

    print("\n" + "=" * 60)
    print(f"FSM FUZZING COMPLETE")
    print(f"Total violations: {len(violations)}")
    for v in violations:
        print(
            f"  [{v['state']}][{v['transition']}][{v['field']}:{v['mutation']}] "
            f"{v['category'].upper()}"
        )
    print("=" * 60)


def send_valid_join(context: dict) -> bytes:
    """
    Sends a valid JoinRequest and returns the nonce used.
    Caller is responsible for updating used_nonces.
    """
    mhdr = bytes([0x00])
    join_eui_le = JOIN_EUI[::-1]
    dev_eui_le = DEV_EUI[::-1]
    dev_nonce = os.urandom(2)
    mic = compute_join_request_mic(mhdr, JOIN_EUI, DEV_EUI, dev_nonce)
    frame = mhdr + join_eui_le + dev_eui_le + dev_nonce + mic
    body = wrap_in_semtech_udp_json(frame, len(frame))
    send_packet(valid_header(), body)
    return dev_nonce


def navigate_to_substate(state: str, substate: str, context: dict) -> dict:
    """
        Navigates ChirpStack into the required substate.
        Returns updated context after navigation.
    """
    print(f"\n[NAV] Navigating to {state}/{substate}")

    if state == "S0":
        if substate == "S0a":
            delete_device_session()
            flush_device_nonces()
            # delete session flush device then navigate
            context = get_current_context(context.get("used_nonces", []))

        elif substate == "S0b":
            delete_device_session()
            context = get_current_context(context.get("used_nonces", []))
            # delete session then navigate

    elif state == "S1":
        if substate == "S1a":
            delete_device_session()
            nonce = send_valid_join(context)
            used_nonces.append(nonce)  # update global
            context["last_join_nonce"] = nonce
            time.sleep(2)
            context = get_current_context(context.get("used_nonces", []))
            if not context["session_exists"]:
                print("[NAV ERROR] Failed to reach S1a — join not accepted")
                return context

    elif state == "S2":
        delete_device_session()
        flush_device_nonces()
        nonce = send_valid_join(context)
        used_nonces.append(nonce)  # update global
        context["last_join_nonce"] = nonce
        time.sleep(2)
        context = get_current_context(context.get("used_nonces", []))
        if not context["session_exists"]:
                        print("[NAV ERROR] Failed to reach S2 — join not accepted")
                        return context
        # all S2 substates arrive the same way
        # delete, joinreq, sleep 2

    elif state == "S3":
        # navigate to s2, all s3 needs to be in s2 first
        delete_device_session()
        flush_device_nonces()
        nonce = send_valid_join(context)
        used_nonces.append(nonce)  # update global
        context["last_join_nonce"] = nonce
        time.sleep(2)
        context = get_current_context(context.get("used_nonces", []))
        if not context["session_exists"]:
                        print("[NAV ERROR] Failed to reach S3 — join not accepted")
                        return context

        # rejoin request zeroed mic sleep 2
        frame = build_frame("RejoinRequest", {}, context)
        body = wrap_in_semtech_udp_json(frame, len(frame))
        send_packet(valid_header(), body)
        time.sleep(2)
        context = get_current_context(context.get("used_nonces", []))
        if not context["session_exists"]:
            print("[NAV ERROR] Session destroyed after RejoinRequest — unexpected")
            return context

    return get_current_context(context.get("used_nonces", []))


def flush_device_nonces():
    """
    Flushes DevNonce history directly via PostgreSQL.
    Fallback if REST API endpoint is unavailable.
    """
    stdout, stderr = run_docker_cmd([
        "docker", "exec", POSTGRES_CONTAINER,
        "psql", "-U", "chirpstack", "-c",
        f"DELETE FROM device_keys WHERE dev_eui = '\\x{DEV_EUI.hex()}';"
    ])
    if "DELETE" in stdout:
        print("[NONCE] DevNonce history flushed via SQL")
    else:
        print(f"[NONCE ERROR] {stderr}")



if __name__ == "__main__":

    try:
        context = get_current_context()
        for state_name in ["S2", "S3"]:
            for substate_name, substate in FSM["states"][state_name]["substates"].items():
                context = navigate_to_substate(state_name, substate_name, context)
                run_substate(state_name, substate_name, substate, context)
        print(f"\nTotal violations: {len(violations)}")
        for v in violations:
            print(f"  [{v['state']}][{v['transition']}][{v['field']}:{v['mutation']}] "
                  f"{v['category'].upper()}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\nViolations before crash: {len(violations)}")
        for v in violations:
            print(f"  [{v['state']}][{v['transition']}][{v['field']}:{v['mutation']}] "
                  f"{v['category'].upper()}")
        input("\nPress Enter to exit...")

    # powercfg /change standby-timeout-ac 0
    # python -u statefuzzingalgo.py > fuzzing_results.txt 2>&1
    # powershell Get-Content fuzzing_results.txt -Wait


    # try:
    #     run_fsm()
    # except Exception as e:
    #     import traceback
    #     print(f"\n[CRASH] {e}")
    #     traceback.print_exc()
    #     print(f"\nViolations found before crash: {len(violations)}")
    #     for v in violations:
    #         print(f"  [{v['state']}][{v['transition']}][{v['field']}:{v['mutation']}] "
    #               f"{v['category'].upper()}")

    # input("\n Press Enter to exit...")