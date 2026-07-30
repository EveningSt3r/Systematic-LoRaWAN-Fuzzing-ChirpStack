import socket
import json
import base64
import os
import struct
import time


from FuzzTest1SemTechUDP import (
    send_packet,
    send_raw,
    valid_header,
    TARGET,
    sock,
    APP_KEY,
    DEV_EUI,
    JOIN_EUI,
    DEV_ADDR,
    GW_EUI,
)

from statefulFuzzer import (
    run_docker_cmd,
    get_redis_stream_length,
    poll_redis_for_new_entry,
    get_recent_bridge_logs,
    check_logs_for_errors,
    compute_join_request_mic,
    delete_device_session,
    get_device_state,
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
            "description": "No active session exists",
            "substates": {
                "S2a": {
                    "description": "Clear - previously joined, session deleted",
                    "field_config": "no_session_history",
                    "sequence_origin": ["deleted"],
                    "valid_messages": ["JoinRequest"],
                    "invalid_messages": ["DataUp", "RejoinRequest"],
                    "transitions": {},
                },
                "S2b": {
                    "description": "Clear - previously joined, session deleted",
                    "field_config": "no_session_history",
                    "sequence_origin": ["deleted"],
                    "valid_messages": ["JoinRequest"],
                    "invalid_messages": ["DataUp", "RejoinRequest"],
                    "transitions": {},
                },
            },
        },
        "S3": {
            "description": "No active session exists",
            "substates": {
                "S3a": {
                    "description": "Clear - previously joined, session deleted",
                    "field_config": "no_session_history",
                    "sequence_origin": ["deleted"],
                    "valid_messages": ["JoinRequest"],
                    "invalid_messages": ["DataUp", "RejoinRequest"],
                    "transitions": {},
                },
                "S3b": {
                    "description": "Clear - previously joined, session deleted",
                    "field_config": "no_session_history",
                    "sequence_origin": ["deleted"],
                    "valid_messages": ["JoinRequest"],
                    "invalid_messages": ["DataUp", "RejoinRequest"],
                    "transitions": {},
                },
            },
        },
    }
}
