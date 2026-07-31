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
                            "mic_state": "invalid",
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
                            "payload_state": "Normal",
                            "expected_cs_response": "reject",
                            "expected_error": "UPLINK_MIC",
                            "next_state": "S0",
                        }
                    },
                },
                "S3b": {
                    "description": "Old session DataUp during rejoin window",
                    "field_config": "old_session_DataUp",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["ReJoinRequest"],
                    "invalid_messages": ["DataUp", "JoinRequest"],
                    "transitions": {
                        "ReJoin_Old_Session": {
                            "trigger": "ReJoinRequest",
                            "mic_state": "invalid",
                            "payload_state": "Normal",
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
                            "mic_state": "valid",
                            "payload_state": "Normal",
                            "expected_cs_response": "reject",
                            "expected_error": "OTAA",
                            "next_state": "S0",
                        }
                    },
                },
                "S3d": {
                    "description": "New session DataUp during rejoin window",
                    "field_config": "new_session_rejoin",
                    "sequence_origin": ["normal_join", "rejoin", "duplicate_join"],
                    "valid_messages": ["ReJoinRequest"],
                    "invalid_messages": ["DataUp", "JoinRequest"],
                    "transitions": {
                        "New_Session": {
                            "trigger": "ReJoinRequest",
                            "mic_state": "valid",
                            "payload_state": "Normal",
                            "expected_cs_response": "accept",
                            "expected_error": None,
                            "next_state": "S3",
                        }
                    },
                },
            },
        },
    }
}
