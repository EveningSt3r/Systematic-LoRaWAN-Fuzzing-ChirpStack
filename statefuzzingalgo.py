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
    GW_EUI
)

from statefulFuzzer import (
    run_docker_cmd,
    get_redis_stream_length,
    poll_redis_for_new_entry,
    get_recent_bridge_logs,
    check_logs_for_errors,
    compute_join_request_mic,
    delete_device_session,
    get_device_state
)