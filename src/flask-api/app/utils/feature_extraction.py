"""
Utility functions for extracting network traffic features (Supports 12 and 25 variables).
"""
import numpy as np
from datetime import datetime
from config import Config

def calculate_time_diff(time_list):
    if len(time_list) <= 1:
        return []
    time_list.sort()
    time_diffs = []
    for i in range(1, len(time_list)):
        diff = (time_list[i] - time_list[i-1]).total_seconds() * 1000000
        time_diffs.append(diff)
    return time_diffs

def calculate_idle_times(time_list, threshold=Config.IDLE_THRESHOLD):
    time_diffs = calculate_time_diff(time_list)
    return [diff for diff in time_diffs if diff > threshold]

def calculate_active_times(time_list, threshold=Config.IDLE_THRESHOLD):
    time_diffs = calculate_time_diff(time_list)
    return [diff for diff in time_diffs if diff <= threshold]

def extract_fwd_iat_std(forward_times):
    fwd_iats = calculate_time_diff(forward_times)
    return float(np.std(fwd_iats)) if len(fwd_iats) >= 2 else 0.0

def extract_bwd_iat_std(backward_times):
    bwd_iats = calculate_time_diff(backward_times)
    return float(np.std(bwd_iats)) if len(bwd_iats) >= 2 else 0.0

def extract_flow_iat_std(all_times):
    flow_iats = calculate_time_diff(all_times)
    return float(np.std(flow_iats)) if len(flow_iats) >= 2 else 0.0

def extract_fwd_iat_max(forward_times):
    fwd_iats = calculate_time_diff(forward_times)
    return float(max(fwd_iats)) if fwd_iats else 0.0

def extract_fwd_iat_min(forward_times):
    fwd_iats = calculate_time_diff(forward_times)
    return float(min(fwd_iats)) if fwd_iats else 0.0

def extract_bwd_iat_min(backward_times):
    bwd_iats = calculate_time_diff(backward_times)
    return float(min(bwd_iats)) if bwd_iats else 0.0

def extract_flow_iat_min(all_times):
    flow_iats = calculate_time_diff(all_times)
    return float(min(flow_iats)) if flow_iats else 0.0

def extract_flow_iat_mean(all_times):
    flow_iats = calculate_time_diff(all_times)
    return float(np.mean(flow_iats)) if flow_iats else 0.0

def extract_flow_iat_max(all_times):
    flow_iats = calculate_time_diff(all_times)
    return float(max(flow_iats)) if flow_iats else 0.0

def extract_fwd_iat_mean(forward_times):
    fwd_iats = calculate_time_diff(forward_times)
    return float(np.mean(fwd_iats)) if fwd_iats else 0.0

def extract_fwd_iat_total(forward_times):
    fwd_iats = calculate_time_diff(forward_times)
    return float(np.sum(fwd_iats)) if fwd_iats else 0.0

def extract_bwd_iat_total(backward_times):
    bwd_iats = calculate_time_diff(backward_times)
    return float(np.sum(bwd_iats)) if bwd_iats else 0.0

def extract_bwd_iat_mean(backward_times):
    bwd_iats = calculate_time_diff(backward_times)
    return float(np.mean(bwd_iats)) if bwd_iats else 0.0

def extract_flow_duration(all_times):
    if len(all_times) < 2:
        return 0.0
    return float((max(all_times) - min(all_times)).total_seconds() * 1000000)

def extract_bwd_iat_max(backward_times):
    bwd_iats = calculate_time_diff(backward_times)
    return float(max(bwd_iats)) if bwd_iats else 0.0

def extract_idle_max(all_times, threshold=Config.IDLE_THRESHOLD):
    idle_times = calculate_idle_times(all_times, threshold)
    return float(max(idle_times)) if idle_times else 0.0

def extract_idle_mean(all_times, threshold=Config.IDLE_THRESHOLD):
    idle_times = calculate_idle_times(all_times, threshold)
    return float(np.mean(idle_times)) if idle_times else 0.0

def extract_idle_min(all_times, threshold=Config.IDLE_THRESHOLD):
    idle_times = calculate_idle_times(all_times, threshold)
    return float(min(idle_times)) if idle_times else 0.0

def extract_active_mean(all_times, threshold=Config.IDLE_THRESHOLD):
    active_times = calculate_active_times(all_times, threshold)
    return float(np.mean(active_times)) if active_times else 0.0

def parse_packet_data(packet_data):
    if not packet_data or len(packet_data) == 0:
        return [], [], []

    forward_times = []
    backward_times = []
    all_times = []

    first_src_ip = packet_data[0]['src_ip']
    first_src_port = packet_data[0]['src_port']

    for packet in packet_data:
        try:
            ts = packet.get('timestamp')
            if isinstance(ts, (int, float)):
                timestamp = datetime.fromtimestamp(ts)
            elif isinstance(ts, str):
                try:
                    timestamp = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                except Exception:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()

            all_times.append(timestamp)

            if packet.get('src_ip') == first_src_ip and packet.get('src_port') == first_src_port:
                forward_times.append(timestamp)
            else:
                backward_times.append(timestamp)
        except Exception:
            now = datetime.now()
            all_times.append(now)
            forward_times.append(now)

    return forward_times, backward_times, all_times

def extract_all_features(packet_data):
    forward_times, backward_times, all_times = parse_packet_data(packet_data)

    total_fwd_pkts = len(forward_times) if forward_times else 1
    total_bwd_pkts = len(backward_times)

    # 25 Extended Variables
    features = {
        'Fwd IAT Std': extract_fwd_iat_std(forward_times),
        'Bwd IAT Std': extract_bwd_iat_std(backward_times),
        'Flow IAT Std': extract_flow_iat_std(all_times),
        'Fwd IAT Max': extract_fwd_iat_max(forward_times),
        'Flow IAT Mean': extract_flow_iat_mean(all_times),
        'Flow IAT Max': extract_flow_iat_max(all_times),
        'Fwd IAT Mean': extract_fwd_iat_mean(forward_times),
        'Fwd IAT Total': extract_fwd_iat_total(forward_times),
        'Flow Duration': extract_flow_duration(all_times),
        'Bwd IAT Max': extract_bwd_iat_max(backward_times),
        'Idle Max': extract_idle_max(all_times),
        'Idle Mean': extract_idle_mean(all_times),
        'Fwd IAT Min': extract_fwd_iat_min(forward_times),
        'Bwd IAT Min': extract_bwd_iat_min(backward_times),
        'Flow IAT Min': extract_flow_iat_min(all_times),
        'Bwd IAT Total': extract_bwd_iat_total(backward_times),
        'Bwd IAT Mean': extract_bwd_iat_mean(backward_times),
        'Total Fwd Packets': float(total_fwd_pkts),
        'Total Backward Packets': float(total_bwd_pkts),
        'Total Length of Fwd Packets': float(total_fwd_pkts * 64),
        'Total Length of Bwd Packets': float(total_bwd_pkts * 64),
        'Fwd Header Length': float(total_fwd_pkts * 20),
        'Bwd Header Length': float(total_bwd_pkts * 20),
        'Active Mean': extract_active_mean(all_times),
        'Idle Min': extract_idle_min(all_times)
    }

    return features