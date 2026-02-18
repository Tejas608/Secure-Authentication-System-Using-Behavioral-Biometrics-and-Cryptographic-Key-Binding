import math
import statistics
from typing import List, Dict, Set
import numpy as np

def _pair_key_events(events: List[Dict]) -> List[float]:
    """Compute dwell times."""
    keydown_map = {}
    dwell_times = []
    for evt in events:
        if evt.get("type") == "keydown":
            keydown_map[evt.get("code")] = evt.get("timestamp", 0.0)
        elif evt.get("type") == "keyup":
            start = keydown_map.pop(evt.get("code"), None)
            if start is not None:
                dwell_times.append(max(evt.get("timestamp", 0.0) - start, 0.001))
    return dwell_times

def _flight_times(events: List[Dict]) -> List[float]:
    """Compute flight times."""
    keydown_ts = [evt.get("timestamp", 0.0) for evt in events if evt.get("type") == "keydown"]
    flights = []
    for i in range(1, len(keydown_ts)):
        flights.append(max(keydown_ts[i] - keydown_ts[i - 1], 0.001))
    return flights

def _get_press_release_pattern(events: List[Dict]) -> Dict:
    """Analyze press-release patterns."""
    if not events:
        return {"pattern_entropy": 0.0, "key_variation": 0.0}
    
    key_sequence = []
    for evt in events:
        if evt.get("type") == "keydown":
            key = evt.get("key", "").lower()
            if len(key) == 1 or key == "space":
                key_sequence.append(key)
    
    # Calculate pattern entropy
    if len(key_sequence) < 2:
        return {"pattern_entropy": 0.0, "key_variation": 0.0}
    
    # Calculate transitions
    transitions = {}
    for i in range(len(key_sequence) - 1):
        transition = (key_sequence[i], key_sequence[i + 1])
        transitions[transition] = transitions.get(transition, 0) + 1
    
    # Calculate entropy
    total = sum(transitions.values())
    entropy = 0.0
    for count in transitions.values():
        p = count / total
        entropy -= p * math.log(p + 1e-10, 2)
    
    # Normalize entropy
    max_entropy = math.log(len(transitions) + 1e-10, 2) if transitions else 1.0
    normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
    
    # Key variation (unique keys / total keys)
    unique_keys = len(set(key_sequence))
    key_variation = unique_keys / len(key_sequence) if key_sequence else 0.0
    
    return {
        "pattern_entropy": normalized_entropy,
        "key_variation": key_variation,
        "unique_transitions": len(transitions)
    }

def _safe_stats(values: List[float]):
    if not values:
        return 0.0, 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0, values[0]
    return statistics.mean(values), statistics.pstdev(values), statistics.median(values)

def extract_features(events: List[Dict]) -> Dict[str, float]:
    """Extract comprehensive keystroke features."""
    if not events:
        return {
            "dwell_mean": 0.0,
            "dwell_std": 0.0,
            "dwell_median": 0.0,
            "flight_mean": 0.0,
            "flight_std": 0.0,
            "flight_median": 0.0,
            "total_time": 0.0,
            "key_count": 0.0,
            "cadence": 0.0,
            "rhythm_consistency": 0.0,
            "pressure_variance": 0.0,
            "dwell_flight_ratio": 0.0,
            "dwell_cv": 0.0,
            "pattern_entropy": 0.0,
            "key_variation": 0.0,
            "typing_burstiness": 0.0
        }

    # Sanitize events
    events_sorted = _sanitize_backspaces(sorted(events, key=lambda x: x.get("timestamp", 0.0)))
    if not events_sorted:
        return {
            "dwell_mean": 0.0,
            "dwell_std": 0.0,
            "dwell_median": 0.0,
            "flight_mean": 0.0,
            "flight_std": 0.0,
            "flight_median": 0.0,
            "total_time": 0.0,
            "key_count": 0.0,
            "cadence": 0.0,
            "rhythm_consistency": 0.0,
            "pressure_variance": 0.0,
            "dwell_flight_ratio": 0.0,
            "dwell_cv": 0.0,
            "pattern_entropy": 0.0,
            "key_variation": 0.0,
            "typing_burstiness": 0.0
        }
    
    dwell_times = _pair_key_events(events_sorted)
    flight_times = _flight_times(events_sorted)
    
    dwell_mean, dwell_std, dwell_median = _safe_stats(dwell_times)
    flight_mean, flight_std, flight_median = _safe_stats(flight_times)
    
    first_ts = events_sorted[0].get("timestamp", 0.0)
    last_ts = events_sorted[-1].get("timestamp", first_ts)
    total_time = max(last_ts - first_ts, 0.001)
    
    key_count = len([e for e in events_sorted if e.get("type") == "keydown"])
    cadence = (key_count / total_time) if total_time > 0 else 0.0
    
    # Rhythm consistency
    rhythm_consistency = 0.0
    if flight_times and flight_mean > 0:
        rhythm_consistency = flight_std / flight_mean
    
    # Pressure variance
    pressure_variance = dwell_std if dwell_std > 0 else 0.0
    
    # Ratios
    dwell_flight_ratio = (dwell_mean / flight_mean) if flight_mean > 0.001 else 0.0
    dwell_cv = (dwell_std / dwell_mean) if dwell_mean > 0.001 else 0.0
    
    # Pattern analysis
    pattern_data = _get_press_release_pattern(events_sorted)
    
    # Typing burstiness (coefficient of variation of flight times)
    typing_burstiness = (statistics.pstdev(flight_times) / statistics.mean(flight_times)) if flight_times and statistics.mean(flight_times) > 0 else 0.0
    
    return {
        "dwell_mean": dwell_mean,
        "dwell_std": dwell_std,
        "dwell_median": dwell_median,
        "flight_mean": flight_mean,
        "flight_std": flight_std,
        "flight_median": flight_median,
        "total_time": total_time,
        "key_count": float(key_count),
        "cadence": cadence,
        "rhythm_consistency": rhythm_consistency,
        "pressure_variance": pressure_variance,
        "dwell_flight_ratio": dwell_flight_ratio,
        "dwell_cv": dwell_cv,
        "pattern_entropy": pattern_data["pattern_entropy"],
        "key_variation": pattern_data["key_variation"],
        "typing_burstiness": typing_burstiness
    }

def feature_vector(feature_map: Dict[str, float]) -> List[float]:
    """Convert to ordered feature vector."""
    ordered_keys = [
        "dwell_mean",
        "dwell_std",
        "dwell_median",
        "flight_mean",
        "flight_std",
        "flight_median",
        "total_time",
        "key_count",
        "cadence",
        "rhythm_consistency",
        "pressure_variance",
        "dwell_flight_ratio",
        "dwell_cv",
        "pattern_entropy",
        "key_variation",
        "typing_burstiness"
    ]
    return [float(feature_map.get(k, 0.0)) for k in ordered_keys]

# ---------- Sanitization helpers ----------

def _is_printable_key(key: str) -> bool:
    """Check if key produces a character."""
    if not isinstance(key, str):
        return False
    if len(key) == 1:
        return True
    return key in ("Space",)

def _sanitize_backspaces(events: List[Dict]) -> List[Dict]:
    """Remove events for characters deleted via Backspace."""
    if not events:
        return events

    units = []
    open_unit_idx_by_code = {}

    for idx, evt in enumerate(events):
        etype = evt.get("type")
        key = evt.get("key")
        code = evt.get("code")

        if etype == "keydown":
            if key == "Backspace":
                for u in reversed(units):
                    if not u.get("deleted") and u.get("down_idx") is not None:
                        u["deleted"] = True
                        break
                continue
            if _is_printable_key(key):
                unit = {"key": key, "code": code, "down_idx": idx, "up_idx": None, "deleted": False}
                units.append(unit)
                open_unit_idx_by_code[code] = len(units) - 1
        elif etype == "keyup":
            if key == "Backspace":
                continue
            if _is_printable_key(key):
                u_idx = open_unit_idx_by_code.get(code)
                if u_idx is not None:
                    units[u_idx]["up_idx"] = idx
                    open_unit_idx_by_code.pop(code, None)

    keep = set()
    for u in units:
        if not u.get("deleted") and u.get("down_idx") is not None and u.get("up_idx") is not None:
            keep.add(int(u["down_idx"]))
            keep.add(int(u["up_idx"]))

    filtered = [evt for i, evt in enumerate(events) if i in keep]
    return filtered