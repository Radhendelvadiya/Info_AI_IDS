from collections import defaultdict
from sklearn.ensemble import IsolationForest
import numpy as np
import threading
import time

# In-memory fallback storage (used if Django ORM is not available)
packet_sizes = []
connection_counter = defaultdict(int)
_alerts = []
traffic_bytes = 0
packet_count = 0

model = IsolationForest(contamination=0.02)
model_trained = False


def detect_packet(packet):
    # legacy in-memory detector kept for quick testing
    global traffic_bytes, model_trained

    try:
        from scapy.all import IP, TCP
    except Exception:
        return

    if IP in packet:
        src = packet[IP].src
        size = len(packet)

        traffic_bytes += size
        packet_sizes.append(size)
        connection_counter[src] += 1

        # Rule 1: Port scan detection
        if connection_counter[src] > 100:
            _alerts.append({"type": "Port Scan", "source": src})

        # Rule 2: Suspicious ports
        if TCP in packet:
            if packet[TCP].dport in [23, 445, 3389]:
                _alerts.append({"type": "Suspicious Port Access", "source": src})

        # Train model after baseline
        if len(packet_sizes) > 200 and not model_trained:
            data = np.array(packet_sizes).reshape(-1, 1)
            model.fit(data)
            model_trained = True

        # AI detection
        if model_trained:
            score = model.decision_function([[size]])
            if score < -0.1:
                _alerts.append({"type": "AI Anomaly", "source": src})


def start_sniffing():
    try:
        from scapy.all import sniff
    except Exception:
        raise RuntimeError("Scapy is not available")
    sniff(prn=detect_packet, store=False)


def start_background():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()


def get_dashboard_data():
    """
    Return a dashboard-friendly dict. Prefer database-backed values (if Django is
    configured) otherwise fall back to in-memory accumulators.
    """
    try:
        import os
        from django.utils import timezone
        from datetime import timedelta
        from django.db.models import Sum
        # Ensure settings are configured by the caller if running standalone
        from intrusion_app.models import Alert, TrafficLog

        # Active alerts in the last 24 hours
        since = timezone.now() - timedelta(days=1)
        active_alerts = Alert.objects.filter(timestamp__gte=since).count()

        total_bytes = TrafficLog.objects.aggregate(total=Sum('bytes_count'))['total'] or 0

        recent_alerts_qs = Alert.objects.order_by('-timestamp')[:10]
        recent_alerts = [
            {"type": a.attack_type, "severity": a.severity, "timestamp": a.timestamp.isoformat()}
            for a in recent_alerts_qs
        ]

        return {
            "active_alerts": active_alerts,
            "traffic_gb": round(total_bytes / (1024 ** 3), 4),
            "alerts": recent_alerts,
        }
    except Exception:
        # Fallback to memory-based stats
        return {
            "active_alerts": len(_alerts),
            "traffic_gb": round(traffic_bytes / (1024 ** 3), 4),
            "alerts": _alerts[-10:]
        }


packet_count += 1
print("Total Packets (module load):", packet_count)
