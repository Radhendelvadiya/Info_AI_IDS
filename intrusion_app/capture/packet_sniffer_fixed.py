try:
    from scapy.all import sniff, IP, TCP, UDP
except Exception:
    sniff = None
    IP = TCP = UDP = None

from .feature_extractor_clean import extract_features
from intrusion_app.ml.ids_model import predict_packet
import os

# When this sniffer is run as a standalone process we want to persist alerts
# and traffic to the Django DB so the web dashboard (which queries the DB)
# will reflect captured packets. Try to configure Django if not already set.
try:
    if os.environ.get('DJANGO_SETTINGS_MODULE') is None:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ai_ids.settings')
    import django
    django.setup()
    from intrusion_app.models import Alert, TrafficLog
    _ORM_AVAILABLE = True
except Exception:
    _ORM_AVAILABLE = False


def packet_callback(packet):
    if IP is None:
        return
    if IP in packet:
        features = extract_features(packet)
        prediction = predict_packet(features)

        src = packet[IP].src
        dst = packet[IP].dst
        size = len(packet)
        print(f"[IDS] {src} -> {dst} | {prediction} | {size} bytes")

        # Persist traffic bytes and alerts to DB so dashboard can read them
        try:
            if _ORM_AVAILABLE:
                TrafficLog.objects.create(bytes_count=size)
                if prediction and prediction.upper() in ("ATTACK", "ANOMALY", "MALICIOUS"):
                    a = Alert.objects.create(attack_type=str(prediction), severity='high')
                    # Mitigation: record blocked IP (safe default - DB + optional OS-level)
                    try:
                        from intrusion_app.models import BlockedIP
                        b = BlockedIP.objects.create(ip=src, reason=str(prediction))
                        print(f"[IDS] Mitigation recorded for {src}")

                        # Send real-time event to WebSocket group
                        try:
                            from asgiref.sync import async_to_sync
                            from channels.layers import get_channel_layer
                            channel_layer = get_channel_layer()
                            msg = {
                                'type': 'new_alert',
                                'attack_type': str(prediction),
                                'source': src,
                                'timestamp': str(a.timestamp),
                                'blocked': True
                            }
                            async_to_sync(channel_layer.group_send)('alerts', {'type': 'alert_message', 'message': msg})
                        except Exception as _e:
                            print('[IDS] failed to send websocket event', _e)

                        # Optional OS-level blocking
                        try:
                            from django.conf import settings
                            if getattr(settings, 'IDS_ENABLE_OS_BLOCKING', False):
                                import platform, subprocess
                                system = platform.system().lower()
                                if system == 'windows':
                                    rule_name = f"InfoIDS Block {src}"
                                    cmd = [
                                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                        'name=%s' % rule_name, 'dir=in', 'action=block', f'remoteip={src}'
                                    ]
                                    subprocess.run(cmd, check=False)
                                else:
                                    # Linux/macOS: use iptables (may require sudo)
                                    cmd = ['iptables', '-I', 'INPUT', '-s', src, '-j', 'DROP']
                                    subprocess.run(cmd, check=False)
                                print(f'[IDS] OS-level block attempted for {src}')
                        except Exception as _e:
                            print('[IDS] OS block failed', _e)
                    except Exception as _e:
                        print("[IDS] Mitigation DB write failed:", _e)
        except Exception as e:
            # Don't crash the sniffer if DB write fails; just log
            print("[IDS] DB write failed:", e)


def start_sniffing():
    if sniff is None:
        raise RuntimeError("Scapy is not installed. Install with: pip install scapy")
    sniff(prn=packet_callback, store=False)


if __name__ == '__main__':
    start_sniffing()
