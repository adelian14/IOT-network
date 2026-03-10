import sys
import os
import signal

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.ids_monitor import IDSMonitor
from reports.report_generator import ReportGenerator


def main():
    broker_ip = os.getenv("MQTT_BROKER", "10.0.0.100")
    broker_port = int(os.getenv("MQTT_PORT", "1883"))

    print("=" * 60)
    print("  IoT Network Security System - IDS")
    print(f"  Broker: {broker_ip}:{broker_port}")
    print("=" * 60)

    report_gen = ReportGenerator()
    monitor = IDSMonitor(
        broker_ip=broker_ip,
        broker_port=broker_port,
        report_generator=report_gen,
    )

    def shutdown(sig, frame):
        print("\n[MAIN] Shutting down IDS...")
        monitor.stop()
        summary = report_gen.generate_summary_report(monitor.decision_engine.incident_log)
        if summary:
            print(f"[MAIN] Summary report saved: {summary}")
        stats = monitor.get_stats()
        print(f"[MAIN] Final stats: {stats}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        monitor.start()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
