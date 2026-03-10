"""
Offensive Node - Main attack orchestrator.
Provides both menu-driven and automated attack sequences
for testing the IDS/firewall system.
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from offensive.scanner import run_full_scan
from offensive.attacks import spoofing, flooding, injection, replay, malformed

BROKER_IP = os.getenv("MQTT_BROKER", "10.0.0.100")

ATTACKS = {
    "1": ("Network Scan", lambda: run_full_scan()),
    "2": ("Spoofing (fake sensor data)", lambda: spoofing.run(BROKER_IP)),
    "3": ("Flooding (DoS)", lambda: flooding.run(BROKER_IP)),
    "4": ("Injection (direct actuator commands)", lambda: injection.run(BROKER_IP)),
    "5": ("Replay (capture & replay)", lambda: replay.run(BROKER_IP)),
    "6": ("Malformed Payloads", lambda: malformed.run(BROKER_IP)),
    "7": ("Run ALL attacks (automated sequence)", None),
}


def print_banner():
    print("=" * 60)
    print("  IoT Offensive Testing Node")
    print(f"  Target Broker: {BROKER_IP}")
    print("=" * 60)


def print_menu():
    print("\nAvailable attacks:")
    for key, (name, _) in ATTACKS.items():
        print(f"  [{key}] {name}")
    print("  [q] Quit")
    print()


def run_all_attacks():
    """Execute all attacks in sequence with pauses between them."""
    print("\n" + "=" * 60)
    print("  AUTOMATED ATTACK SEQUENCE")
    print("=" * 60)

    sequence = [
        ("Network Scan", lambda: run_full_scan()),
        ("Spoofing", lambda: spoofing.run(BROKER_IP, duration=15)),
        ("Flooding", lambda: flooding.run(BROKER_IP, duration=10, messages_per_second=30)),
        ("Injection", lambda: injection.run(BROKER_IP, duration=15, interval=1.5)),
        ("Replay", lambda: replay.run(BROKER_IP, capture_time=8, replay_time=15)),
        ("Malformed", lambda: malformed.run(BROKER_IP, duration=15)),
    ]

    total_start = time.time()
    results = []

    for i, (name, attack_fn) in enumerate(sequence, 1):
        print(f"\n{'─' * 40}")
        print(f"  Attack {i}/{len(sequence)}: {name}")
        print(f"{'─' * 40}")

        start = time.time()
        try:
            result = attack_fn()
            elapsed = time.time() - start
            results.append((name, "SUCCESS", elapsed, result))
            print(f"  Completed in {elapsed:.1f}s")
        except Exception as e:
            elapsed = time.time() - start
            results.append((name, "FAILED", elapsed, str(e)))
            print(f"  FAILED after {elapsed:.1f}s: {e}")

        if i < len(sequence):
            pause = 5
            print(f"\n  Pausing {pause}s before next attack...")
            time.sleep(pause)

    total_elapsed = time.time() - total_start
    print(f"\n{'=' * 60}")
    print("  ATTACK SEQUENCE COMPLETE")
    print(f"  Total time: {total_elapsed:.1f}s")
    print(f"{'=' * 60}")

    print("\nResults:")
    for name, status, elapsed, detail in results:
        print(f"  {name:25s} {status:10s} {elapsed:6.1f}s  {detail}")


def interactive_mode():
    """Menu-driven attack selection."""
    print_banner()

    while True:
        print_menu()
        choice = input("Select attack> ").strip().lower()

        if choice == "q":
            print("Exiting offensive node.")
            break

        if choice == "7":
            run_all_attacks()
            continue

        attack = ATTACKS.get(choice)
        if attack is None:
            print("Invalid choice. Try again.")
            continue

        name, fn = attack
        print(f"\nLaunching: {name}")
        try:
            fn()
        except Exception as e:
            print(f"Attack failed: {e}")


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "auto":
            print_banner()
            run_all_attacks()
        elif cmd == "scan":
            run_full_scan()
        elif cmd in ATTACKS and ATTACKS[cmd][1]:
            print_banner()
            ATTACKS[cmd][1]()
        else:
            print(f"Usage: {sys.argv[0]} [auto|scan|1-6]")
            print("  auto  - Run all attacks in sequence")
            print("  scan  - Network scan only")
            print("  1-6   - Run specific attack")
            print("  (no args) - Interactive menu")
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
