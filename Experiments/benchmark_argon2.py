
import platform
import statistics
import sys
import time
from importlib.metadata import version
from pathlib import Path

from argon2 import PasswordHasher, Type

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

PASSWORD = "Benchmark-Password-2026!"
ROUNDS = 5

CONFIGURATIONS = [
    {
        "name": "A - Lightweight",
        "memory_cost": 19 * 1024,
        "time_cost": 2,
        "parallelism": 1,
    },
    {
        "name": "B - Current baseline",
        "memory_cost": 64 * 1024,
        "time_cost": 3,
        "parallelism": 4,
    },
    {
        "name": "C - Higher memory",
        "memory_cost": 128 * 1024,
        "time_cost": 2,
        "parallelism": 4,
    },
]


def benchmark_configuration(config):
    hasher = PasswordHasher(
        time_cost=config["time_cost"],
        memory_cost=config["memory_cost"],
        parallelism=config["parallelism"],
        hash_len=32,
        salt_len=16,
        type=Type.ID,
    )

    # Warm-up operations are excluded from measurements.
    stored_hash = hasher.hash(PASSWORD)
    assert hasher.verify(stored_hash, PASSWORD)

    hash_times = []

    for _ in range(ROUNDS):
        start = time.perf_counter()
        stored_hash = hasher.hash(PASSWORD)
        hash_times.append(time.perf_counter() - start)

    verify_times = []

    for _ in range(ROUNDS):
        start = time.perf_counter()
        result = hasher.verify(stored_hash, PASSWORD)
        verify_times.append(time.perf_counter() - start)

        assert result is True

    return hash_times, verify_times


def report(title, durations):
    milliseconds = [value * 1000 for value in durations]

    print(f"  {title}")
    print(f"    Median: {statistics.median(milliseconds):.2f} ms")
    print(f"    Mean:   {statistics.mean(milliseconds):.2f} ms")
    print(f"    Min:    {min(milliseconds):.2f} ms")
    print(f"    Max:    {max(milliseconds):.2f} ms")


def main():
    print("ARGON2ID CONFIGURATION COMPARISON")
    print("=" * 48)
    print(f"Python:      {sys.version.split()[0]}")
    print(f"Platform:    {platform.platform()}")
    print(f"argon2-cffi: {version('argon2-cffi')}")
    print(f"Runs per operation: {ROUNDS}")
    print("Hash length: 32 bytes")
    print("Salt length: 16 bytes")

    for config in CONFIGURATIONS:
        print("\n" + "-" * 48)
        print(config["name"])
        print(f"Memory:      {config['memory_cost'] / 1024:.0f} MiB")
        print(f"Iterations:  {config['time_cost']}")
        print(f"Parallelism: {config['parallelism']}")

        hash_times, verify_times = benchmark_configuration(config)

        report("Hashing:", hash_times)
        report("Verification:", verify_times)

    print("\nAll benchmark configurations completed successfully.")


if __name__ == "__main__":
    main()