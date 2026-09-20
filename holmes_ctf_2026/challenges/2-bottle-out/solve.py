#!/usr/bin/env python3
"""Recover the deleted VPN log used in the Bottle Out solution.

The challenge VM exposed its forensic disk as a raw Windows device.  The deleted
``spur.log`` file occupied the two clusters below; this script reconstructs
the file without embedding VM credentials or connecting to the remote box.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


CLUSTER_SIZE = 4096
SPUR_LOG_CLUSTERS = (0x152C6C, 0x14FE0F)
SPUR_LOG_SIZE = 6201


def recover_spur_log(disk: Path, output: Path) -> bytes:
    """Read the known NTFS cluster locations and write the recovered log."""

    data = bytearray()
    with disk.open("rb") as handle:
        for cluster in SPUR_LOG_CLUSTERS:
            handle.seek(cluster * CLUSTER_SIZE)
            data.extend(handle.read(CLUSTER_SIZE))

    recovered = bytes(data[:SPUR_LOG_SIZE])
    output.write_bytes(recovered)
    return recovered


def print_answers(log: bytes) -> None:
    """Print the VPN evidence needed for the first three questions."""

    text = log.decode("utf-8", errors="replace")
    patterns = {
        "remote endpoint": r"remote:\s*\[AF_INET\]([^\s]+)",
        "certificate authority": r"VERIFY OK:\s*depth=1,\s*CN=([^\r\n]+)",
        "assigned address": r"ASSIGN_IP,,([^,\r\n]+)",
    }
    for label, pattern in patterns.items():
        match = re.search(pattern, text, flags=re.IGNORECASE)
        print(f"{label}: {match.group(1) if match else 'not found'}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--disk",
        type=Path,
        default=Path(r"\\.\D:"),
        help=r"raw challenge disk/device (default: \\.\D:)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("spur.log.recovered"),
        help="where to save the recovered log",
    )
    args = parser.parse_args()

    log = recover_spur_log(args.disk, args.output)
    print(f"recovered {len(log)} bytes into {args.output}")
    print_answers(log)


if __name__ == "__main__":
    main()
