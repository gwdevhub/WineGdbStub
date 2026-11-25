#!/usr/bin/env python3
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "build" / "bin"
PORT = int(os.environ.get("GWSTUB_PORT", "2345"))


def frame(payload: str) -> bytes:
    return b"$" + payload.encode() + b"#" + format(sum(payload.encode()) & 0xFF, "02x").encode()


class Client:
    def __init__(self) -> None:
        self.sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        self.buffer = b""

    def send(self, payload: str) -> None:
        self.sock.sendall(frame(payload))

    def next_packet(self, timeout: float) -> str:
        deadline = time.time() + timeout
        while True:
            start = self.buffer.find(b"$")
            end = self.buffer.find(b"#", start) if start >= 0 else -1
            if end >= 0 and len(self.buffer) >= end + 3:
                payload = self.buffer[start + 1:end].decode()
                self.buffer = self.buffer[end + 3:]
                return payload
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("no packet")
            self.sock.settimeout(remaining)
            data = self.sock.recv(4096)
            if not data:
                raise ConnectionError("stub closed the connection")
            self.buffer += data

    def ask(self, payload: str, timeout: float = 5.0) -> str:
        self.send(payload)
        return self.next_packet(timeout)

    def close(self) -> None:
        self.sock.close()


def registers(client: Client) -> dict:
    raw = bytes.fromhex(client.ask("g"))
    names = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"]
    return {name: struct.unpack_from("<I", raw, i * 4)[0] for i, name in enumerate(names)}


def check(condition: bool, message: str) -> None:
    print(("PASS " if condition else "FAIL ") + message)
    if not condition:
        raise SystemExit(1)


def wait_for_address(output: Path, timeout: float) -> int:
    deadline = time.time() + timeout
    while time.time() < deadline:
        match = re.search(r"hitMe=(?:0x)?([0-9a-fA-F]+)", output.read_text(errors="replace")) if output.exists() else None
        if match:
            return int(match.group(1), 16)
        time.sleep(0.2)
    raise TimeoutError("target did not print hitMe's address")


def wait_for_port(timeout: float) -> Client:
    deadline = time.time() + timeout
    while True:
        try:
            return Client()
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(0.3)


def main() -> int:
    env = dict(os.environ, WINEDEBUG="-all", GWSTUB_MODULE="WineGdbStub.dll")
    output = Path(tempfile.mkdtemp()) / "target.out"
    with output.open("w") as out:
        target = subprocess.Popen(["wine", "StubTarget.exe"], cwd=BIN, env=env, stdout=out, stderr=subprocess.DEVNULL)
    try:
        address = wait_for_address(output, 60)
        client = wait_for_port(30)
        print(f"hitMe at 0x{address:08x}")

        check(client.ask("?") == "S05", "initial stop reply is S05")
        connect_tib = client.ask("qGetTIBAddr:1")
        check(len(connect_tib) == 8 and all(c in "0123456789abcdef" for c in connect_tib), f"qGetTIBAddr works right after connecting ({connect_tib})")
        check(client.ask("qfThreadInfo") == "m1", "thread list is reported")
        check(client.ask(f"Z0,{address:x},1") == "OK", "breakpoint inserted at hitMe")

        client.send("c")
        check(client.next_packet(15) == "S05", "continue stops at the breakpoint")
        regs = registers(client)
        check(regs["eip"] == address, f"eip is hitMe (0x{regs['eip']:08x})")
        check(client.ask(f"m{address:x},1") == "cc", "int3 is in memory at the breakpoint")
        tib = int(client.ask("qGetTIBAddr:1"), 16)
        self_pointer = struct.unpack("<I", bytes.fromhex(client.ask(f"m{tib + 0x18:x},4")))[0]
        check(self_pointer == tib, f"qGetTIBAddr returns a thread information block (0x{tib:08x})")

        client.send("s")
        check(client.next_packet(10) == "S05", "single step reports a stop")
        stepped = registers(client)["eip"]
        check(stepped != address and stepped > address and stepped - address < 0x40, f"single step moved eip (0x{stepped:08x})")

        client.send("c")
        check(client.next_packet(15) == "S05", "continue steps over the breakpoint and stops on the next call")
        check(registers(client)["eip"] == address, "second hit is hitMe again")

        check(client.ask(f"z0,{address:x},1") == "OK", "breakpoint removed")
        client.send("qRcmd," + b"modules".hex())
        output = ""
        while True:
            packet = client.next_packet(5)
            if packet == "OK":
                break
            if packet.startswith("O"):
                output += bytes.fromhex(packet[1:]).decode()
        check("StubTarget.exe" in output and "WineGdbStub.dll" in output, "monitor modules lists the target and the stub")
        print(output.strip())
        base = next(int(line.split()[0], 16) for line in output.splitlines() if line.endswith("WineGdbStub.dll"))
        image_base = struct.unpack_from("<I", (BIN / "WineGdbStub.dll").read_bytes(), struct.unpack_from("<I", (BIN / "WineGdbStub.dll").read_bytes(), 0x3C)[0] + 24 + 28)[0]
        client.send("qOffsets")
        offsets = client.next_packet(5)
        expected = "Text=%x;Data=%x;Bss=%x" % ((base - image_base,) * 3)
        check(offsets == expected, f"qOffsets reports the module's move ({offsets})")
        check(client.ask("D") == "OK", "detach replies OK")
        client.close()
        time.sleep(2)
        check(target.poll() is None, "target keeps running after detach")
        return 0
    finally:
        target.kill()
        target.wait()


if __name__ == "__main__":
    sys.exit(main())
