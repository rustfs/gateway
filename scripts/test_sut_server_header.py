#!/usr/bin/env python3
# Copyright 2026 RustFS Team
# SPDX-License-Identifier: Apache-2.0
"""Check how `ci/lib/sut.sh` reads an external endpoint's own `Server` header.

Owns `sut_server_header`: what an endpoint says it is, as the client matrix and mint record it
before `compat-sut --external` stands in front of it (rustfs/backlog#2758). The value is echoed
into a CI log line, so a hostile or folded header must come out as one printable line; an endpoint
that does not answer must stop the run with the environment exit, never record an empty build.
Not responsible for the observer itself (`compat/sut/tests/binary/external.rs`).
"""

import socket
import subprocess
import threading
import unittest
from pathlib import Path

LIBRARY = Path(__file__).resolve().parents[1] / "ci/lib/sut.sh"


def endpoint(answer: bytes) -> tuple[int, threading.Thread]:
    """A one-shot raw HTTP server answering any request with `answer`."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    def serve() -> None:
        connection, _ = server.accept()
        connection.recv(65536)
        connection.sendall(answer)
        connection.close()
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server.getsockname()[1], thread


def read(port: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", f'source "{LIBRARY}"; sut_server_header http://127.0.0.1:{port}'],
        capture_output=True,
        text=True,
        timeout=30,
    )


def head(server: bytes) -> bytes:
    return b"HTTP/1.1 403 Forbidden\r\n" + server + b"Content-Length: 0\r\nConnection: close\r\n\r\n"


class ServerHeaderTests(unittest.TestCase):
    def test_the_endpoints_own_name_is_read_from_a_refusal(self):
        port, thread = endpoint(head(b"Server: RustFS\r\n"))
        result = read(port)
        thread.join(5)
        self.assertEqual((result.returncode, result.stdout), (0, "RustFS\n"), result.stderr)

    def test_an_endpoint_that_names_nothing_prints_nothing(self):
        port, thread = endpoint(head(b""))
        result = read(port)
        thread.join(5)
        self.assertEqual((result.returncode, result.stdout), (0, "\n"), result.stderr)

    def test_n_a_folded_control_laden_header_is_one_printable_line(self):
        port, thread = endpoint(head(b"Server: Evil\x07Build\r\n ::add-mask::folded\r\n"))
        result = read(port)
        thread.join(5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("\n"), 1, repr(result.stdout))
        self.assertTrue(result.stdout.rstrip("\n").isprintable(), repr(result.stdout))
        self.assertFalse(result.stdout.startswith("::"), repr(result.stdout))

    def test_n_an_oversized_header_is_bounded(self):
        port, thread = endpoint(head(b"Server: " + b"A" * 4000 + b"\r\n"))
        result = read(port)
        thread.join(5)
        self.assertEqual(len(result.stdout.rstrip("\n")), 200, len(result.stdout))

    def test_n_an_endpoint_that_does_not_answer_is_an_environment_failure(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        result = read(port)
        self.assertEqual((result.returncode, result.stdout), (3, ""), result.stderr)
        self.assertIn("did not answer HEAD /", result.stderr)


if __name__ == "__main__":
    unittest.main()
