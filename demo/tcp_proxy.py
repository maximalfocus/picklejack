"""A minimal loopback TCP proxy so the egress-free vulnerable container is reachable.

The vulnerable app runs on an internal (no-egress) network with no host port, so
that even in-container code execution cannot reach the network. This benign
forwarder — which reconstructs no objects and executes no user input — sits on both
that internal network and an edge network, publishing ``127.0.0.1:8001`` and
forwarding to the vulnerable container.
"""

from __future__ import annotations

import asyncio
import os

# Binds inside the container; the host publishes this only on 127.0.0.1 (loopback).
LISTEN_HOST = os.environ.get("PROXY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_LISTEN_PORT", "8001"))
TARGET_HOST = os.environ.get("PROXY_TARGET_HOST", "vulnerable")
TARGET_PORT = int(os.environ.get("PROXY_TARGET_PORT", "8001"))


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def _handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    try:
        server_reader, server_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(
        _pipe(client_reader, server_writer),
        _pipe(server_reader, client_writer),
    )


async def main() -> None:
    server = await asyncio.start_server(_handle, LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
