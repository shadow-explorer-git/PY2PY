import asyncio
import base64
import hashlib
import json
import struct
import os
import uuid
from pathlib import Path
from .crypto_engine import CryptoManager
from .identity import DeviceIdentity
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CHUNK_SIZE = 65536
HANDSHAKE_DOMAIN = b"PY2PY-authenticated-handshake-v3"


def _encode_handshake(role: str, ephemeral_key: bytes, identity: DeviceIdentity, peer_key: bytes = b"") -> bytes:
    signed_data = HANDSHAKE_DOMAIN + role.encode("ascii") + peer_key + ephemeral_key
    return json.dumps({
        "version": 3,
        "role": role,
        "ephemeral_key": base64.b64encode(ephemeral_key).decode("ascii"),
        "identity_key": base64.b64encode(identity.public_bytes()).decode("ascii"),
        "signature": base64.b64encode(identity.sign(signed_data)).decode("ascii"),
    }).encode("utf-8")


def _decode_handshake(payload: bytes, expected_role: str, peer_key: bytes = b"") -> tuple[bytes, bytes]:
    try:
        data = json.loads(payload.decode("utf-8"))
        if data.get("version") != 3 or data.get("role") != expected_role:
            raise ValueError("Unsupported handshake protocol.")
        ephemeral_key = base64.b64decode(data["ephemeral_key"], validate=True)
        identity_key = base64.b64decode(data["identity_key"], validate=True)
        signature = base64.b64decode(data["signature"], validate=True)
        if len(identity_key) != 32:
            raise ValueError("Invalid peer identity key.")
        signed_data = HANDSHAKE_DOMAIN + expected_role.encode("ascii") + peer_key + ephemeral_key
        Ed25519PublicKey.from_public_bytes(identity_key).verify(signature, signed_data)
        return ephemeral_key, identity_key
    except (KeyError, ValueError, TypeError, InvalidSignature) as error:
        raise ValueError("Peer identity signature verification failed.") from error


def _verification_code(shared_key: bytes) -> str:
    value = int.from_bytes(hashlib.sha256(b"PY2PY-SAS-v3" + shared_key).digest()[:4], "big")
    return f"{value % 10_000_000_000:010d}"

async def send_msg(writer: asyncio.StreamWriter, data: bytes):
    """Helper to send length-prefixed binary data."""
    writer.write(struct.pack('>I', len(data))) # Send 4-byte length
    writer.write(data)
    await writer.drain()

async def recv_msg(reader: asyncio.StreamReader) -> bytes:
    """Helper to receive length-prefixed binary data."""
    length_bytes = await reader.readexactly(4)
    length = struct.unpack('>I', length_bytes)[0]
    return await reader.readexactly(length)

class FileTransferServer:
    def __init__(self, port: int, save_dir: str = "received_files", host: str | None = None):
        self.port = port
        self.host = host
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(exist_ok=True)
        self.server = None
        self.on_status = None
        self.on_request_permission = None
        self.identity = DeviceIdentity()
        self.on_progress = None
        self.on_received = None

    def _status(self, message: str):
        print(message)
        if self.on_status:
            self.on_status(message)

    def _progress(self, completed: int, total: int):
        if self.on_progress:
            self.on_progress(completed, total)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        self._status(f"Incoming connection from {addr}")
        crypto = CryptoManager()

        try:
            # 1. KEY EXCHANGE (ECDH)
            self._status("Establishing secure connection…")
            client_pub_key, client_identity_key = _decode_handshake(
                await recv_msg(reader), "client"
            )
            server_pub_key = crypto.get_public_key_bytes()
            await send_msg(writer, _encode_handshake(
                "server", server_pub_key, self.identity, client_pub_key
            ))
            crypto.derive_shared_key(client_pub_key)
            self._status("Secure channel established.")

            # 2. RECEIVE ENCRYPTED METADATA
            encrypted_meta = await recv_msg(reader)
            metadata = crypto.decrypt_metadata(encrypted_meta)
            
            filename = metadata['filename']
            file_hash = metadata['hash']
            encrypted_size = metadata['encrypted_size']
            source_size = metadata.get('source_size', encrypted_size)
            payload_plaintext_size = metadata.get('payload_plaintext_size')
            if metadata.get('protocol_version') != 2 or not isinstance(payload_plaintext_size, int):
                raise ValueError("Unsupported or invalid transfer protocol.")
            
            if self.on_request_permission:
               # Trigger the Flet Dialog box
               response = await self.on_request_permission(
                   filename,
                   source_size,
                   DeviceIdentity.fingerprint(client_identity_key),
                   _verification_code(crypto.shared_key),
               )
            else:
                # Fallback to CLI if running without GUI
                prompt = f"Accept '{filename}'? (y/n): "
                response = await asyncio.to_thread(input, prompt)
            
            # Send encrypted response
            encrypted_response = crypto.encrypt_metadata({"status": response.strip().lower()})
            await send_msg(writer, encrypted_response)
            
            if response.strip().lower() != 'y':
                self._status("Transfer rejected.")
                return

            # 4. RECEIVE ENCRYPTED STREAM
            encrypted_payload_path = self.save_dir / f".py2py-{uuid.uuid4().hex}.encrypted"
            self._status(f"Receiving {filename}…")
            
            received = 0
            self._progress(0, encrypted_size)
            with open(encrypted_payload_path, "wb") as f:
                while received < encrypted_size:
                    chunk = await reader.read(min(CHUNK_SIZE, encrypted_size - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
                    self._progress(received, encrypted_size)

            if received != encrypted_size:
                raise ConnectionError("Transfer ended before all data was received.")

            # 5. DECRYPT AND UNPACK
            self._status("Transfer received. Verifying and unpacking...")
            crypto.decrypt_and_unpack(
                str(encrypted_payload_path),
                str(self.save_dir),
                file_hash,
                payload_plaintext_size,
            )
            os.remove(encrypted_payload_path)
            await send_msg(writer, crypto.encrypt_metadata({"status": "complete"}))
            self._status(f"Received {filename} successfully.")
            if self.on_received:
                self.on_received(filename, self.save_dir)

        except Exception as e:
            self._status(f"Transfer failed: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, host=self.host, port=self.port)
        addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
        self._status(f"Listening securely on {addrs}")
        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None


class FileTransferClient:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.on_status = None
        self.on_progress = None
        self.on_verify_peer = None
        self.identity = DeviceIdentity()

    def _status(self, message: str):
        print(message)
        if self.on_status:
            self.on_status(message)

    def _progress(self, completed: int, total: int):
        if self.on_progress:
            self.on_progress(completed, total)

    async def send_file(self, filepaths: str | list[str]):
        paths = [filepaths] if isinstance(filepaths, str) else filepaths
        if not paths or not all(Path(path).exists() for path in paths):
            self._status("Selected file no longer exists.")
            return

        crypto = CryptoManager()
        encrypted_payload_path = f"py2py-{os.urandom(8).hex()}.sending.encrypted"

        self._status(f"Connecting to {self.target_ip}:{self.target_port}…")
        writer = None
        try:
            reader, writer = await asyncio.open_connection(self.target_ip, self.target_port)

            # 1. KEY EXCHANGE (ECDH)
            self._status("Establishing secure connection…")
            client_pub_key = crypto.get_public_key_bytes()
            await send_msg(writer, _encode_handshake("client", client_pub_key, self.identity))
            server_pub_key, server_identity_key = _decode_handshake(
                await recv_msg(reader), "server", client_pub_key
            )
            crypto.derive_shared_key(server_pub_key)
            self._status("Secure channel established.")
            # 2. PACK AND ENCRYPT (Local processing)
            metadata = await asyncio.to_thread(crypto.pack_and_encrypt, paths, encrypted_payload_path)

            # 3. SEND ENCRYPTED METADATA
            self._status("Preparing encrypted file…")
            encrypted_meta = crypto.encrypt_metadata(metadata)
            await send_msg(writer, encrypted_meta)
            if self.on_verify_peer:
                accepted = await self.on_verify_peer(
                    DeviceIdentity.fingerprint(server_identity_key),
                    _verification_code(crypto.shared_key),
                )
                if not accepted:
                    self._status("Peer verification cancelled by sender.")
                    return

            # 4. WAIT FOR RESPONSE
            encrypted_response = await recv_msg(reader)
            response_data = crypto.decrypt_metadata(encrypted_response)
            
            if response_data.get("status") != 'y':
                self._status("Receiver rejected the transfer.")
                os.remove(encrypted_payload_path)
                return
                
            self._status("Receiver accepted. Sending file…")

            # 5. STREAM ENCRYPTED DATA
            total_size = os.path.getsize(encrypted_payload_path)
            sent = 0
            self._progress(0, total_size)
            with open(encrypted_payload_path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    writer.write(chunk)
                    await writer.drain()
                    sent += len(chunk)
                    self._progress(sent, total_size)

            self._status("Upload complete. Waiting for receiver confirmation...")
            final_response = crypto.decrypt_metadata(await recv_msg(reader))
            if final_response.get("status") != "complete":
                raise ConnectionError("Receiver could not verify or unpack the transfer.")
            self._status("Transfer completed successfully on both devices.")

        except Exception as e:
            self._status(f"Connection failed: {e}")
        finally:
            if os.path.exists(encrypted_payload_path):
                os.remove(encrypted_payload_path)
            if writer:
                writer.close()
                await writer.wait_closed()

# --- CLI Test Block ---
async def main():
    import sys
    if len(sys.argv) < 2 or sys.argv[1] not in ['serve', 'send']:
        print("Usage: python core_network.py [serve|send] ...")
        sys.exit(1)

    if sys.argv[1] == 'serve':
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 35000
        server = FileTransferServer(port=port)
        await server.start()

    elif sys.argv[1] == 'send':
        ip, port, path = sys.argv[2], int(sys.argv[3]), sys.argv[4]
        client = FileTransferClient(ip, port)
        await client.send_file(path)

if __name__ == "__main__":
    asyncio.run(main())
