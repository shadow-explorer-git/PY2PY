import asyncio
import base64
import hashlib
import json
import socket
import struct
import os
import queue
import ipaddress
import tarfile
import uuid
from pathlib import Path
from .crypto_engine import CryptoManager, EncryptedTarStreamWriter, get_source_info, TAG_SIZE
from .identity import DeviceIdentity, IDENTITY_DIR
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .trust import add_trust, is_trusted, TRUST_FILE
from . import localization
from .config import get_config

MAX_MESSAGE_SIZE = 16 * 1024 * 1024
HANDSHAKE_DOMAIN = b"PY2PY-authenticated-handshake-v3"


def _encode_handshake(
    role: str,
    ephemeral_key: bytes,
    identity: DeviceIdentity,
    device_name: str,
    peer_key: bytes = b"",
    extra: bytes = b"",
) -> bytes:
    signed_data = HANDSHAKE_DOMAIN + role.encode("ascii") + peer_key + ephemeral_key + extra
    return json.dumps({
        "version": 3,
        "role": role,
        "device_name": device_name,
        "ephemeral_key": base64.b64encode(ephemeral_key).decode("ascii"),
        "identity_key": base64.b64encode(identity.public_bytes()).decode("ascii"),
        "signature": base64.b64encode(identity.sign(signed_data)).decode("ascii"),
        "extra": base64.b64encode(extra).decode("ascii"),
    }).encode("utf-8")


def _decode_handshake(payload: bytes, expected_role: str, peer_key: bytes = b"") -> tuple[bytes, bytes, bytes, str]:
    try:
        data = json.loads(payload.decode("utf-8"))
        if data.get("version") != 3 or data.get("role") != expected_role:
            raise ValueError("Unsupported handshake protocol.")
        device_name = data.get("device_name", "Unknown Device")
        ephemeral_key = base64.b64decode(data["ephemeral_key"], validate=True)
        identity_key = base64.b64decode(data["identity_key"], validate=True)
        signature = base64.b64decode(data["signature"], validate=True)
        extra = base64.b64decode(data.get("extra", ""), validate=True)
        if len(identity_key) != 32:
            raise ValueError("Invalid peer identity key.")
        signed_data = HANDSHAKE_DOMAIN + expected_role.encode("ascii") + peer_key + ephemeral_key + extra
        Ed25519PublicKey.from_public_bytes(identity_key).verify(signature, signed_data)
        return ephemeral_key, identity_key, extra, device_name
    except (KeyError, ValueError, TypeError, InvalidSignature) as error:
        raise ValueError("Peer identity signature verification failed.") from error


def _verification_code(shared_key: bytes) -> str:
    value = int.from_bytes(hashlib.sha256(b"PY2PY-SAS-v3" + shared_key).digest()[:4], "big")
    return f"{value % 10_000_000_000:010d}"


def _encode_trust_update(peer_fingerprint: str, trusted: bool) -> bytes:
    return json.dumps({
        "type": "trust_update",
        "peer_fingerprint": peer_fingerprint,
        "trusted": trusted,
    }).encode("utf-8")


def _decode_trust_update(payload: bytes) -> dict | None:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("type") != "trust_update":
        return None
    peer_fingerprint = data.get("peer_fingerprint")
    trusted = data.get("trusted")
    if not isinstance(peer_fingerprint, str) or not isinstance(trusted, bool):
        return None
    return {"peer_fingerprint": peer_fingerprint, "trusted": trusted}


def _encode_kem_ciphertext(
    ciphertext: bytes,
    identity: DeviceIdentity,
    client_key: bytes,
    server_key: bytes,
    kem_public_key: bytes,
) -> bytes:
    signed_data = HANDSHAKE_DOMAIN + b"mlkem768" + client_key + server_key + kem_public_key + ciphertext
    return json.dumps({
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "signature": base64.b64encode(identity.sign(signed_data)).decode("ascii"),
    }).encode("utf-8")


def _decode_kem_ciphertext(
    payload: bytes,
    identity_key: bytes,
    client_key: bytes,
    server_key: bytes,
    kem_public_key: bytes,
) -> bytes:
    try:
        data = json.loads(payload.decode("utf-8"))
        ciphertext = base64.b64decode(data["ciphertext"], validate=True)
        signature = base64.b64decode(data["signature"], validate=True)
        signed_data = HANDSHAKE_DOMAIN + b"mlkem768" + client_key + server_key + kem_public_key + ciphertext
        Ed25519PublicKey.from_public_bytes(identity_key).verify(signature, signed_data)
        return ciphertext
    except (KeyError, ValueError, TypeError, InvalidSignature) as error:
        raise ValueError("ML-KEM ciphertext signature verification failed.") from error


async def send_msg(writer: asyncio.StreamWriter, data: bytes):
    """Helper to send length-prefixed binary data."""
    writer.write(struct.pack('>I', len(data)))
    writer.write(data)
    await writer.drain()


async def recv_msg(reader: asyncio.StreamReader, timeout: float = 30.0) -> bytes:
    """Helper to receive length-prefixed binary data with an explicit network timeout window."""
    try:
        length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    except asyncio.TimeoutError:
        raise TimeoutError("Network read timed out waiting for message length header.")
        
    length = struct.unpack('>I', length_bytes)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large.")
        
    try:
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    except asyncio.TimeoutError:
        raise TimeoutError("Network read timed out waiting for message body payload.")


class FileTransferServer:
    def __init__(self, port: int, host: str | None = None):
        self.port = port
        self.host = host
        self.server = None
        self.started_event = asyncio.Event()
        self.startup_exception: Exception | None = None
        self.on_status = None
        self.on_request_permission = None
        self.identity = DeviceIdentity()
        self.on_progress = None
        self.on_received = None
        self.on_transfer_start = None
        self.on_transfer_end = None

    def _status(self, key: str, **kwargs):
        if self.on_status:
            # self.on_status is set to ui.set_status_localized
            self.on_status(key, **kwargs)
        else:
            # Fallback for CLI usage or if on_status is not set
            message = localization.get_string(key).format(**kwargs)
            print(message)

    def _progress(self, completed: int, total: int):
        if self.on_progress: self.on_progress(completed, total)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        peer_ip = addr[0]
        self._status("status_incoming_connection", ip=peer_ip)

        encrypted_payload_path = None
        task = asyncio.current_task()
        if self.on_transfer_start:
            self.on_transfer_start(task)

        # FIREWALL: Initial IP-based check
        config = get_config()
        firewall_config = config.get("firewall", {})
        firewall_mode = firewall_config.get("mode", "lan_only")
        crypto = CryptoManager()

        if firewall_mode == "lan_only":
            try:
                ip_obj = ipaddress.ip_address(peer_ip)
                if ip_obj.is_global:
                    self._status("status_blocked_public_ip", ip=peer_ip)
                    writer.close()
                    await writer.wait_closed()
                    return
            except ValueError:  # Handle cases where peer_ip is not a valid IP address string
                self._status("status_blocked_invalid_ip", ip=peer_ip)
                writer.close()
                await writer.wait_closed()
                return

        try: # Main try block for handle_client
            # 1. KEY EXCHANGE (ECDH)
            self._status("status_establishing_secure_connection")
            client_pub_key, client_identity_key, _, client_name = _decode_handshake(
                await recv_msg(reader), "client"
            )
            server_pub_key = crypto.get_public_key_bytes()
            mlkem_private_key = MLKEM768PrivateKey.generate()
            mlkem_public_key = mlkem_private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            device_name = socket.gethostname() or "Receiver"
            await send_msg(writer, _encode_handshake(
                "server", server_pub_key, self.identity, device_name, client_pub_key, mlkem_public_key
            ))
            kem_ciphertext = _decode_kem_ciphertext(
                await recv_msg(reader),
                client_identity_key,
                client_pub_key,
                server_pub_key,
                mlkem_public_key,
            )
            crypto.derive_shared_key(client_pub_key, mlkem_private_key.decapsulate(kem_ciphertext)) # This is the KEM decapsulation
            self._status("status_secure_channel_established")

            fingerprint = DeviceIdentity.fingerprint(client_identity_key)

            # FIREWALL: Post-handshake check for high security mode
            if firewall_mode == "high_security":
                is_whitelisted = peer_ip in firewall_config.get("whitelist", [])
                if not is_trusted(fingerprint) and not is_whitelisted:
                    self._status("status_blocked_high_security", ip=peer_ip, fp=fingerprint)
                    writer.close()
                    await writer.wait_closed()
                    return

            # 2. RECEIVE ENCRYPTED METADATA
            encrypted_meta = await recv_msg(reader)
            metadata = crypto.decrypt_metadata(encrypted_meta)
            
            protocol_version = metadata.get("protocol_version", 2)
            filename = metadata.get('filename')
            if not filename:
                raise ValueError("Filename missing from transfer metadata.")

            if protocol_version >= 3:
                source_size = metadata.get('source_size')
                if not isinstance(source_size, int):
                    raise ValueError("Invalid or missing source_size for v3 protocol.")
                file_hash = None  # Received at the end for v3
                payload_plaintext_size = None # Received at the end for v3
            elif protocol_version == 2:
                file_hash = metadata['hash']
                encrypted_size = metadata['encrypted_size']
                source_size = metadata.get('source_size', encrypted_size)
                payload_plaintext_size = metadata.get('payload_plaintext_size')
                if not isinstance(payload_plaintext_size, int):
                    raise ValueError("Invalid payload_plaintext_size for v2 protocol.")
            else:
                raise ValueError(f"Unsupported protocol version: {protocol_version}")
            
            receiver_fingerprint = DeviceIdentity.fingerprint(self.identity.public_bytes())
            receiver_trusts_sender = is_trusted(fingerprint)
            
            # The trust update is part of the response in the new protocol
            response_payload = {"status": "y"}
            if metadata.get("protocol_version", 2) >= 3:
                response_payload["trust_update"] = {"peer_fingerprint": receiver_fingerprint, "trusted": receiver_trusts_sender}
            else:
                await send_msg(writer, _encode_trust_update(receiver_fingerprint, receiver_trusts_sender))

            if self.on_request_permission:
               response, custom_path = await self.on_request_permission(
                   filename,
                   source_size,
                   fingerprint,
                   client_name,
                   _verification_code(crypto.shared_key),
               )
            else:
                prompt = f"Accept '{filename}'? (y/n): "
                response = await asyncio.to_thread(input, prompt)
                custom_path = None
            
            # Send encrypted response
            response_payload["status"] = response.strip().lower()
            encrypted_response = crypto.encrypt_metadata(response_payload)
            await send_msg(writer, encrypted_response)
            
            if response.strip().lower() != 'y':
                self._status("status_transfer_rejected")
                return

            if custom_path:
                save_dir = Path(custom_path)
            else:
                save_dir = Path(get_config()["receive"]["location"])
            save_dir.mkdir(parents=True, exist_ok=True)

            encrypted_payload_path = save_dir / f".py2py-{uuid.uuid4().hex}.encrypted"
            self._status("status_receiving_file", filename=filename)

            # 4. RECEIVE ENCRYPTED STREAM
            if metadata.get("protocol_version", 2) >= 3:
                # Protocol v3: Streaming with length-prefixed chunks
                with open(encrypted_payload_path, "wb") as f:
                    nonce_prefix = await reader.readexactly(8)
                    await asyncio.to_thread(f.write, nonce_prefix)

                    received_encrypted_bytes = 0
                    chunks_received = 0
                    # The total is the source file size, the completed part is an estimate
                    # of the plaintext bytes received so far.
                    self._progress(0, source_size)
                    while True:
                        len_bytes = await reader.readexactly(4)
                        chunk_len = struct.unpack('>I', len_bytes)[0]
                        if chunk_len == 0:
                            break

                        chunk = await reader.readexactly(chunk_len)
                        await asyncio.to_thread(f.write, chunk)

                        received_encrypted_bytes += chunk_len
                        chunks_received += 1

                        # Estimate plaintext received by subtracting overhead.
                        # This is more accurate for the progress bar than comparing encrypted bytes to source size.
                        estimated_plaintext_received = received_encrypted_bytes - (chunks_received * TAG_SIZE)
                        self._progress(min(estimated_plaintext_received, source_size), source_size)

                final_meta_encrypted = await recv_msg(reader)
                final_meta = crypto.decrypt_metadata(final_meta_encrypted)
                file_hash = final_meta['hash']
                payload_plaintext_size = final_meta['payload_plaintext_size']

            else:
                # Protocol v2: Fixed-size payload
                chunk_size = get_config()["network"]["chunk_size"]
                received = 0
                self._progress(0, encrypted_size)
                with open(encrypted_payload_path, "wb") as f:
                    while received < encrypted_size:
                        try:
                            chunk = await asyncio.wait_for(
                                reader.read(min(chunk_size, encrypted_size - received)),
                                timeout=30.0
                            )
                        except asyncio.TimeoutError:
                            raise TimeoutError("Network link went silent during stream transfer extraction.")
                            
                        if not chunk:
                            break
                        await asyncio.to_thread(f.write, chunk)
                        received += len(chunk)
                        self._progress(received, encrypted_size)

                if received != encrypted_size:
                    raise ConnectionError("Transfer ended before all data was received.")

            # 5. DECRYPT AND UNPACK
            self._status("status_verifying_unpacking")
            try:
                await asyncio.to_thread(
                    crypto.decrypt_and_unpack,
                    str(encrypted_payload_path),
                    str(save_dir),
                    file_hash,
                    payload_plaintext_size,
                )
            except Exception:
                # Ensure we try to clean up even if decryption fails
                if encrypted_payload_path.exists():
                    os.remove(encrypted_payload_path)
                raise

            os.remove(encrypted_payload_path)
            encrypted_payload_path = None

            # Send final confirmation
            try:
                await send_msg(writer, crypto.encrypt_metadata({"status": "complete"}))
            except (ConnectionError, BrokenPipeError):
                # Client may have already closed the connection, which is fine. This is normal.
                self._status("status_client_disconnected_normal")
                pass

            self._status("status_received_successfully", filename=filename)
            if self.on_received:
                self.on_received(filename, save_dir)

        except asyncio.CancelledError:
            self._status("status_transfer_cancelled_by_user")
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
            self._status("status_transfer_cancelled")
        except Exception as e:
            self._status("status_transfer_failed", error=e)
        finally:
            if encrypted_payload_path and encrypted_payload_path.exists():
                try:
                    os.remove(encrypted_payload_path)
                except Exception:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, ConnectionAbortedError):
                pass  # Expected if the connection is abruptly closed during cancellation.
            if self.on_transfer_end:
                self.on_transfer_end()

    async def start(self):
        try:
            self.server = await asyncio.start_server(self.handle_client, host=self.host, port=self.port)
            addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
            self._status("status_listening_securely_on", addrs=addrs)
            self.started_event.set()
            async with self.server:
                await self.server.serve_forever()
        except Exception as e:
            self.startup_exception = e
            self.started_event.set() # Wake up any waiters

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        
        # Reset state for potential restart
        self.started_event.clear()
        self.startup_exception = None


class FileTransferClient:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.on_status = None
        self.on_progress = None
        self.on_verify_peer = None
        self.identity = DeviceIdentity()

    def _status(self, key: str, **kwargs):
        if self.on_status:
            self.on_status(key, **kwargs)
        else:
            # Fallback for CLI usage or if on_status is not set
            message = localization.get_string(key).format(**kwargs)
            print(message)

    def _progress(self, completed: int, total: int):
        if self.on_progress:
            self.on_progress(completed, total)

    async def send_file(self, filepaths: str | list[str]):
        crypto = CryptoManager()
        try:
            paths, source_size, filename = await asyncio.to_thread(get_source_info, filepaths)
        except (ValueError, FileNotFoundError) as e:
            self._status("status_transfer_failed", error=str(e))
            return

        writer = None
        try: # Main try block for send_file
            # Wrap connection attempt in wait_for to prevent long hangs if peer is offline
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, self.target_port),
                timeout=15.0
            )

            # 1. KEY EXCHANGE (ECDH)
            self._status("status_establishing_secure_connection")
            client_pub_key = crypto.get_public_key_bytes()
            device_name = socket.gethostname() or "Sender"
            await send_msg(writer, _encode_handshake("client", client_pub_key, self.identity, device_name))
            server_pub_key, server_identity_key, mlkem_public_key, server_name = _decode_handshake(
                await recv_msg(reader), "server", client_pub_key
            )
            mlkem_peer_key = MLKEM768PublicKey.from_public_bytes(mlkem_public_key)
            pq_shared_secret, kem_ciphertext = mlkem_peer_key.encapsulate()
            await send_msg(writer, _encode_kem_ciphertext(
                kem_ciphertext,
                self.identity,
                client_pub_key,
                server_pub_key,
                mlkem_public_key,
            ))
            crypto.derive_shared_key(server_pub_key, pq_shared_secret)
            self._status("status_secure_channel_established")
            
            # 2. SEND INITIAL METADATA
            self._status("status_preparing_transfer")
            metadata = {
                "filename": filename,
                "source_size": source_size,
                "protocol_version": 3,
            }
            encrypted_meta = crypto.encrypt_metadata(metadata)
            await send_msg(writer, encrypted_meta)

            # 3. WAIT FOR RESPONSE (contains trust info in v3)
            # PATCH: Mărit timeout-ul la 300 secunde pentru a împiedica deconectarea clientului în timp ce partenerul acceptă dialogul GUI
            encrypted_response = await recv_msg(reader, timeout=300.0)
            response_data = crypto.decrypt_metadata(encrypted_response)
            
            if response_data.get("trust_update", {}).get("trusted"):
                server_fingerprint = response_data["trust_update"]["peer_fingerprint"]
                add_trust(server_fingerprint, server_name)
                self._status("status_trusted_receiver")

            if self.on_verify_peer:
                accepted = await self.on_verify_peer(
                    DeviceIdentity.fingerprint(server_identity_key),
                    server_name,
                    _verification_code(crypto.shared_key),
                )
                if not accepted:
                    self._status("status_transfer_cancelled_by_user")
                    return

            if response_data.get("status") != 'y':
                self._status("status_transfer_rejected")
                return
                
            # 4. STREAM ENCRYPTED DATA
            def producer_thread(q_out, crypto_manager, source_paths_list, total_size):
                class QueueWriter:
                    def __init__(self, q): self.q = q
                    def write(self, b):
                        # b is a tuple: (encrypted_chunk, plaintext_chunk_size)
                        self.q.put(b)
                        # Return the plaintext size, which is what tarfile's caller would have "written"
                        return b[1]
                    def flush(self): pass

                try:
                    queue_writer = QueueWriter(q_out)
                    nonce_prefix = os.urandom(8)
                    stream_writer = EncryptedTarStreamWriter(queue_writer, crypto_manager.payload_key, nonce_prefix)

                    # The first item on the queue is the nonce prefix, for the consumer.
                    q_out.put(nonce_prefix)

                    with tarfile.open(fileobj=stream_writer, mode="w") as tar:
                        # To provide a smoother progress bar, we manually walk the paths,
                        # sort the files by size (largest first), and add them individually.
                        # This prevents the progress bar from jumping wildly when processing many small files.
                        items_to_add = []
                        top_level_used_names = set()
                        for p_obj in source_paths_list:
                            arc_base_name = p_obj.name
                            name = arc_base_name
                            number = 2
                            while name.casefold() in top_level_used_names:
                                name = f"{arc_base_name} ({number})"
                                number += 1
                            top_level_used_names.add(name.casefold())

                            items_to_add.append((p_obj, name))
                            if p_obj.is_dir():
                                for child in sorted(p_obj.rglob("*")):
                                    relative_path = child.relative_to(p_obj)
                                    arc_path = str(Path(name) / relative_path)
                                    items_to_add.append((child, arc_path))

                        files = [(p, a, p.stat().st_size) for p, a in items_to_add if p.is_file()]
                        dirs = [(p, a) for p, a in items_to_add if p.is_dir()]
                        
                        files.sort(key=lambda x: x[2], reverse=True)

                        for path, arcname in dirs:
                            tar.add(path, arcname=arcname, recursive=False)
                        for path, arcname, _ in files:
                            tar.add(path, arcname=arcname, recursive=False)

                    stream_writer.close()
                    return {"hash": stream_writer.sha256_hash.hexdigest(), "payload_plaintext_size": stream_writer.plaintext_size}
                except Exception as e:
                    q_out.put(e)
                finally:
                    q_out.put(None)

            # Use a small queue size to prevent the producer (file reader) from running too far ahead
            # of the consumer (network writer). A large buffer causes jerky progress bar updates,
            # as the producer fills the buffer in a quick burst and then waits a long time for the
            # network to catch up. A smaller size paces the producer to the network speed.
            q = queue.Queue(maxsize=2)
            loop = asyncio.get_running_loop()
            # The producer thread no longer reports progress. It just produces data.
            producer = loop.run_in_executor(None, producer_thread, q, crypto, paths, source_size)

            # The first item from the producer is the nonce prefix.
            nonce_prefix = await loop.run_in_executor(None, q.get)
            if isinstance(nonce_prefix, Exception): raise nonce_prefix
            writer.write(nonce_prefix)
            
            # Progress is now reported here in the consumer loop, which reflects network speed.
            bytes_sent = 0
            self._progress(0, source_size)

            while True:
                # Subsequent items are (encrypted_chunk, plaintext_size) tuples or None.
                item = await loop.run_in_executor(None, q.get)
                if item is None: break
                if isinstance(item, Exception): raise item
                
                encrypted_chunk, plaintext_chunk_size = item

                writer.write(struct.pack('>I', len(encrypted_chunk)))
                writer.write(encrypted_chunk)
                await writer.drain()

                bytes_sent += plaintext_chunk_size
                # Cap the progress at the total source size to prevent the UI from showing >100% due to tar overhead.
                self._progress(min(bytes_sent, source_size), source_size)
            
            writer.write(struct.pack('>I', 0))
            await writer.drain()
            final_meta = await producer

            self._status("status_verifying_unpacking")
            await send_msg(writer, crypto.encrypt_metadata(final_meta))
            final_response = crypto.decrypt_metadata(await recv_msg(reader))
            if final_response.get("status") != "complete":
                raise ConnectionError("Receiver could not verify or unpack the transfer.")
            self._status("status_received_successfully", filename=filename)

        except asyncio.CancelledError:
            self._status("status_transfer_cancelled_by_user")
            raise
        except asyncio.TimeoutError: # From wait_for(open_connection)
            self._status("status_peer_offline", ip=self.target_ip, port=self.target_port)
        except (ConnectionError, asyncio.IncompleteReadError, TimeoutError): # TimeoutError from recv_msg
            self._status("status_transfer_cancelled") # Generic cancellation
        except Exception as e:
            self._status("status_transfer_failed", error=e)
        finally:
            if writer:
                writer.close()
                try:
                    # Add a timeout to wait_closed to prevent hanging on unclean shutdown
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except (ConnectionResetError, ConnectionAbortedError, asyncio.TimeoutError):
                    # This is expected if the other side closes the connection abruptly,
                    # or if we time out waiting for a clean close. We tried our best.
                    pass


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
