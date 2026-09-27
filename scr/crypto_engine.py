import os
import json
import struct
import tarfile
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .config import get_config

NONCE_PREFIX_SIZE = 8
TAG_SIZE = 16
METADATA_AAD = b"PY2PY-metadata-v2"
PAYLOAD_AAD_PREFIX = b"PY2PY-payload-v2"


def get_source_info(source_paths: str | list[str]) -> tuple[list[Path], int, str]:
    """Validates paths, calculates total size, and determines a display name."""
    paths = [Path(source_paths)] if isinstance(source_paths, str) else [Path(p) for p in source_paths]
    if not paths:
        raise ValueError("No files or folders were selected.")
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"Selected item does not exist: {path}")
        if path.is_symlink() or (path.is_dir() and any(p.is_symlink() for p in path.rglob("*"))):
            raise ValueError("Symbolic links are not allowed in transfers.")

    source_size = sum(
        item.stat().st_size
        for path in paths
        for item in ([path] if path.is_file() else path.rglob("*"))
        if item.is_file()
    )
    filename = f"{len(paths)} item(s)" if len(paths) > 1 else paths[0].name
    return paths, source_size, filename

class EncryptedTarStreamWriter:
    """A file-like object that intercepts plaintext tar bytes, packs them into fixed chunks, 

    encrypts them on-the-fly, and writes them directly to the output destination file descriptor.
    """
    
    def __init__(self, f_out, payload_key: bytes, nonce_prefix: bytes):
        self.f_out = f_out
        self.payload_key = payload_key
        self.nonce_prefix = nonce_prefix
        self.aead = ChaCha20Poly1305(payload_key)
        self.buffer = bytearray()
        self.counter = 0
        self.sha256_hash = hashlib.sha256()
        self.plaintext_size = 0
        # Use configurable chunk size for performance tuning
        self.chunk_size = get_config()["network"]["chunk_size"]
        
    def write(self, b: bytes) -> int:
        self.buffer.extend(b)
        while len(self.buffer) >= self.chunk_size:
            chunk = bytes(self.buffer[:self.chunk_size])
            del self.buffer[:self.chunk_size]
            self._encrypt_and_write_chunk(chunk)
        return len(b)
    
    def tell(self) -> int:
        return self.plaintext_size + len(self.buffer)

    def _encrypt_and_write_chunk(self, chunk: bytes):
        self.sha256_hash.update(chunk)
        self.plaintext_size += len(chunk)
        
        nonce = self.nonce_prefix + struct.pack(">I", self.counter)
        aad = PAYLOAD_AAD_PREFIX + struct.pack(">I", self.counter)
        encrypted_chunk = self.aead.encrypt(nonce, chunk, aad)
        # Pass a tuple of (encrypted_bytes, plaintext_bytes_size) to the underlying writer.
        self.f_out.write((encrypted_chunk, len(chunk)))
        self.counter += 1

    def flush(self):
        pass

    def close(self):
        if self.buffer:
            chunk = bytes(self.buffer)
            self.buffer.clear()
            self._encrypt_and_write_chunk(chunk)


class CryptoManager:
    def __init__(self):
        self.shared_key = None
        self.metadata_key = None
        self.payload_key = None
        self.private_key = ec.generate_private_key(ec.SECP384R1())

    def get_public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_key(self, peer_public_bytes: bytes, pq_shared_secret: bytes | None = None):
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        ecdh_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        if pq_shared_secret is not None and len(pq_shared_secret) != 32:
            raise ValueError("Invalid ML-KEM shared secret.")

        ikm = ecdh_secret + (pq_shared_secret or b"")

        try:
            local_pub = self.get_public_key_bytes()
        except Exception:
            local_pub = b""
        a_pub, b_pub = (local_pub, peer_public_bytes) if local_pub <= peer_public_bytes else (peer_public_bytes, local_pub)
        salt = hashlib.sha256(b"PY2PY-HKDF-salt-v1" + a_pub + b_pub).digest()

        key_material = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=salt,
            info=b'p2p_file_transfer|hybrid-v1'
        ).derive(ikm)
        self.metadata_key = key_material[:32]
        self.payload_key = key_material[32:]
        self.shared_key = key_material

    def encrypt_metadata(self, metadata: dict) -> bytes:
        if not self.metadata_key:
            raise ValueError("Shared key not established.")
            
        nonce = os.urandom(12)
        plaintext = json.dumps(metadata).encode('utf-8')
        ciphertext = ChaCha20Poly1305(self.metadata_key).encrypt(nonce, plaintext, METADATA_AAD)
        return nonce + ciphertext

    def decrypt_metadata(self, encrypted_bytes: bytes) -> dict:
        if not self.metadata_key:
            raise ValueError("Shared key not established.")
            
        if len(encrypted_bytes) < 12 + TAG_SIZE:
            raise ValueError("Invalid encrypted metadata.")
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        plaintext = ChaCha20Poly1305(self.metadata_key).decrypt(nonce, ciphertext, METADATA_AAD)
        return json.loads(plaintext.decode('utf-8'))

    def pack_and_encrypt(self, source_paths: str | list[str], encrypted_output: str) -> dict:
        if not self.payload_key:
            raise ValueError("Shared key not established.")
            
        paths, source_size, filename = get_source_info(source_paths)

        output_dir = Path(encrypted_output).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
        
        print("[*] Packaging and encrypting archive payload stream on-the-fly...")
        with open(encrypted_output, "wb") as f_out:
            stream_writer = EncryptedTarStreamWriter(f_out, self.payload_key, nonce_prefix)
            
            with tarfile.open(fileobj=stream_writer, mode="w") as tar:
                used_names = set()
                for path in paths:
                    name = path.name
                    base_name, suffix, number = name, "", 2
                    while name.casefold() in used_names:
                        name = f"{base_name} ({number})"
                        number += 1
                    used_names.add(name.casefold())
                    tar.add(path, arcname=name, recursive=True)
                    
            stream_writer.close()

        chunk_count = stream_writer.counter
        plaintext_size = stream_writer.plaintext_size
        encrypted_size = NONCE_PREFIX_SIZE + plaintext_size + (chunk_count * TAG_SIZE)
        
        if chunk_count > 0xFFFFFFFF:
            raise ValueError("Transfer is too large for the authenticated chunk format.")

        return {
            "filename": filename,
            "source_size": source_size,
            "hash": stream_writer.sha256_hash.hexdigest(),
            "encrypted_size": encrypted_size,
            "payload_plaintext_size": plaintext_size,
            "protocol_version": 2,
        }

    def decrypt_and_unpack(self, encrypted_input: str, dest_dir: str, expected_hash: str, plaintext_size: int):
        if plaintext_size < 0:
            raise ValueError("Invalid encrypted payload size.")
        temp_tar = f"{encrypted_input}.decrypted.tar"
        sha256_hash = hashlib.sha256()
        if not self.payload_key:
            raise ValueError("Shared key not established.")
        aead = ChaCha20Poly1305(self.payload_key)
        chunk_size = get_config()["network"]["chunk_size"]
        
        print("[*] Decrypting payload...")
        with open(encrypted_input, "rb") as f_in, open(temp_tar, "wb") as f_out:
            nonce_prefix = f_in.read(NONCE_PREFIX_SIZE)
            if len(nonce_prefix) != NONCE_PREFIX_SIZE:
                raise ValueError("Truncated encrypted payload.")
            remaining = plaintext_size
            counter = 0
            while remaining:
                plaintext_chunk_size = min(chunk_size, remaining)
                encrypted_chunk = f_in.read(plaintext_chunk_size + TAG_SIZE)
                if len(encrypted_chunk) != plaintext_chunk_size + TAG_SIZE:
                    raise ValueError("Truncated encrypted payload.")
                nonce = nonce_prefix + struct.pack(">I", counter)
                aad = PAYLOAD_AAD_PREFIX + struct.pack(">I", counter)
                decrypted_chunk = aead.decrypt(nonce, encrypted_chunk, aad)
                sha256_hash.update(decrypted_chunk)
                f_out.write(decrypted_chunk)
                remaining -= plaintext_chunk_size
                counter += 1
            if f_in.read(1):
                raise ValueError("Unexpected data after encrypted payload.")
        actual_hash = sha256_hash.hexdigest()
        if actual_hash != expected_hash:
            os.remove(temp_tar)
            raise ValueError("Hash mismatch! File corrupted or tampered with.")
            
        print("[*] Unpacking...")
        with tarfile.open(temp_tar, "r") as tar:
            destination = Path(dest_dir).resolve()
            for member in tar.getmembers():
                member_path = (destination / member.name).resolve()
                if not member_path.is_relative_to(destination) or member.issym() or member.islnk():
                    raise ValueError("Unsafe archive content rejected.")
            
            # PATCH: Adăugarea filtrului securizat nativ introdus în Python 3.12+ împotriva vulnerabilităților de Path Traversal
            if hasattr(tarfile, "data_filter"):
                tar.extractall(path=destination, filter='data')
            else:
                tar.extractall(path=destination)
        os.remove(temp_tar)
