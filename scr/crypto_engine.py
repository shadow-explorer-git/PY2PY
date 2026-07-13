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

CHUNK_SIZE = 65536
NONCE_PREFIX_SIZE = 8
TAG_SIZE = 16
METADATA_AAD = b"PY2PY-metadata-v2"
PAYLOAD_AAD_PREFIX = b"PY2PY-payload-v2"

class CryptoManager:
    """Handles ECDH key exchange, message encryption, and stream encryption."""
    
    def __init__(self):
        self.shared_key = None
        # Generate a private Elliptic Curve key for this session
        self.private_key = ec.generate_private_key(ec.SECP384R1())

    def get_public_key_bytes(self) -> bytes:
        """Exports the public key to send to the peer."""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def derive_shared_key(self, peer_public_bytes: bytes):
        """Derives a 32-byte ChaCha20-Poly1305 key from the peer's public key."""
        peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Use HKDF to safely stretch the shared secret into a 32-byte AEAD key.
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'p2p_file_transfer'
        ).derive(shared_secret)

    def encrypt_metadata(self, metadata: dict) -> bytes:
        """Authenticates and encrypts JSON metadata with ChaCha20-Poly1305."""
        if not self.shared_key:
            raise ValueError("Shared key not established.")
            
        nonce = os.urandom(12)
        plaintext = json.dumps(metadata).encode('utf-8')
        ciphertext = ChaCha20Poly1305(self.shared_key).encrypt(nonce, plaintext, METADATA_AAD)
        return nonce + ciphertext

    def decrypt_metadata(self, encrypted_bytes: bytes) -> dict:
        """Authenticates and decrypts JSON metadata."""
        if not self.shared_key:
            raise ValueError("Shared key not established.")
            
        if len(encrypted_bytes) < 12 + TAG_SIZE:
            raise ValueError("Invalid encrypted metadata.")
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        plaintext = ChaCha20Poly1305(self.shared_key).decrypt(nonce, ciphertext, METADATA_AAD)
        return json.loads(plaintext.decode('utf-8'))

    def pack_and_encrypt(self, source_paths: str | list[str], encrypted_output: str) -> dict:
        """Packs one or more files/folders and encrypts them on the fly."""
        if not self.shared_key:
            raise ValueError("Shared key not established.")
            
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
        temp_tar = f"{encrypted_output}.tmp.tar"

        print(f"[*] Packaging {len(paths)} item(s) into tar...")
        with tarfile.open(temp_tar, "w") as tar:
            used_names = set()
            for path in paths:
                name = path.name
                base_name, suffix, number = name, "", 2
                while name.casefold() in used_names:
                    name = f"{base_name} ({number})"
                    number += 1
                used_names.add(name.casefold())
                tar.add(path, arcname=name, recursive=True)
            
        sha256_hash = hashlib.sha256()
        plaintext_size = os.path.getsize(temp_tar)
        chunk_count = (plaintext_size + CHUNK_SIZE - 1) // CHUNK_SIZE
        if chunk_count > 0xFFFFFFFF:
            raise ValueError("Transfer is too large for the authenticated chunk format.")
        encrypted_size = NONCE_PREFIX_SIZE + plaintext_size + (chunk_count * TAG_SIZE)
        nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
        aead = ChaCha20Poly1305(self.shared_key)
        
        print("[*] Encrypting payload...")
        with open(temp_tar, "rb") as f_in, open(encrypted_output, "wb") as f_out:
            f_out.write(nonce_prefix)
            counter = 0
            while chunk := f_in.read(CHUNK_SIZE):
                sha256_hash.update(chunk)
                nonce = nonce_prefix + struct.pack(">I", counter)
                aad = PAYLOAD_AAD_PREFIX + struct.pack(">I", counter)
                encrypted_chunk = aead.encrypt(nonce, chunk, aad)
                f_out.write(encrypted_chunk)
                counter += 1
                
        os.remove(temp_tar)
        return {
            "filename": f"{len(paths)} item(s)" if len(paths) > 1 else paths[0].name,
            "source_size": source_size,
            "hash": sha256_hash.hexdigest(),
            "encrypted_size": encrypted_size,
            "payload_plaintext_size": plaintext_size,
            "protocol_version": 2,
        }

    def decrypt_and_unpack(self, encrypted_input: str, dest_dir: str, expected_hash: str, plaintext_size: int):
        """Authenticates every payload chunk, then verifies and extracts it."""
        if plaintext_size < 0:
            raise ValueError("Invalid encrypted payload size.")
        temp_tar = f"{encrypted_input}.decrypted.tar"
        sha256_hash = hashlib.sha256()
        aead = ChaCha20Poly1305(self.shared_key)
        
        print("[*] Decrypting payload...")
        with open(encrypted_input, "rb") as f_in, open(temp_tar, "wb") as f_out:
            nonce_prefix = f_in.read(NONCE_PREFIX_SIZE)
            if len(nonce_prefix) != NONCE_PREFIX_SIZE:
                raise ValueError("Truncated encrypted payload.")
            remaining = plaintext_size
            counter = 0
            while remaining:
                plaintext_chunk_size = min(CHUNK_SIZE, remaining)
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
            tar.extractall(path=destination)
        os.remove(temp_tar)
