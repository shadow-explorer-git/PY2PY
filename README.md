# PY2PY

PY2PY is a local-network file sharing application built with Python and Flet. It discovers receiving devices on the selected LAN interface and transfers one or more files or folders after the receiver explicitly accepts the transfer.

## What it does

- Sends one or more files and folders as one transfer.
- Discovers receivers on the local network with mDNS/Zeroconf.
- Lets the user choose a network interface or provide a local IPv4 address manually.
- Shows the incoming transfer name and size before accepting it.
- Shows progress on both sender and receiver.
- Verifies, decrypts, and extracts received content to `received_files`.
- Shows a completion dialog and can open the receiving folder.

## Run from source

Python 3.10 or newer is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

On macOS/Linux, activate or invoke the virtual environment with the platform-appropriate path.

## How to transfer a file

1. On the receiving device, open **Receive files**.
2. Select the LAN interface that connects both devices, then press **Start receiving**.
3. On the sending device, open **Send a file**, choose the same LAN interface, and wait for the receiver to appear.
4. Add files and/or folders, then press **Send** next to the receiver.
5. Accept or reject the transfer on the receiving device.

Both devices must be on the same reachable local network. Firewall software may need permission for the application and TCP port `35000`.

## Security model and limitations

PY2PY generates a new ECDH P-384 key pair for each transfer and derives a session key with HKDF-SHA256. Metadata is authenticated and encrypted with ChaCha20-Poly1305. The file archive is encrypted in streaming chunks, each authenticated with its own unique ChaCha20-Poly1305 nonce and tag. This detects modification, truncation, reordering, and forged metadata before content is accepted. The receiver also verifies a SHA-256 hash of the complete decrypted archive before extraction. The app rejects symbolic links and checks archive paths before extraction to reduce archive path-traversal risk.

Each device also creates a persistent Ed25519 signing identity in its user profile. It signs the ephemeral ECDH handshake and the app shows both users the same ten-digit verification code. Compare this code through a trusted side channel (for example, in person or by phone) before accepting a transfer. If a man-in-the-middle creates two separate sessions, the two users will see different codes. The displayed identity fingerprint can be recorded to recognize a device later.

Important: users must compare the verification code for this protection against an active network attacker to be effective. Automatic trust/certificate management is not yet implemented; do not accept a transfer when the codes differ or cannot be compared.

Device discovery is visible to other devices on the selected LAN. Only accept transfers from people and devices you trust.

## Build a Windows one-file executable

The repository can be packaged as a single Windows executable with Flet/PyInstaller:

```powershell
.\.venv\Scripts\python.exe -m pip install pyinstaller
.\.venv\Scripts\flet.exe pack main.py -n PY2PY --distpath dist -y
```

The output is `dist\PY2PY.exe`. Build Windows releases on Windows, macOS releases on macOS, and Linux releases on Linux.
