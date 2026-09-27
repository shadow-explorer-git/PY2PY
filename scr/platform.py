"""Cross-platform utilities for OS integration."""
from __future__ import annotations

import subprocess
import sys
import os
import shutil
import tempfile
from pathlib import Path


def open_folder(path: str | Path) -> bool:
    """Open the given folder in the system file manager.

    Returns True when the operation was dispatched, False on failure.
    """
    p = str(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(p)
            return True
        if sys.platform == "darwin":
            subprocess.run(["open", p], check=False)
            return True
        # Assume UNIX-like (Linux)
        try:
            subprocess.run(["xdg-open", p], check=False)
            return True
        except FileNotFoundError:
            return False
    except Exception:
        return False


def check_firewall_rules_windows(app_name: str = "PY2PY") -> bool:
    """
    Checks if the firewall rules for the app exist on Windows.
    Returns True if both TCP and UDP rules are present, False otherwise.
    """
    if not sys.platform.startswith("win"):
        return True  # Not applicable on other OSes

    rule_name_tcp = f"{app_name} TCP"
    rule_name_udp = f"{app_name} UDP (Discovery)"

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    check_tcp_cmd = f'netsh advfirewall firewall show rule name="{rule_name_tcp}"'
    tcp_exists = subprocess.run(
        check_tcp_cmd, shell=True, capture_output=True, check=False, startupinfo=startupinfo
    ).returncode == 0

    check_udp_cmd = f'netsh advfirewall firewall show rule name="{rule_name_udp}"'
    udp_exists = subprocess.run(
        check_udp_cmd, shell=True, capture_output=True, check=False, startupinfo=startupinfo
    ).returncode == 0

    return tcp_exists and udp_exists


def add_firewall_rule_windows(app_name: str = "PY2PY") -> None:
    """
    Executes commands to add firewall rules for the app on Windows,
    triggering a single UAC prompt if necessary.
    """
    if not sys.platform.startswith("win"):
        return

    import ctypes

    rule_name_tcp = f"{app_name} TCP"
    rule_name_udp = f"{app_name} UDP (Discovery)"
    # When packaged, sys.executable points to the .exe. When run from source, it's python.exe.
    # This is the correct behavior for program-based rules.
    executable_path = sys.executable

    # Use CREATE_NO_WINDOW to prevent flashing a console window during checks.
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    check_tcp_cmd = f'netsh advfirewall firewall show rule name="{rule_name_tcp}"'
    tcp_exists = subprocess.run(
        check_tcp_cmd, shell=True, capture_output=True, check=False, startupinfo=startupinfo
    ).returncode == 0

    check_udp_cmd = f'netsh advfirewall firewall show rule name="{rule_name_udp}"'
    udp_exists = subprocess.run(
        check_udp_cmd, shell=True, capture_output=True, check=False, startupinfo=startupinfo
    ).returncode == 0

    if tcp_exists and udp_exists:
        return

    commands_to_run = []
    if not tcp_exists:
        commands_to_run.append(
            f'netsh advfirewall firewall add rule name="{rule_name_tcp}" '
            f'dir=in action=allow protocol=TCP program="{executable_path}" enable=yes'
        )

    if not udp_exists:
        commands_to_run.append(
            f'netsh advfirewall firewall add rule name="{rule_name_udp}" '
            f'dir=in action=allow protocol=UDP localport=5353 program="{executable_path}" enable=yes'
        )

    if not commands_to_run:
        return

    # Create a temporary batch file to run all commands with a single UAC prompt.
    # The script will execute the netsh commands and then delete itself.
    script_content = "@echo off\n" + "\n".join(commands_to_run) + '\n(goto) 2>nul & del "%~f0"'

    temp_bat_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.bat', encoding='utf-8') as f:
            temp_bat_file = f.name
            f.write(script_content)

        # Execute the batch file with elevated privileges using the 'runas' verb.
        # This will trigger a single UAC prompt for all commands in the script.
        # The SW_HIDE (0) flag attempts to run the command window hidden.
        ctypes.windll.shell32.ShellExecuteW(None, "runas", temp_bat_file, None, None, 0)
    except Exception:
        # If creating or running the script fails, try to clean up.
        if temp_bat_file and os.path.exists(temp_bat_file):
            try:
                os.remove(temp_bat_file)
            except OSError:
                pass  # Can't do much if cleanup fails.


def check_firewall_linux(port: int) -> tuple[str, str | None]:
    """
    Checks for common Linux firewalls and determines if rules for the app are needed.

    Returns a tuple of (status, message).
    - status: 'not_needed', 'missing', 'unknown'
    - message: A command for the user to run, or an informational string.
    """
    if not sys.platform.startswith("linux"):
        return "not_needed", None

    discovery_port = 5353
    tcp_rule_found = False
    udp_rule_found = False

    # 1. Check for UFW (Uncomplicated Firewall)
    if shutil.which("ufw"):
        try:
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True, check=False, timeout=5)
            output = result.stdout.lower()

            if "inactive" in output:
                return "not_needed", "Firewall (ufw) is inactive."

            tcp_rule_found = f"{port}/tcp" in output and "allow" in output
            udp_rule_found = f"{discovery_port}/udp" in output and "allow" in output

            if tcp_rule_found and udp_rule_found:
                return "not_needed", None
            
            commands = []
            if not tcp_rule_found:
                commands.append(f"sudo ufw allow {port}/tcp")
            if not udp_rule_found:
                commands.append(f"sudo ufw allow {discovery_port}/udp")
            
            return "missing", " && ".join(commands)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # Fall through to check firewalld

    # 2. Check for firewalld
    if shutil.which("firewall-cmd"):
        try:
            state_result = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, check=False, timeout=5)
            if state_result.returncode != 0 or "not running" in state_result.stdout:
                return "not_needed", "Firewall (firewalld) is not running."

            result = subprocess.run(["firewall-cmd", "--list-ports", "--permanent"], capture_output=True, text=True, check=True, timeout=5)
            output = result.stdout
            tcp_rule_found = f"{port}/tcp" in output
            udp_rule_found = f"{discovery_port}/udp" in output

            if tcp_rule_found and udp_rule_found:
                return "not_needed", None

            commands = []
            if not tcp_rule_found:
                commands.append(f"sudo firewall-cmd --add-port={port}/tcp --permanent")
            if not udp_rule_found:
                commands.append(f"sudo firewall-cmd --add-port={discovery_port}/udp --permanent")
            commands.append("sudo firewall-cmd --reload")
            
            return "missing", " && ".join(commands)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass  # Fall through to the generic message

    # 3. Fallback
    return "unknown", f"Could not detect a known firewall (ufw, firewalld). Please ensure TCP port {port} and UDP port {discovery_port} are allowed for PY2PY to receive files."
