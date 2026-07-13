import asyncio
import ipaddress
import socket
from pathlib import Path

import flet as ft

from .core_network import FileTransferClient, FileTransferServer
from .discovery import ReceiverAnnouncer, SenderScanner, get_local_interfaces


PORT = 35000


def main(page: ft.Page):
    page.window.icon = "/final.ico"
    page.title = "PY2PY — Secure file sharing"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 24
    page.window.width = 850
    page.window.height = 720
    page.window.min_width = 650
    page.window.min_height = 500
    

    selected_paths: list[str] = []
    scanner: SenderScanner | None = None
    announcer: ReceiverAnnouncer | None = None
    server: FileTransferServer | None = None
    server_task: asyncio.Task | None = None
    devices: dict[str, tuple[str, int]] = {}

    status = ft.Text("Ready", color=ft.Colors.GREY_400)
    send_progress_label = ft.Text("", color=ft.Colors.GREY_400)
    send_progress = ft.ProgressBar(value=0, visible=False)
    receive_progress_label = ft.Text("", color=ft.Colors.GREY_400)
    receive_progress = ft.ProgressBar(value=0, visible=False)
    selected_file = ft.Text("No files or folders selected", color=ft.Colors.GREY_400)
    device_list = ft.ListView(
        spacing=6,
        padding=8,
        scroll=ft.ScrollMode.ALWAYS,
    )
    lan_options = get_local_interfaces()

    def show_manual_ip_help(_):
        dialog = ft.AlertDialog(
            title=ft.Text("Choosing a custom LAN IP"),
            content=ft.Column([
                ft.Text("Normally, leave this field empty and select an interface from the list."),
                ft.Text("Use a custom IP only when the needed adapter is missing from the list, such as a VPN, USB Ethernet adapter, or a manually configured network."),
                ft.Text("Enter the IPv4 address assigned to that adapter — for example 192.168.1.25 — not the router address and not a public IP address."),
            ], tight=True, spacing=10),
            actions=[ft.TextButton("Got it", on_click=lambda _: page.pop_dialog())],
        )
        page.show_dialog(dialog)

    def interface_dropdown():
        return ft.Dropdown(
        label="Network interface",
        value=lan_options[0][1],
        options=[
            ft.DropdownOption(
                key=ip,
                text=name,
                content=ft.Column([
                    ft.Text(name, weight=ft.FontWeight.BOLD),
                    ft.Text(ip, size=12, color=ft.Colors.GREY_400),
                ], spacing=0),
            )
            for name, ip in lan_options
        ],
        width=340,
        )

    def manual_ip_field():
        return ft.TextField(
        label="Custom local IPv4 address (optional)",
        hint_text="Only use if your adapter is not listed, e.g. 192.168.1.25",
        width=340,
        suffix=ft.IconButton(ft.Icons.HELP_OUTLINE, tooltip="Help choosing a custom IP", on_click=show_manual_ip_help),
        )

    receiver_lan_selector = interface_dropdown()
    receiver_manual_lan = manual_ip_field()
    sender_lan_selector = interface_dropdown()
    sender_manual_lan = manual_ip_field()

    def set_status(message: str):
        status.value = message
        page.update()

    def format_size(size: int) -> str:
        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(size)
        for unit in units:
            if value < 1024 or unit == units[-1]:
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return f"{size} B"

    def update_send_progress(completed: int, total: int):
        send_progress.visible = True
        send_progress.value = completed / total if total else 0
        send_progress_label.value = f"Sending: {format_size(completed)} of {format_size(total)} ({send_progress.value * 100:.0f}%)"
        page.update()

    def update_receive_progress(completed: int, total: int):
        receive_progress.visible = True
        receive_progress.value = completed / total if total else 0
        receive_progress_label.value = f"Receiving: {format_size(completed)} of {format_size(total)} ({receive_progress.value * 100:.0f}%)"
        page.update()

    def show_received_notification(filename: str, destination: Path):
        location = destination.resolve()

        def open_folder(_):
            page.launch_url(location.as_uri())
            page.pop_dialog()

        dialog = ft.AlertDialog(
            title=ft.Text("Transfer complete"),
            content=ft.Text(f"{filename} arrived successfully.\n\nSaved in:\n{location}"),
            actions=[
                ft.TextButton("Ignore", on_click=lambda _: page.pop_dialog()),
                ft.ElevatedButton("Open folder", icon=ft.Icons.FOLDER_OPEN, on_click=open_folder),
            ],
        )
        page.show_dialog(dialog)

    async def verify_receiver(peer_fingerprint: str, verification_code: str) -> bool:
        answer = asyncio.get_running_loop().create_future()

        def choose(value: bool):
            if not answer.done():
                answer.set_result(value)
            page.pop_dialog()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Verify receiver"),
            content=ft.Text(
                "Compare this code with the receiver's incoming-transfer dialog. "
                "Continue only when both codes are identical.\n\n"
                f"Verification code: {verification_code}\n"
                f"Receiver identity: {peer_fingerprint}"
            ),
            actions=[
                ft.TextButton("Cancel transfer", on_click=lambda _: choose(False)),
                ft.ElevatedButton("Codes match", on_click=lambda _: choose(True)),
            ],
        )
        page.show_dialog(dialog)
        return await answer

    async def ask_permission(
        filename: str,
        size: int,
        peer_fingerprint: str,
        verification_code: str,
    ) -> str:
        answer = asyncio.get_running_loop().create_future()

        def choose(value: str):
            if not answer.done():
                answer.set_result(value)
            page.pop_dialog()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Incoming file"),
            content=ft.Text(
                f"Accept '{filename}'?\n\n"
                f"Size: {format_size(size)}\n\n"
                "Compare this code with the sender before accepting:\n"
                f"Verification code: {verification_code}\n"
                f"Sender identity: {peer_fingerprint}"
            ),
            actions=[
                ft.TextButton("Reject", on_click=lambda _: choose("n")),
                ft.ElevatedButton("Accept", on_click=lambda _: choose("y")),
            ],
        )
        page.show_dialog(dialog)
        return await answer

    def add_selected_paths(paths: list[str]):
        for path in paths:
            if path and path not in selected_paths:
                selected_paths.append(path)
        if selected_paths:
            names = ", ".join(Path(path).name for path in selected_paths[:3])
            extra = f" + {len(selected_paths) - 3} more" if len(selected_paths) > 3 else ""
            selected_file.value = f"{len(selected_paths)} selected: {names}{extra}"
            selected_file.color = ft.Colors.WHITE
            set_status("Choose a receiver to start the encrypted transfer.")

    async def select_files():
        files = await picker.pick_files(allow_multiple=True)
        if files:
            add_selected_paths([file.path for file in files if file.path])
        else:
            set_status("File selection cancelled.")

    async def select_folder():
        folder = await picker.get_directory_path(dialog_title="Select a folder to send")
        if folder:
            add_selected_paths([folder])
        else:
            set_status("Folder selection cancelled.")

    def clear_selection(_):
        selected_paths.clear()
        selected_file.value = "No files or folders selected"
        selected_file.color = ft.Colors.GREY_400
        set_status("Selection cleared.")

    picker = ft.FilePicker()
    page.services.append(picker)

    async def send_to(ip: str, port: int):
        if not selected_paths:
            set_status("Select one or more files or folders first.")
            return
        client = FileTransferClient(ip, port)
        client.on_status = set_status
        client.on_progress = update_send_progress
        client.on_verify_peer = verify_receiver
        send_progress.value = 0
        send_progress.visible = True
        send_progress_label.value = "Preparing encrypted transfer..."
        page.update()
        await client.send_file(selected_paths)

    def device_found(name: str, ip: str, port: int):
        if devices.get(name) == (ip, port):
            return
        devices[name] = (ip, port)
        device_list.controls.append(
            ft.ListTile(
                leading=ft.Icon(ft.Icons.COMPUTER),
                title=ft.Text(name),
                subtitle=ft.Text(f"{ip}:{port}"),
                trailing=ft.ElevatedButton("Send", on_click=lambda _, i=ip, p=port: page.run_task(send_to, i, p)),
            )
        )
        set_status(f"Found receiver: {name}")

    async def start_scanner(restart: bool = False):
        nonlocal scanner
        requested_ip = sender_manual_lan.value.strip() or sender_lan_selector.value
        try:
            interface_ip = str(ipaddress.IPv4Address(requested_ip))
        except ipaddress.AddressValueError:
            set_status("Enter a valid sender IPv4 address.")
            return
        if scanner and not restart and scanner.interface_ip == interface_ip:
            return
        if scanner:
            await asyncio.to_thread(scanner.stop_scanning)
            scanner = None
        devices.clear()
        device_list.controls.clear()
        # Zeroconf's synchronous API must not block Flet's asyncio loop.
        scanner = await asyncio.to_thread(
            SenderScanner,
            on_device_found=device_found,
            interface_ip=interface_ip,
        )
        await asyncio.to_thread(scanner.start_scanning)
        set_status(f"Scanning for receivers on {interface_ip}…")

    async def start_receiver():
        nonlocal announcer, server, server_task
        if server_task and not server_task.done():
            return
        requested_ip = receiver_manual_lan.value.strip() or receiver_lan_selector.value
        try:
            listen_ip = str(ipaddress.IPv4Address(requested_ip))
        except ipaddress.AddressValueError:
            set_status("Enter a valid IPv4 address.")
            return
        name = socket.gethostname() or "PY2PY device"
        server = FileTransferServer(PORT, host=listen_ip)
        server.on_status = set_status
        server.on_request_permission = ask_permission
        server.on_progress = update_receive_progress
        server.on_received = show_received_notification
        announcer = ReceiverAnnouncer(PORT, name, ip_address=listen_ip)
        # register_service waits internally for an asyncio callback. Running it
        # on Flet's loop would deadlock and raise EventLoopBlocked.
        await asyncio.to_thread(announcer.start)
        server_task = asyncio.create_task(server.start())
        set_status(f"Ready to receive on {listen_ip}:{PORT}.")

    async def stop_receiver():
        nonlocal announcer, server, server_task
        if announcer:
            await asyncio.to_thread(announcer.stop)
            announcer = None
        if server:
            await server.stop()
            server = None
        if server_task:
            server_task.cancel()
            server_task = None
        set_status("Receiving stopped.")

    def go_back(_):
        page.go("/")

    def route_change(_):
        page.controls.clear()
        if page.route == "/send":
            page.run_task(start_scanner)
            body = ft.Column([
                ft.Text("Discover receivers on", size=18, weight=ft.FontWeight.BOLD),
                ft.Row([sender_lan_selector, sender_manual_lan], wrap=True),
                ft.Text("The default is the adapter currently used for internet access. Use ? for help with a custom address.", size=12, color=ft.Colors.GREY_400),
                ft.OutlinedButton("Scan selected interface", icon=ft.Icons.REFRESH, on_click=lambda _: page.run_task(start_scanner, True)),
                ft.Divider(),
                ft.Container(
                    content=ft.Column([
                        ft.Icon(ft.Icons.UPLOAD_FILE, size=36),
                        ft.Text("Add files to a secure transfer", weight=ft.FontWeight.BOLD),
                        ft.Text("Click here, or use Add folder below."),
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    border=ft.Border.all(1, ft.Colors.BLUE_GREY_400),
                    border_radius=12,
                    padding=16,
                    alignment=ft.Alignment.CENTER,
                    ink=True,
                    on_click=lambda _: page.run_task(select_files),
                ),
                ft.Row([
                    ft.ElevatedButton("Add files", icon=ft.Icons.INSERT_DRIVE_FILE, on_click=lambda _: page.run_task(select_files)),
                    ft.ElevatedButton("Add folder", icon=ft.Icons.FOLDER_OPEN, on_click=lambda _: page.run_task(select_folder)),
                    ft.OutlinedButton("Clear", on_click=clear_selection),
                ]),
                selected_file,
                send_progress_label,
                send_progress,
                ft.Divider(),
                ft.Text("Devices ready to receive", size=18, weight=ft.FontWeight.BOLD),
                ft.Container(
                    content=device_list,
                    height=360,
                    border=ft.Border.all(1, ft.Colors.BLUE_GREY_800),
                    border_radius=8,
                ),
                status,
            ], expand=True, scroll=ft.ScrollMode.ADAPTIVE)
            page.appbar = ft.AppBar(
                title=ft.Text("Send a file"),
                leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=go_back),
            )
        elif page.route == "/receive":
            body = ft.Column([
                ft.Text("Your device will be visible on the local network while receiving is enabled."),
                ft.Text("Listen on", size=18, weight=ft.FontWeight.BOLD),
                ft.Row([receiver_lan_selector, receiver_manual_lan], wrap=True),
                ft.Text("The default is the adapter currently used for internet access. Enter a custom local address only when the needed adapter is not listed.", size=12, color=ft.Colors.GREY_400),
                ft.ElevatedButton("Start receiving", icon=ft.Icons.PLAY_ARROW, on_click=lambda _: page.run_task(start_receiver)),
                ft.OutlinedButton("Stop receiving", icon=ft.Icons.STOP, on_click=lambda _: page.run_task(stop_receiver)),
                ft.Divider(), receive_progress_label, receive_progress, status,
            ], spacing=16)
            page.appbar = ft.AppBar(
                title=ft.Text("Receive files"),
                leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=go_back),
            )
        else:
            page.appbar = ft.AppBar(title=ft.Text("PY2PY"))
            body = ft.Column([
                ft.Text("Secure local file sharing", size=28, weight=ft.FontWeight.BOLD),
                ft.Text("Choose what you want to do."),
                ft.Row([
                    ft.ElevatedButton("Send a file", icon=ft.Icons.SEND, on_click=lambda _: page.go("/send")),
                    ft.ElevatedButton("Receive files", icon=ft.Icons.DOWNLOAD, on_click=lambda _: page.go("/receive")),
                ], alignment=ft.MainAxisAlignment.CENTER),
                status,
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, alignment=ft.MainAxisAlignment.CENTER, expand=True)
            page.add(body)
            page.update()
            return
        page.add(body)
        page.update()

    page.on_route_change = route_change
    # The initial route is already "/", so page.go("/") would not trigger
    # on_route_change. Build the first screen explicitly.
    route_change(None)


if __name__ == "__main__":
    #ft.run(main)
    asyncio.run(ft.app_async(target=main, assets_dir="assets"))
