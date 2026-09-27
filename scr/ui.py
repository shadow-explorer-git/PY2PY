# ui.py
import asyncio
import ipaddress
import socket
import subprocess
import sys
import time
import os
from pathlib import Path
from datetime import datetime

import flet as ft

from . import localization
from .core_network import FileTransferClient, FileTransferServer
from .discovery import ReceiverAnnouncer, SenderScanner, SubnetScanner, get_local_interfaces
from .trust import add_trust, is_trusted, list_trusted, remove_trust
from .config import get_config, save_config, get_default_config


def format_size(size: int) -> str:
    """Formats a size in bytes into a human-readable string (KB, MB, GB)."""
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def format_speed(speed_bytes_per_sec: float) -> str:
    """Formats a speed in B/s into a human-readable string (KB/s, MB/s)."""
    if speed_bytes_per_sec < 1024 * 1024:
        return f"{speed_bytes_per_sec / 1024:.1f} KB/s"
    if speed_bytes_per_sec < 1024 * 1024 * 1024:
        return f"{speed_bytes_per_sec / (1024 * 1024):.2f} MB/s"
    return f"{speed_bytes_per_sec / (1024 * 1024 * 1024):.2f} GB/s"


def create_progress_handler(page: ft.Page, label: ft.Text, progress_bar: ft.ProgressBar, role: str):
    """Factory to create a progress handler that calculates and displays transfer speed."""
    last_update_time = 0.0
    last_completed_bytes = 0
    start_time = 0.0

    async def update_ui_async(completed, total, speed):
        """This coroutine runs on the main event loop to safely update UI controls."""
        try:
            progress_bar.visible = True
            progress_bar.value = completed / total
            
            if speed > 1024:
                label.value = localization.get_string("progress_label").format(
                    role=localization.get_string(role),
                    completed=format_size(completed),
                    total=format_size(total),
                    percent=progress_bar.value * 100,
                    speed=format_speed(speed)
                )
            else:
                label.value = localization.get_string("progress_label_no_speed").format(
                    role=localization.get_string(role),
                    completed=format_size(completed),
                    total=format_size(total),
                    percent=progress_bar.value * 100
                )
            page.update()
        except RuntimeError as e:
            if "destroyed session" in str(e):
                # This is expected if a transfer is running when the app closes.
                pass
            else:
                raise

    def handler(completed: int, total: int):
        nonlocal last_update_time, last_completed_bytes, start_time
        current_time = time.monotonic()

        if completed == 0 and total > 0:  # Start of a new transfer
            start_time = current_time
            last_update_time = current_time
            last_completed_bytes = 0

        if total == 0: return

        time_delta = current_time - last_update_time
        if time_delta < 0.25 and completed < total: return  # Throttle UI updates

        bytes_delta = completed - last_completed_bytes
        speed = bytes_delta / time_delta if time_delta > 0 else 0
        last_update_time, last_completed_bytes = current_time, completed

        # Instead of updating UI directly, schedule the update on the main event loop.
        # This is thread-safe and prevents conflicts with other UI updates.
        page.run_task(update_ui_async, completed, total, speed)

    return handler

def main(page: ft.Page):
    config = get_config()
    localization.set_language(config.get("language", "en"))

    page.window.icon = "final.ico"
    page.title = localization.get_string("app_title")

    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 24
    page.window.width = 850
    page.window.height = 720
    page.window.min_width = 650
    page.window.min_height = 500
    
    # Define the main layout structure once. This is more stable than rebuilding on each route change.
    main_content_area = ft.Column(
        expand=True,
        scroll=ft.ScrollMode.ADAPTIVE,
        # Default properties, will be updated by route_change
        spacing=12,
        horizontal_alignment=ft.CrossAxisAlignment.START,
    )

    # In-memory state for the sender UI to persist across route changes within a session.
    sender_ui_state = {
        "send_mode": "auto",  # 'auto' or 'manual'
        "manual_mode": "ip",  # 'ip' or 'subnet'
        "direct_ip": "",
        "direct_port": str(get_config().get("network", {}).get("port", 35000)),
        "subnet_cidr": "",
        "subnet_port": str(get_config().get("network", {}).get("port", 35000)),
    }

    selected_paths: list[str] = []
    scanner: SenderScanner | None = None
    announcer: ReceiverAnnouncer | None = None
    subnet_scanner: SubnetScanner | None = None
    server: FileTransferServer | None = None
    server_task: asyncio.Task | None = None
    devices: dict[str, tuple[str, int]] = {} # Discovered devices for sender
    send_transfer_active = False # Is a send transfer currently active?
    current_send_task: asyncio.Task | None = None # The task for the active send transfer
    active_send_target: tuple[str, int] | None = None # The (ip, port) of the current send target
    receive_transfer_active = False # Is a receive transfer currently active?
    current_receive_task: asyncio.Task | None = None # The task for the active receive transfer
    firewall_checked_this_session = False

    log_view = ft.ListView(
        spacing=2,
        auto_scroll=True,
        expand=True,
    )

    status_container = ft.Container(
        content=log_view,
        padding=ft.Padding(left=12, right=4, top=6, bottom=6),
        bgcolor=ft.Colors.WHITE10,
        border=ft.Border(top=ft.BorderSide(1, ft.Colors.WHITE12)),
        alignment=ft.Alignment(-1, 0),
        height=80,
    )

    direct_ip_send_progress_label = ft.Text("", color=ft.Colors.GREY_400)
    direct_ip_send_progress = ft.ProgressBar(value=0, visible=False)
    list_view_send_progress_label = ft.Text("", color=ft.Colors.GREY_400)
    list_view_send_progress = ft.ProgressBar(value=0, visible=False)
    receive_progress_label = ft.Text("", color=ft.Colors.GREY_400)
    receive_progress = ft.ProgressBar(value=0, visible=False)    
    selected_file = ft.Text(localization.get_string("selected_file_none"), color=ft.Colors.GREY_400)
    device_list = ft.ListView(
        spacing=6,
        padding=8,
        scroll=ft.ScrollMode.ALWAYS,
    )
    perform_filtering = config.get("ui", {}).get("show_only_recommended_interfaces", False)
    lan_options = get_local_interfaces(perform_bind_check=perform_filtering)

    helper_text_content = localization.get_string("lan_helper_text")
    helper_text_style = {"size": 12, "color": ft.Colors.GREY_400}
    sender_lan_helper = ft.Text(helper_text_content, **helper_text_style, visible=bool(lan_options))
    receiver_lan_helper = ft.Text(helper_text_content, **helper_text_style, visible=bool(lan_options))

    selected_items_list = ft.ListView(
        spacing=4,
        height=120,
        scroll=ft.ScrollMode.ALWAYS, 
    )

    def clear_selection(_):
        selected_paths.clear()
        render_selected_items()
        set_status(localization.get_string("status_selection_cleared"))

    clear_btn = ft.OutlinedButton(localization.get_string("clear_all_button"), icon=ft.Icons.DELETE_SWEEP, on_click=clear_selection, visible=False)

    selected_items_card = ft.Card(
        visible=False, # Initially hidden
        content=ft.Container(
            content=ft.Column([
                ft.Row([
                    selected_file,
                    clear_btn
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Divider(height=1, color=ft.Colors.BLUE_GREY_800),
                selected_items_list
            ]),
            padding=12
        ),
        bgcolor=ft.Colors.BLACK26
    )

    def render_selected_items():
        selected_items_list.controls.clear()
        if not selected_paths:
            selected_file.value = localization.get_string("selected_file_none")
            selected_file.color = ft.Colors.GREY_400
            clear_btn.visible = False
            selected_items_card.visible = False
        else:
            selected_items_card.visible = True
            selected_file.value = localization.get_string("selected_file_count").format(count=len(selected_paths))
            selected_file.color = ft.Colors.BLUE_200
            clear_btn.visible = True
            
            for path in selected_paths:
                p_obj = Path(path)
                is_dir = p_obj.is_dir()
                
                def remove_item(e, p=path):
                    if p in selected_paths:
                        selected_paths.remove(p)
                    render_selected_items()
                    set_status(localization.get_string("status_item_removed"))

                selected_items_list.controls.append(
                    ft.Container(
                        content=ft.Row([
                            ft.Icon(
                                ft.Icons.FOLDER if is_dir else ft.Icons.INSERT_DRIVE_FILE, 
                                color=ft.Colors.BLUE_400 if is_dir else ft.Colors.GREEN_400,
                                size=16
                            ),
                            ft.Text(p_obj.name, expand=True, size=13, weight=ft.FontWeight.W_500),
                            ft.Text(str(p_obj.parent), size=11, color=ft.Colors.GREY_500, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                            ft.IconButton(
                                icon=ft.Icons.CLOSE,
                                icon_size=14,
                                icon_color=ft.Colors.RED_300,
                                tooltip=localization.get_string("remove_from_list_tooltip"),
                                on_click=remove_item
                            )
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        padding=ft.Padding(left=8, right=8, top=2, bottom=2),
                        border_radius=6,
                        bgcolor=ft.Colors.BLUE_GREY_900,
                    )
                )
        page.update()

    def add_selected_paths(paths: list[str]):
        for path in paths:
            if path:
                cleaned_path = path.strip().strip('"').strip("'")
                if cleaned_path and cleaned_path not in selected_paths:
                    if Path(cleaned_path).exists():
                        selected_paths.append(cleaned_path)
                    else:
                        set_status(localization.get_string("status_skipped_not_exist").format(path=cleaned_path))
        render_selected_items()
        if selected_paths:
            set_status(localization.get_string("status_choose_receiver"))

    def _render_device_list():
        """Synchronously re-renders the device list from the `devices` dictionary."""
        device_list.controls.clear()
        for name, (ip, port) in list(devices.items()):
            # If the name is the IP, it's from a manual scan. Display it clearly.
            title = ft.Text(name) if name != ip else ft.Text(localization.get_string("device_list_ip_prefix").format(ip=ip), weight=ft.FontWeight.BOLD)
            subtitle = ft.Text(f"{ip}:{port}") if name != ip else None

            is_active_target = active_send_target == (ip, port)

            if is_active_target:
                # This is the device we are sending to. Show a cancel button.
                action_button = ft.ElevatedButton(
                    localization.get_string("cancel_transfer_button_short"),
                    icon=ft.Icons.CANCEL,
                    bgcolor=ft.Colors.RED_700,
                    on_click=lambda _: current_send_task.cancel() if current_send_task else None
                )
            else:
                # This is not the active transfer. Show a send button.
                action_button = ft.ElevatedButton(
                    localization.get_string("device_list_send_button"), # Disable other send buttons during a send transfer
                    on_click=lambda _, i=ip, p=port: page.run_task(send_to_target, i, p, update_send_progress_list, list_view_send_progress_label, list_view_send_progress), # Disable other send buttons during a send transfer
                    disabled=send_transfer_active # Disable other send buttons during a send transfer
                )

            device_list.controls.append(ft.ListTile(leading=ft.Icon(ft.Icons.COMPUTER), title=title, subtitle=subtitle, trailing=action_button))

    def show_subnet_help(_):
        dialog = ft.AlertDialog(
            title=ft.Text(localization.get_string("subnet_help_title")),
            content=ft.Column([
                ft.Text(localization.get_string("subnet_help_line1")),
                ft.Text(localization.get_string("subnet_help_line2")),
                ft.Text(localization.get_string("subnet_help_examples")),
                ft.Text(localization.get_string("subnet_help_example1")),
                ft.Text(localization.get_string("subnet_help_example2")),
            ], tight=True, spacing=10),
            actions=[ft.TextButton(localization.get_string("got_it_button"), on_click=lambda _: page.pop_dialog())],
        )
        page.show_dialog(dialog)

    def create_lan_options_list():
        options = []
        config = get_config()
        show_only_recommended = config.get("ui", {}).get("show_only_recommended_interfaces", False)

        for item in lan_options:
            if show_only_recommended and item["is_undesirable"]:
                continue

            name = item["name"]
            ip = item["ip"]
            is_default = item["is_default"]
            is_recommended = not item["is_undesirable"]

            name_text = ft.Text(name, weight=ft.FontWeight.BOLD)
            indicator_row = ft.Row(spacing=4, vertical_alignment=ft.CrossAxisAlignment.CENTER)

            if is_default:
                name_text.color = ft.Colors.AMBER_300
                indicator_row.controls.append(ft.Icon(ft.Icons.STAR, color=ft.Colors.AMBER, size=16))
                indicator_row.controls.append(ft.Text("(Default)", color=ft.Colors.AMBER, size=11, weight=ft.FontWeight.BOLD))
            elif is_recommended:
                name_text.color = ft.Colors.GREEN_400

            options.append(
                ft.DropdownOption(
                    key=ip,
                    text=name,  # `text` is used for filtering when user types in dropdown
                    content=ft.Column([
                        ft.Row([
                            name_text,
                            indicator_row,
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(ip, size=12, color=ft.Colors.GREY_400),
                    ], spacing=0),
                )
            )
        return options

    sender_lan_selector = ft.Dropdown(
        label=localization.get_string("lan_selector_label"),
        value=lan_options[0]["ip"] if lan_options else None, # This will be re-evaluated on route change
        options=create_lan_options_list(),
        expand=True,
    )
    receiver_lan_selector = ft.Dropdown(
        label=localization.get_string("lan_selector_label"),
        value=lan_options[0]["ip"] if lan_options else None,
        options=create_lan_options_list(),
        expand=True,
    )

    def on_log_message(topic: str, message: str):
        """
        PubSub handler for log messages. Appends a new message to the log view.
        This handler is called on the main UI thread, so it's safe to update controls directly.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_view.controls.append(
            ft.Row([
                ft.Text(f"[{timestamp}]", color=ft.Colors.GREY_600, size=11, font_family="monospace"),
                ft.Text(message, color=ft.Colors.GREY_400, size=12, expand=True, selectable=True),
            ], spacing=8)
        )
        if len(log_view.controls) > 100:
            log_view.controls.pop(0)
        page.update()

    def on_device_update(topic: str, message: dict):
        """PubSub handler for device list updates."""
        try:
            command = message.get("command")
            data = message.get("data")
            updated = False
            if command == "device_found":
                name, ip, port = data["name"], data["ip"], data["port"]
                if devices.get(name) != (ip, port):
                    devices[name] = (ip, port)
                    updated = True
            elif command == "device_lost":
                name = data
                if name in devices:
                    del devices[name]
                    updated = True
            
            if updated:
                _render_device_list()
                page.update()
        except RuntimeError as e:
            if "destroyed session" not in str(e):
                raise

    async def refresh_interfaces(_):
        try:
            set_status(localization.get_string("status_refreshing_interfaces"))
            await asyncio.sleep(0.1)  # give UI time to show status

            current_sender_ip = sender_lan_selector.value
            current_receiver_ip = receiver_lan_selector.value

            nonlocal lan_options
            config = get_config()
            perform_filtering = config.get("ui", {}).get("show_only_recommended_interfaces", False)
            lan_options = await asyncio.to_thread(get_local_interfaces, perform_bind_check=perform_filtering)
            new_options = create_lan_options_list()
            valid_ips = {item["ip"] for item in lan_options}
            new_default_ip = lan_options[0]["ip"] if lan_options else None

            sender_lan_selector.options = new_options
            receiver_lan_selector.options = new_options
            sender_lan_selector.value = current_sender_ip if current_sender_ip in valid_ips else new_default_ip
            receiver_lan_selector.value = current_receiver_ip if current_receiver_ip in valid_ips else new_default_ip

            sender_lan_helper.visible = bool(lan_options)
            receiver_lan_helper.visible = bool(lan_options)

            set_status(localization.get_string("status_interfaces_updated"))
            page.update()
        except RuntimeError as e:
            if "destroyed session" in str(e):
                print("UI Log (session destroyed): Suppressed UI update in refresh_interfaces.")
            else:
                raise

    update_send_progress_direct_ip = create_progress_handler(page, direct_ip_send_progress_label, direct_ip_send_progress, "role_sending")
    update_send_progress_list = create_progress_handler(page, list_view_send_progress_label, list_view_send_progress, "role_sending")
    update_receive_progress = create_progress_handler(page, receive_progress_label, receive_progress, "role_receiving")

    def show_received_notification(filename: str, destination: Path):
        location = destination.resolve()

        from .platform import open_folder as _open_folder

        def open_folder(_):
            async def _open():
                try:
                    success = await asyncio.to_thread(_open_folder, location)
                    if not success:
                        try:
                            page.launch_url(location.as_uri())
                        except Exception:
                            pass
                finally:
                    page.pop_dialog()

            asyncio.create_task(_open())

        dialog = ft.AlertDialog(
            title=ft.Text(localization.get_string("transfer_complete_title")),
            content=ft.Text(localization.get_string("transfer_complete_message").format(filename=filename, location=location)),
            actions=[
                ft.TextButton(localization.get_string("ignore_button"), on_click=lambda _: page.pop_dialog()),
                ft.ElevatedButton(localization.get_string("open_folder_button"), icon=ft.Icons.FOLDER_OPEN, on_click=open_folder),
            ],
        )
        page.show_dialog(dialog)

    async def verify_receiver(peer_fingerprint: str, peer_name: str, verification_code: str) -> bool:
        if is_trusted(peer_fingerprint):
            set_status(localization.get_string("status_trusted_receiver"))
            return True

        answer = asyncio.get_running_loop().create_future()

        def choose(value: bool):
            if not answer.done():
                answer.set_result(value)
            page.pop_dialog()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(localization.get_string("verify_receiver_title")),
            content=ft.Text(
                localization.get_string("verify_receiver_instructions") + "\n\n" +
                localization.get_string("verification_code_label").format(code=verification_code) + "\n" +
                localization.get_string("receiver_label").format(name=peer_name) + "\n" +
                localization.get_string("receiver_identity_label").format(fp=peer_fingerprint)
            ),
            actions=[
                ft.TextButton(localization.get_string("cancel_transfer_button"), on_click=lambda _: choose(False)),
                ft.ElevatedButton(localization.get_string("codes_match_button"), on_click=lambda _: choose(True)),
            ],
        )
        page.show_dialog(dialog)
        return await answer

    async def ask_permission(
        filename: str,
        size: int,
        peer_fingerprint: str,
        peer_name: str,
        verification_code: str,
    ) -> tuple[str, str | None]:
        answer = asyncio.get_running_loop().create_future()

        trusted = is_trusted(peer_fingerprint)
        trust_checkbox = ft.Checkbox(label=localization.get_string("trust_device_checkbox")) if not trusted else None

        # This needs to be async to handle the directory picker
        async def process_choice(value: str, trust: bool = False):
            if value == 'y':
                save_path = None
                if get_config()["receive"]["mode"] == "ask":
                    # Use the directory_picker defined later in main()
                    save_path = await directory_picker.get_directory_path(
                        dialog_title=localization.get_string("dialog_title_select_save_folder")
                    )
                    if not save_path:  # User cancelled the directory picker
                        if not answer.done(): answer.set_result(('n', None))
                        page.pop_dialog()
                        return

                if trust:
                    add_trust(peer_fingerprint, peer_name)
                
                if not answer.done():
                    answer.set_result(('y', save_path))
            else:  # 'n'
                if not answer.done():
                    answer.set_result(('n', None))
            
            page.pop_dialog()

        def choose_sync_wrapper(value: str, trust: bool = False):
            page.run_task(process_choice, value, trust)

        content_items = [
            ft.Text(localization.get_string("incoming_transfer_from").format(name=peer_name, fp=peer_fingerprint)),
            ft.Text(localization.get_string("filename_label").format(filename=filename)),
            ft.Text(localization.get_string("size_label").format(size=format_size(size))),
        ]
        if not trusted:
            content_items.append(ft.Text(localization.get_string("compare_code_prompt") + "\n"))
            content_items.append(ft.Text(localization.get_string("verification_code_label").format(code=verification_code)))
        if trust_checkbox:
            content_items.append(trust_checkbox)

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(localization.get_string("incoming_file_title")),
            content=ft.Column(content_items, tight=True, spacing=10),
            actions=[
                ft.TextButton(localization.get_string("reject_button"), on_click=lambda _: choose_sync_wrapper("n", False)),
                ft.ElevatedButton(localization.get_string("accept_button"), on_click=lambda _: choose_sync_wrapper("y", trust_checkbox.value if trust_checkbox else False)),
            ],
        )
        page.show_dialog(dialog)
        return await answer

    # FilePickers for selecting files/folders to send, and for choosing save locations.
    file_picker = ft.FilePicker()
    directory_picker = ft.FilePicker()
    settings_directory_picker = ft.FilePicker()

    async def do_pick_files():
        files = await file_picker.pick_files(allow_multiple=True)
        if files:
            add_selected_paths([f.path for f in files if f.path])
        else:
            set_status(localization.get_string("status_file_selection_cancelled"))
        page.update()

    async def do_get_directory():
        path = await file_picker.get_directory_path(dialog_title=localization.get_string("dialog_title_select_send_folder"))
        if path:
            add_selected_paths([path])
        else:
            set_status(localization.get_string("status_folder_selection_cancelled"))
        page.update()
    
    def _reset_send_transfer_state(is_manual_ip_mode=False, send_btn=None, check_btn=None, cancel_btn=None):
        """Centralized function to reset all sender-related transfer state."""
        nonlocal send_transfer_active, current_send_task, active_send_target
        send_transfer_active = False
        current_send_task = None
        active_send_target = None

        try:
            # Reset progress bars
            direct_ip_send_progress.visible = False
            list_view_send_progress.visible = False
            direct_ip_send_progress_label.value = ""
            list_view_send_progress_label.value = ""

            _render_device_list() # This updates the list view buttons

            if is_manual_ip_mode and all((send_btn, check_btn, cancel_btn)):
                send_btn.visible = True
                check_btn.visible = True
                cancel_btn.visible = False
            page.update() # Update the UI to reflect the new state
        except RuntimeError as e:
            if "destroyed session" in str(e):
                print("UI Log (session destroyed): Suppressed UI update in _reset_send_transfer_state.")
            else:
                raise

    async def send_to_target(ip: str, port: int, progress_handler, progress_label: ft.Text, progress_bar: ft.ProgressBar, send_btn=None, check_btn=None, cancel_btn=None):
        nonlocal send_transfer_active, current_send_task, active_send_target
        if send_transfer_active:
            set_status(localization.get_string("status_transfer_in_progress"))
            return
        if not selected_paths:
            set_status(localization.get_string("status_select_files_first"))
            return
        
        send_transfer_active = True
        active_send_target = (ip, port)
        _render_device_list()

        is_manual_ip_mode = all((send_btn, check_btn, cancel_btn))
        if is_manual_ip_mode:
            send_btn.visible = False
            check_btn.visible = False
            cancel_btn.visible = True
            page.update()
        
        try:
            client = FileTransferClient(ip, port)
            client.on_status = set_status_localized
            client.on_progress = progress_handler
            client.on_verify_peer = verify_receiver
            progress_bar.value = 0
            progress_bar.visible = True
            progress_label.value = localization.get_string("status_preparing_transfer")
            page.update()
    
            task = asyncio.create_task(client.send_file(selected_paths))
            current_send_task = task
            await task
        except asyncio.CancelledError:
            pass # Expected, the client already logged its own status.
        finally:
            _reset_send_transfer_state(is_manual_ip_mode, send_btn, check_btn, cancel_btn)

    def device_found(name: str, ip: str, port: int):
        if devices.get(name) == (ip, port):
            return
        # Send a structured message to the pubsub handler to update UI from the main thread.
        page.pubsub.send_all_on_topic("devices", {
            "command": "device_found",
            "data": {"name": name, "ip": ip, "port": port}
        })

    async def check_and_configure_firewall():
        """
        Checks for and configures firewall rules on Windows/Linux.
        Runs only once per application session. Returns True if it's okay to proceed.
        """
        nonlocal firewall_checked_this_session
        if firewall_checked_this_session:
            return True

        firewall_checked_this_session = True

        if sys.platform.startswith("win"):
            from .platform import check_firewall_rules_windows, add_firewall_rule_windows

            rules_exist = await asyncio.to_thread(check_firewall_rules_windows)
            if not rules_exist:
                answer = asyncio.get_running_loop().create_future()
                def choose(ok: bool):
                    if not answer.done(): answer.set_result(ok)
                    page.pop_dialog()

                dialog = ft.AlertDialog(
                    modal=True,
                    title=ft.Text(localization.get_string("win_firewall_title")),
                    content=ft.Text(localization.get_string("win_firewall_prompt")),
                    actions=[
                        ft.TextButton(localization.get_string("cancel_button"), on_click=lambda _: choose(False)),
                        ft.ElevatedButton(localization.get_string("ok_continue_button"), on_click=lambda _: choose(True)),
                    ]
                )
                page.show_dialog(dialog)
                ok_to_proceed = await answer
                if ok_to_proceed:
                    set_status(localization.get_string("status_requesting_firewall_perms"))
                    await asyncio.to_thread(add_firewall_rule_windows)
                    await asyncio.sleep(1)  # Give a moment for rules to apply
                    return True
                else:
                    set_status(localization.get_string("status_firewall_not_configured"))
                    return False

        elif sys.platform.startswith("linux"):
            from .platform import check_firewall_linux
            from .config import get_config

            port = get_config().get("network", {}).get("port", 35000)
            status, message = await asyncio.to_thread(check_firewall_linux, port)

            if status in ("missing", "unknown") and message:
                answer = asyncio.get_running_loop().create_future()
                def choose():
                    if not answer.done(): answer.set_result(None)
                    page.pop_dialog()

                dialog = ft.AlertDialog(
                    modal=True,
                    title=ft.Text(localization.get_string("linux_firewall_title")),
                    content=ft.Column([
                        ft.Text(localization.get_string("linux_firewall_prompt")),
                        ft.TextField(value=message, read_only=True, multiline=True, border=ft.InputBorder.NONE),
                    ], tight=True, spacing=10),
                    actions=[
                        ft.ElevatedButton(localization.get_string("got_it_button"), on_click=lambda _: choose()),
                    ]
                )
                page.show_dialog(dialog)
                await answer

        return True


    def device_lost(name: str):
        if name in devices:
            # Send a structured message to the pubsub handler to update UI from the main thread.
            page.pubsub.send_all_on_topic("devices", {
                "command": "device_lost",
                "data": name
            })

    def handle_receive_start(task: asyncio.Task):
        nonlocal receive_transfer_active, current_receive_task
        
        try:
            action_row = None
            cancel_button = None
            for ctrl in main_content_area.controls:
                if ctrl.data == "receiver_action_buttons_row":
                    action_row = ctrl
                elif isinstance(ctrl, ft.Row) and ctrl.data == "receive_progress_controls" and len(ctrl.controls) > 1:
                    cancel_button = ctrl.controls[1]
            
            receive_transfer_active = True
            current_receive_task = task

            if action_row: action_row.visible = False
            if cancel_button: cancel_button.visible = True
            page.update()
        except RuntimeError as e:
            if "destroyed session" in str(e):
                print("UI Log (session destroyed): Suppressed UI update in handle_receive_start.")
            else:
                raise

    def handle_receive_end():
        nonlocal receive_transfer_active, current_receive_task
        receive_transfer_active = False
        current_receive_task = None

        try:
            # Reset progress bar visibility and text
            receive_progress.visible = False
            receive_progress_label.value = ""

            action_row = None
            cancel_button = None
            for ctrl in main_content_area.controls:
                if ctrl.data == "receiver_action_buttons_row":
                    action_row = ctrl
                elif isinstance(ctrl, ft.Row) and ctrl.data == "receive_progress_controls" and len(ctrl.controls) > 1:
                    cancel_button = ctrl.controls[1]

            if action_row: action_row.visible = True
            if cancel_button: cancel_button.visible = False
            page.update()
        except RuntimeError as e:
            if "destroyed session" in str(e):
                print("UI Log (session destroyed): Suppressed UI update in handle_receive_end.")
            else:
                raise

    async def start_scanner(restart: bool = False):
        nonlocal scanner

        if not await check_and_configure_firewall():
            return

        requested_ip = sender_lan_selector.value
        if not requested_ip or requested_ip == "add_custom":
            return
        try:
            ip_obj = ipaddress.ip_address(requested_ip)
            interface_ip = str(ip_obj)
        except ValueError:
            set_status(localization.get_string("status_enter_valid_sender_ip"))
            return
        if scanner and not restart and scanner.interface_ip == interface_ip:
            return
        if scanner:
            await scanner.stop_scanning_async()
            scanner = None
        devices.clear()
        device_list.controls.clear()

        # Instantiate on the main thread, async method will handle background tasks.
        scanner = SenderScanner(
            on_device_found=device_found,
            on_device_lost=device_lost,
            interface_ip=interface_ip,
            on_status=set_status_localized,
        )
        
        target = interface_ip or localization.get_string("all_interfaces_target")
        set_status_localized("status_scanning_on_target", target=target)
        await scanner.start_scanning_async()

    async def start_subnet_scan(subnet_str: str, port: int):
        nonlocal subnet_scanner
        if not subnet_str:
            set_status(localization.get_string("status_enter_subnet"))
            return
        if subnet_scanner:
            subnet_scanner.cancel()
        
        devices.clear()
        _render_device_list()
        page.update()
        
        def on_scan_done():
            set_status(localization.get_string("status_subnet_scan_complete"))

        subnet_scanner = SubnetScanner(
            on_device_found=device_found,
            on_scan_complete=on_scan_done,
            on_status=set_status_localized,
        )
        set_status_localized("status_scanning_subnet", subnet=subnet_str, port=port)
        await subnet_scanner.scan(subnet_str, port=port)


    async def start_receiver():
        nonlocal announcer, server, server_task

        # Unified firewall check at the top
        if not await check_and_configure_firewall():
            return

        if server_task and not server_task.done():
            return
        config = get_config()
        port = config.get("network", {}).get("port", 35000)
        requested_ip = receiver_lan_selector.value
        try:
            # Handle None or invalid IP strings
            listen_ip = str(ipaddress.ip_address(requested_ip))
        except (ValueError, TypeError):
            set_status(localization.get_string("status_enter_valid_listen_ip"))
            return

        name = socket.gethostname() or "PY2PY device"
        server = FileTransferServer(port, host=listen_ip)
        server.on_status = set_status_localized
        server.on_request_permission = ask_permission # This is a callback for the UI to ask permission
        server.on_progress = update_receive_progress
        server.on_received = show_received_notification
        server.on_transfer_start = handle_receive_start
        server.on_transfer_end = handle_receive_end
        announcer = ReceiverAnnouncer(port, name, ip_address=listen_ip, interface_ip=listen_ip, on_status=set_status_localized)

        server_task = None
        try:
            await announcer.start_async()
            server_task = asyncio.create_task(server.start())

            # Wait for the server to start or fail, with a timeout.
            await asyncio.wait_for(server.started_event.wait(), timeout=2.0)

            # If the server failed to start, the exception will be stored.
            if server.startup_exception:
                raise server.startup_exception

        except (OSError, asyncio.TimeoutError) as e:
            set_status_localized("error_bind_failed" if isinstance(e, OSError) else "status_receiver_start_failed", ip=listen_ip, port=port)
            if announcer: await announcer.stop_async()
            if server_task and not server_task.done(): server_task.cancel()
            return  # Stop execution

        # The status is now set inside the server.start() method upon successful binding, so this is redundant.

    async def stop_receiver():
        nonlocal announcer, server, server_task
        if announcer:
            await announcer.stop_async()
            announcer = None
        
        if server_task:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass  # This is expected.
            server_task = None

        if server:
            await server.stop()
            server = None

        set_status(localization.get_string("status_receiving_stopped"))

    async def restart_receiver():
        await stop_receiver()
        await start_receiver()

    def go_back(_):
        # Stop any active scanners when leaving a page
        page.go("/")

    def route_change(_):
        # Clear the main content area and services to prepare for the new view.
        main_content_area.controls.clear()
        page.services.clear()
        page.services.append(file_picker)
        page.services.append(directory_picker)
        page.services.append(settings_directory_picker)

        # Re-apply localized strings to global controls on every route change
        page.title = localization.get_string("app_title")
        sender_lan_selector.label = localization.get_string("lan_selector_label")
        receiver_lan_selector.label = localization.get_string("lan_selector_label")
        sender_lan_helper.value = localization.get_string("lan_helper_text")
        receiver_lan_helper.value = localization.get_string("lan_helper_text")
        clear_btn.text = localization.get_string("clear_all_button")
        
        # This list will hold the controls for the main body of the current page.
        body_controls = []
        
        # Update properties of the main content column based on the route
        if page.route == "/" or page.route is None:
            main_content_area.horizontal_alignment = ft.CrossAxisAlignment.CENTER
            main_content_area.alignment = ft.MainAxisAlignment.CENTER
            main_content_area.spacing = 20
        else:
            main_content_area.horizontal_alignment = ft.CrossAxisAlignment.START
            main_content_area.alignment = ft.MainAxisAlignment.START
            main_content_area.spacing = 16 if page.route == "/settings" else 12

        if page.route == "/" or page.route is None:
            page.appbar = ft.AppBar(title=ft.Text(localization.get_string("app_name_short")))
            body_controls.extend([
                ft.Text(localization.get_string("main_title"), size=28, weight=ft.FontWeight.BOLD),
                ft.Text(localization.get_string("main_subtitle")),
                ft.Row([
                    ft.ElevatedButton(localization.get_string("send_button"), icon=ft.Icons.SEND, on_click=lambda _: page.go("/send")),
                    ft.ElevatedButton(localization.get_string("receive_button"), icon=ft.Icons.DOWNLOAD, on_click=lambda _: page.go("/receive")),
                    ft.ElevatedButton(localization.get_string("trusted_button"), icon=ft.Icons.SECURITY, on_click=lambda _: page.go("/trusted")),
                ], alignment=ft.MainAxisAlignment.CENTER),
                ft.ElevatedButton(localization.get_string("settings_button"), icon=ft.Icons.SETTINGS, on_click=lambda _: page.go("/settings")),
            ])

        elif page.route == "/send":
            page.appbar = ft.AppBar(
                title=ft.Text(localization.get_string("send_files_title")),
                leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=go_back, icon_size=20),
                bgcolor=ft.Colors.BLUE_GREY_900,
            )
            render_selected_items()

            # --- Define UI Controls and Handlers in Correct Order ---

            # 1. Define simple controls that handlers will need
            def update_sender_state(key: str, value: str):
                sender_ui_state[key] = value

            direct_ip_field = ft.TextField(
                label=localization.get_string("receiver_ip_label"),
                hint_text="192.168.1.10",
                expand=True,
                value=sender_ui_state["direct_ip"],
                on_change=lambda e: update_sender_state("direct_ip", e.control.value),
            )
            direct_port_field = ft.TextField(
                label=localization.get_string("port_label"),
                value=sender_ui_state["direct_port"],
                width=100,
                keyboard_type=ft.KeyboardType.NUMBER,
                on_change=lambda e: update_sender_state("direct_port", e.control.value),
            )
            ip_status_text = ft.Text("", visible=False, size=12)
            subnet_field = ft.TextField(
                label=localization.get_string("subnet_scan_label"),
                hint_text="192.168.1.0/24",
                expand=True,
                value=sender_ui_state["subnet_cidr"],
                on_change=lambda e: update_sender_state("subnet_cidr", e.control.value),
            )
            subnet_port_field = ft.TextField(
                label=localization.get_string("port_label"),
                value=sender_ui_state["subnet_port"],
                width=100,
                keyboard_type=ft.KeyboardType.NUMBER,
                on_change=lambda e: update_sender_state("subnet_port", e.control.value),
            )
            device_list_card = ft.Card(
                ft.Container(
                    ft.Column([
                        ft.Text(localization.get_string("devices_ready_title"), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text(localization.get_string("devices_ready_subtitle"), size=12, color=ft.Colors.GREY_400),
                        ft.Container(content=device_list, height=240, border=ft.Border.all(1, ft.Colors.BLUE_GREY_800), border_radius=8, margin=ft.Margin(top=10, bottom=0, left=0, right=0)),
                    ]),
                    padding=16
                ),
                visible=True
            )

            # 2. Define event handlers
            async def check_ip_status(_):
                try:
                    ip = direct_ip_field.value.strip()
                    port_str = direct_port_field.value.strip()
                    if not ip or not port_str: 
                        ip_status_text.visible = False
                        page.update()
                        return

                    direct_ip_field.error_text = None
                    direct_port_field.error_text = None

                    ip_status_text.value = localization.get_string("status_checking_short")
                    ip_status_text.color = ft.Colors.AMBER
                    ip_status_text.visible = True
                    page.update()
                    await asyncio.sleep(0.01)

                    try:
                        port = int(port_str)
                        if not (1 <= port <= 65535):
                            raise ValueError("Invalid port range")

                        set_status_localized("status_checking_peer_status", ip=ip, port=port)

                        # Validate IP address format first
                        ip_obj = ipaddress.ip_address(ip) # This will raise ValueError for invalid IP strings

                        # Use asyncio.open_connection similar to SubnetScanner
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(ip, port), timeout=2.0
                        )
                        writer.close()
                        await writer.wait_closed()

                        ip_status_text.value = localization.get_string("status_online_short")
                        ip_status_text.color = ft.Colors.GREEN
                        set_status_localized("status_peer_online", ip=ip, port=port)

                    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                        ip_status_text.value = localization.get_string("status_offline_short")
                        ip_status_text.color = ft.Colors.RED
                        set_status_localized("status_peer_offline", ip=ip, port=port)
                    except ValueError as e: # Catch specific ValueError for IP or port validation
                        if "Invalid port range" in str(e):
                            ip_status_text.value = localization.get_string("status_invalid_short")
                            ip_status_text.color = ft.Colors.RED
                            direct_port_field.error_text = localization.get_string("error_invalid_port")
                            set_status(localization.get_string("status_invalid_port").format(port=port_str))
                        else: # Invalid IP address format
                            ip_status_text.value = localization.get_string("status_invalid_short")
                            ip_status_text.color = ft.Colors.RED
                            direct_ip_field.error_text = localization.get_string("error_invalid_ip")
                            set_status(localization.get_string("error_invalid_ip"))
                    except Exception as e:
                        print(f"DEBUG: Unexpected error during IP status check: {e}")
                        ip_status_text.value = localization.get_string("status_invalid_short")
                        ip_status_text.color = ft.Colors.RED
                        direct_port_field.error_text = localization.get_string("error_invalid_port")
                        set_status(localization.get_string("status_invalid_port").format(port=port_str))
                    page.update()
                except RuntimeError as e:
                    if "destroyed session" in str(e):
                        print("UI Log (session destroyed): Suppressed UI update in check_ip_status.")
                    else:
                        raise

            # These buttons are defined here so they can be passed to the send_to_target task
            send_to_ip_button = ft.ElevatedButton(localization.get_string("send_to_ip_button"), icon=ft.Icons.SEND, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8)), disabled=send_transfer_active)
            check_status_button = ft.OutlinedButton(localization.get_string("check_status_button"), icon=ft.Icons.NETWORK_CHECK)
            cancel_manual_send_button = ft.ElevatedButton(localization.get_string("cancel_transfer_button_short"), icon=ft.Icons.CANCEL, bgcolor=ft.Colors.RED_700, visible=False)

            def on_send_to_ip_click(_):
                ip = direct_ip_field.value.strip()
                if not ip:
                    direct_ip_field.error_text = localization.get_string("error_ip_required")
                    page.update()
                    return
                direct_ip_field.error_text = None
                try:
                    port = int(direct_port_field.value.strip())
                    page.run_task(send_to_target, ip, port, update_send_progress_direct_ip, direct_ip_send_progress_label, direct_ip_send_progress, send_to_ip_button, check_status_button, cancel_manual_send_button)
                except (ValueError, TypeError):
                    direct_port_field.error_text = localization.get_string("error_invalid_port")
                    page.update()

            def on_subnet_scan_click(_):
                subnet = subnet_field.value.strip()
                if not subnet:
                    subnet_field.error_text = localization.get_string("error_subnet_required")
                    page.update()
                    return
                subnet_field.error_text = None
                try:
                    port = int(subnet_port_field.value.strip())
                    device_list_card.visible = True
                    page.update()
                    page.run_task(start_subnet_scan, subnet, port)
                except (ValueError, TypeError):
                    subnet_port_field.error_text = localization.get_string("error_invalid_port")
                    page.update()
            
            direct_ip_field.on_submit = on_send_to_ip_click
            direct_port_field.on_submit = on_send_to_ip_click
            subnet_field.on_submit = on_subnet_scan_click
            subnet_port_field.on_submit = on_subnet_scan_click

            # Assign handlers now that they are defined
            send_to_ip_button.on_click = on_send_to_ip_click
            check_status_button.on_click = check_ip_status
            cancel_manual_send_button.on_click = lambda _: current_send_task.cancel() if current_send_task else None

            # 3. Define panels and complex controls that use the handlers
            auto_panel = ft.Column([
                ft.Row([sender_lan_selector, ft.IconButton(icon=ft.Icons.REFRESH, on_click=refresh_interfaces, tooltip=localization.get_string("refresh_network_list_tooltip"))]),
                sender_lan_helper,
                ft.ElevatedButton(localization.get_string("scan_for_receivers_button"), icon=ft.Icons.SEARCH, on_click=lambda _: page.run_task(start_scanner, True), style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8))),
            ], spacing=10, visible=False)

            direct_ip_panel = ft.Column([
                ft.Row([direct_ip_field, direct_port_field]),
                ft.Row([
                    send_to_ip_button,
                    check_status_button,
                    cancel_manual_send_button,
                    ip_status_text,
                ], alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                direct_ip_send_progress_label,
                direct_ip_send_progress,
            ], spacing=10, visible=False)

            subnet_scan_panel = ft.Column([
                 ft.Row([subnet_field, subnet_port_field, ft.IconButton(ft.Icons.HELP_OUTLINE, on_click=show_subnet_help, tooltip=localization.get_string("what_is_this_tooltip"))]),
                 ft.ElevatedButton(localization.get_string("scan_subnet_button"), icon=ft.Icons.SEARCH, on_click=on_subnet_scan_click, style=ft.ButtonStyle(shape=ft.RoundedRectangleBorder(radius=8))),
            ], visible=False)
            
            ip_mode_button = ft.ElevatedButton(localization.get_string("send_mode_direct_ip"), on_click=lambda _: select_manual_mode("ip"))
            subnet_mode_button = ft.OutlinedButton(localization.get_string("send_mode_subnet_scan"), on_click=lambda _: select_manual_mode("subnet"))

            def select_manual_mode(mode: str):
                sender_ui_state["manual_mode"] = mode
                is_ip = mode == "ip"
                direct_ip_panel.visible = is_ip
                subnet_scan_panel.visible = not is_ip
                device_list_card.visible = not is_ip
                ip_mode_button.style = ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700) if is_ip else None
                subnet_mode_button.style = ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700) if not is_ip else None
                page.update()

            manual_panel = ft.Column([ft.Row([ip_mode_button, subnet_mode_button]), ft.Divider(height=10), direct_ip_panel, subnet_scan_panel], spacing=10, visible=False)

            auto_mode_button = ft.ElevatedButton(localization.get_string("send_mode_auto"), on_click=lambda _: select_send_mode("auto"))
            manual_mode_button = ft.OutlinedButton(localization.get_string("send_mode_manual"), on_click=lambda _: select_send_mode("manual"))

            def select_send_mode(mode: str):
                sender_ui_state["send_mode"] = mode
                is_auto = mode == "auto"
                auto_panel.visible = is_auto
                manual_panel.visible = not is_auto
                device_list_card.visible = is_auto
                auto_mode_button.style = ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700) if is_auto else None
                manual_mode_button.style = ft.ButtonStyle(bgcolor=ft.Colors.BLUE_700) if not is_auto else None
                
                if not is_auto:
                    select_manual_mode(sender_ui_state["manual_mode"]) # Default to IP mode or last used manual mode
                
                nonlocal scanner, subnet_scanner
                if scanner: s = scanner; page.run_task(s.stop_scanning_async); scanner = None
                if subnet_scanner: subnet_scanner.cancel(); subnet_scanner = None
                devices.clear()
                _render_device_list()
                page.update()
                
                if is_auto:
                    page.run_task(start_scanner)

            # 4. Assemble the page
            body_controls.extend([
                ft.Card(ft.Container(ft.Column([
                    ft.Text(localization.get_string("connection_mode_title"), size=18, weight=ft.FontWeight.BOLD),
                    ft.Row([auto_mode_button, manual_mode_button]),
                    ft.Divider(height=10),
                    auto_panel,
                    manual_panel
                ]), padding=16)),
                ft.Card(ft.Container(ft.Column([
                    ft.Text(localization.get_string("select_files_title"), size=18, weight=ft.FontWeight.BOLD),
                    ft.Row([
                        ft.Container(content=ft.Row([ft.Icon(ft.Icons.UPLOAD_FILE, color=ft.Colors.BLUE_300), ft.Text(localization.get_string("add_files_button"), weight=ft.FontWeight.BOLD)], spacing=10), padding=ft.Padding(16, 12, 16, 12), border=ft.Border.all(1, ft.Colors.BLUE_GREY_600), border_radius=8, ink=True, on_click=lambda _: page.run_task(do_pick_files), expand=True),
                        ft.Container(content=ft.Row([ft.Icon(ft.Icons.FOLDER_OPEN, color=ft.Colors.AMBER_300), ft.Text(localization.get_string("add_folders_button"), weight=ft.FontWeight.BOLD)], spacing=10), padding=ft.Padding(16, 12, 16, 12), border=ft.Border.all(1, ft.Colors.BLUE_GREY_600), border_radius=8, ink=True, on_click=lambda _: page.run_task(do_get_directory), expand=True)
                    ], spacing=16),
                    selected_items_card
                ]), padding=16)),
                device_list_card,
                list_view_send_progress_label,
                list_view_send_progress,
            ])
            
            # Set initial state
            select_send_mode(sender_ui_state["send_mode"])

        elif page.route == "/receive":
            config = get_config()
            initial_firewall_settings = {"mode": config.get("firewall", {}).get("mode", "lan_only"), "port": str(config.get("network", {}).get("port", 35000)), "whitelist": list(config.get("firewall", {}).get("whitelist", []))}
            current_whitelist = list(initial_firewall_settings["whitelist"])
            save_fw_button = ft.ElevatedButton(localization.get_string("settings_save_button"), icon=ft.Icons.SAVE, on_click=lambda e: save_receiver_settings(e), disabled=True)
            page.appbar = ft.AppBar(title=ft.Text(localization.get_string("receive_files_title")), leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=go_back), actions=[save_fw_button])
            page.run_task(start_receiver)

            def check_fw_changes(_=None):
                mode_changed = firewall_mode.value != initial_firewall_settings["mode"]
                port_changed = port_field.value != initial_firewall_settings["port"]
                whitelist_changed = set(current_whitelist) != set(initial_firewall_settings["whitelist"])
                has_changed = mode_changed or port_changed or whitelist_changed
                save_fw_button.disabled = not has_changed
                save_fw_button.bgcolor = ft.Colors.BLUE_700 if has_changed else None
                page.update()

            firewall_mode = ft.RadioGroup(value=config.get("firewall", {}).get("mode", "lan_only"), content=ft.Column([ft.Radio(value="lan_only", label=localization.get_string("firewall_mode_lan")), ft.Radio(value="high_security", label=localization.get_string("firewall_mode_high_security")), ft.Radio(value="public", label=localization.get_string("firewall_mode_public"))]))
            port_field = ft.TextField(label=localization.get_string("listening_port_label"), value=str(config.get("network", {}).get("port", 35000)), width=150, keyboard_type=ft.KeyboardType.NUMBER, on_change=check_fw_changes)
            whitelist_field = ft.TextField(label=localization.get_string("add_ip_whitelist_label"), hint_text=localization.get_string("add_ip_whitelist_hint"))
            whitelist_view = ft.ListView(spacing=4, height=100)

            def render_whitelist():
                whitelist_view.controls.clear()
                for ip in current_whitelist:
                    def remove_ip(e, ip_to_remove=ip):
                        current_whitelist.remove(ip_to_remove)
                        render_whitelist()
                        check_fw_changes()
                    whitelist_view.controls.append(ft.Row([ft.Text(ip, expand=True), ft.IconButton(ft.Icons.DELETE, on_click=remove_ip, icon_size=16)]))
                page.update()

            def add_to_whitelist(_):
                ip = whitelist_field.value.strip()
                if ip:
                    try:
                        ipaddress.ip_address(ip)
                        if ip not in current_whitelist:
                            current_whitelist.append(ip)
                            render_whitelist()
                            check_fw_changes()
                        whitelist_field.value = ""
                        page.update()
                    except ValueError:
                        whitelist_field.error_text = localization.get_string("error_invalid_ip")
                        page.update()
            render_whitelist()
            high_security_panel = ft.Column([ft.Text(localization.get_string("high_security_panel_info"), size=12), ft.Row([whitelist_field, ft.ElevatedButton(localization.get_string("add_button"), on_click=add_to_whitelist)]), ft.Container(whitelist_view, border=ft.Border.all(1, ft.Colors.BLUE_GREY_800), border_radius=6, padding=8)], visible=(firewall_mode.value == "high_security"))
            lan_only_panel = ft.Text(localization.get_string("lan_only_panel_info"), size=12, visible=(firewall_mode.value == "lan_only"))
            public_panel = ft.Text(localization.get_string("public_panel_info"), color=ft.Colors.RED, size=12, visible=(firewall_mode.value == "public"))

            def on_firewall_mode_change(e):
                high_security_panel.visible = e.control.value == "high_security"
                lan_only_panel.visible = e.control.value == "lan_only"
                public_panel.visible = e.control.value == "public"
                page.update()

            def on_firewall_mode_change_and_check(e):
                on_firewall_mode_change(e)
                check_fw_changes(e)
            firewall_mode.on_change = on_firewall_mode_change_and_check

            def save_receiver_settings(_):
                new_config = get_config()
                new_config["firewall"]["mode"] = firewall_mode.value
                new_config["firewall"]["whitelist"] = current_whitelist
                try:
                    port_val = int(port_field.value)
                    if not (1024 <= port_val <= 65535): raise ValueError("Port out of range")
                    new_config.setdefault("network", {})["port"] = port_val
                    port_field.error_text = None
                except (ValueError, TypeError):
                    port_field.error_text = localization.get_string("error_invalid_port_range")
                    page.update()
                    return
                save_config(new_config)
                initial_firewall_settings["mode"] = new_config["firewall"]["mode"]
                initial_firewall_settings["port"] = str(new_config["network"]["port"])
                initial_firewall_settings["whitelist"] = list(current_whitelist)
                check_fw_changes()
                set_status(localization.get_string("status_settings_saved_restart"))
                page.snack_bar = ft.SnackBar(content=ft.Text(localization.get_string("settings_saved_snackbar")))
                page.snack_bar.open = True
                page.update()

            firewall_ui = ft.Column([ft.Text(localization.get_string("firewall_access_control_title"), size=18, weight=ft.FontWeight.BOLD), ft.Text(localization.get_string("firewall_access_control_subtitle"), size=12, color=ft.Colors.GREY_400), firewall_mode, high_security_panel, lan_only_panel, public_panel])
            
            def on_restart_click(_):
                set_status(localization.get_string("status_restarting_receiver"))
                page.run_task(restart_receiver)

            body_controls.extend([
                ft.Text(localization.get_string("listen_on_title"), size=18, weight=ft.FontWeight.BOLD),
                ft.Row([receiver_lan_selector, ft.IconButton(icon=ft.Icons.REFRESH, on_click=refresh_interfaces, tooltip=localization.get_string("refresh_network_list_tooltip"))]),
                receiver_lan_helper,
                ft.Row([
                    ft.OutlinedButton(localization.get_string("restart_receiver_button"), icon=ft.Icons.REFRESH, on_click=on_restart_click),
                    ft.OutlinedButton(localization.get_string("stop_receiver_button"), icon=ft.Icons.STOP, on_click=lambda _: page.run_task(stop_receiver))
                ], data="receiver_action_buttons_row", visible=not receive_transfer_active),
                ft.Row([
                    receive_progress_label,
                    ft.ElevatedButton(localization.get_string("cancel_transfer_button_short"), icon=ft.Icons.CANCEL, visible=receive_transfer_active, bgcolor=ft.Colors.RED_700, on_click=lambda _: current_receive_task.cancel() if current_receive_task else None, data="receive_cancel_button")
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, data="receive_progress_controls"),
                receive_progress,
                ft.Divider(),
                ft.Text(localization.get_string("network_settings_title"), size=16, weight=ft.FontWeight.BOLD),
                port_field,
                ft.Text(localization.get_string("wan_receive_info"), size=12, color=ft.Colors.AMBER_400),
                ft.Divider(),
                firewall_ui,
            ])

        elif page.route == "/trusted":
            page.appbar = ft.AppBar(title=ft.Text(localization.get_string("trusted_devices_title")), leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=go_back))
            store = list_trusted()
            controls = []
            if not store:
                controls.append(ft.Text(localization.get_string("no_trusted_devices")))
            else:
                sorted_devices = sorted(store.items(), key=lambda item: (item[1].get("name", "").lower(), item[0]))
                for fp, info in sorted_devices:
                    name = info.get("name") or localization.get_string("unnamed_device")
                    added = info.get("added")
                    try:
                        added_date_str = datetime.fromtimestamp(added).strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        added_date_str = localization.get_string("unknown_date")
                    def make_revoke(fingerprint):
                        def _(_e):
                            remove_trust(fingerprint)
                            route_change(None)
                        return _
                    controls.append(ft.ListTile(leading=ft.Icon(ft.Icons.COMPUTER), title=ft.Text(name, weight=ft.FontWeight.BOLD), subtitle=ft.Column([ft.Text(localization.get_string("fingerprint_label").format(fp=fp), font_family="monospace", size=12, selectable=True), ft.Text(localization.get_string("trusted_since_label").format(date=added_date_str), color=ft.Colors.GREY_500, size=11)], spacing=2), trailing=ft.TextButton(localization.get_string("revoke_button"), on_click=make_revoke(fp))))
            body_controls.extend([
                ft.Text(localization.get_string("trusted_devices_title"), size=18, weight=ft.FontWeight.BOLD),
                ft.Text(localization.get_string("trusted_devices_subtitle"), color=ft.Colors.GREY_400, size=12),
                ft.Divider(),
                ft.Column(controls, spacing=4),
            ])

        elif page.route == "/settings":
            current_config = get_config()
            defaults = get_default_config()
            initial_settings = {"language": current_config.get("language", defaults.get("language", "en")), "receive_mode": current_config.get("receive", {}).get("mode", defaults.get("receive", {}).get("mode", "fixed")), "receive_location": current_config.get("receive", {}).get("location", defaults.get("receive", {}).get("location", "")), "show_only_recommended_interfaces": current_config.get("ui", {}).get("show_only_recommended_interfaces", False)}

            def apply_language_and_restart(_):
                new_lang = lang_dropdown.value
                save_other_settings(_)
                config_to_save = get_config()
                config_to_save["language"] = new_lang
                save_config(config_to_save)
                localization.set_language(new_lang)
                page.go("/")

            def check_for_changes(_=None):
                mode_changed = receive_mode_group.value != initial_settings["receive_mode"]
                loc_changed = receive_location_field.value != initial_settings["receive_location"]
                show_only_recommended_changed = show_only_recommended_switch.value != initial_settings["show_only_recommended_interfaces"]
                settings_have_changed = mode_changed or loc_changed or show_only_recommended_changed
                save_button.disabled = not settings_have_changed
                save_button.bgcolor = ft.Colors.BLUE_700 if settings_have_changed else None
                save_button.update()

            async def open_directory_picker(_):
                selected_path = await settings_directory_picker.get_directory_path(dialog_title=localization.get_string("dialog_title_select_default_receive_folder"))
                if selected_path:
                    receive_location_field.value = selected_path
                    check_for_changes()
                    page.update()

            def save_other_settings(_):
                config_to_save = get_config()
                config_to_save["receive"]["mode"] = receive_mode_group.value
                config_to_save["receive"]["location"] = receive_location_field.value
                config_to_save.setdefault("ui", {})["show_only_recommended_interfaces"] = show_only_recommended_switch.value
                save_config(config_to_save)
                initial_settings["receive_mode"] = receive_mode_group.value
                initial_settings["receive_location"] = receive_location_field.value
                initial_settings["show_only_recommended_interfaces"] = show_only_recommended_switch.value
                check_for_changes()
                page.snack_bar = ft.SnackBar(content=ft.Text(localization.get_string("settings_saved_snackbar")))
                page.snack_bar.open = True
                page.update()

            save_button = ft.ElevatedButton(localization.get_string("settings_save_button"), icon=ft.Icons.SAVE, disabled=True, on_click=save_other_settings)
            page.appbar = ft.AppBar(title=ft.Text(localization.get_string("settings_title")), leading=ft.IconButton(ft.Icons.ARROW_BACK, on_click=go_back), actions=[save_button])
            lang_dropdown = ft.Dropdown(label=localization.get_string("settings_language_label"), value=initial_settings["language"], options=[ft.DropdownOption(code, name) for code, name in localization.get_available_languages()], expand=True)
            apply_lang_button = ft.ElevatedButton(localization.get_string("apply_and_reload_button"), icon=ft.Icons.RESTART_ALT, on_click=apply_language_and_restart)
            # The switch is now defined without a label, as it will be placed in a Row with a separate Text label.
            show_only_recommended_switch = ft.Switch(
                value=initial_settings["show_only_recommended_interfaces"],
                on_change=check_for_changes
            )
            receive_location_field = ft.TextField(label=None, value=initial_settings["receive_location"], read_only=True, expand=True)
            change_location_button = ft.ElevatedButton(localization.get_string("settings_change_location_button"), icon=ft.Icons.FOLDER_OPEN, on_click=open_directory_picker)
            fixed_location_row = ft.Row([receive_location_field, change_location_button], visible=(initial_settings["receive_mode"] == "fixed"))
            
            def on_receive_mode_change_wrapper(_):
                fixed_location_row.visible = (receive_mode_group.value == "fixed")
                check_for_changes()
                page.update()
            
            receive_mode_group = ft.RadioGroup(value=initial_settings["receive_mode"], content=ft.Column([ft.Radio(value="fixed", label=localization.get_string("settings_receive_mode_fixed")), ft.Container(content=fixed_location_row, padding=ft.Padding(left=30)), ft.Radio(value="ask", label=localization.get_string("settings_receive_mode_ask"))]), on_change=on_receive_mode_change_wrapper)
            
            body_controls.extend([
                ft.Card(content=ft.Container(padding=16, content=ft.Column([ft.Text(localization.get_string("settings_language_label"), size=18, weight=ft.FontWeight.BOLD), ft.Row([lang_dropdown, apply_lang_button], alignment=ft.MainAxisAlignment.START), ft.Text(localization.get_string("settings_language_restart_hint"), size=12, color=ft.Colors.AMBER_400, italic=True)], spacing=10))),
                ft.Card(content=ft.Container(padding=16, content=ft.Column([
                    ft.Text(localization.get_string("network_settings_title"), size=18, weight=ft.FontWeight.BOLD),
                    ft.Row([
                        ft.Text(localization.get_string("settings_show_only_recommended_interfaces_label")),
                        show_only_recommended_switch
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    ft.Text(localization.get_string("settings_show_only_recommended_interfaces_subtitle"), size=12, color=ft.Colors.GREY_500)
                ], spacing=10))),
                ft.Card(content=ft.Container(padding=16, content=ft.Column([ft.Text(localization.get_string("settings_receive_location_label"), size=18, weight=ft.FontWeight.BOLD), receive_mode_group], spacing=10))),
            ])

        # Set the new controls for the main content area.
        main_content_area.controls = body_controls
        page.update()

    # Subscribe to background message topics ONCE at application startup.
    page.pubsub.subscribe_topic("logs", on_log_message)
    page.pubsub.subscribe_topic("devices", on_device_update)

    def set_status(message: str):
        """Sends a log message to the UI via pubsub topic. This is thread-safe."""
        try:
            page.pubsub.send_all_on_topic("logs", message)
        except RuntimeError as e:
            # This can happen if the page session is destroyed during a background task.
            if "destroyed session" in str(e):
                print(f"UI Log (session destroyed): {message}")
            else:
                raise

    def set_status_localized(key: str, **kwargs):
        """Gets a localized string and updates the status bar."""
        message = localization.get_string(key).format(**kwargs)
        set_status(message)

    # Add the persistent layout containers to the page.
    page.add(main_content_area, status_container)

    async def on_page_disconnect(_=None):
        """Gracefully stop all background tasks when the UI session ends."""
        nonlocal scanner, announcer, server, server_task, subnet_scanner, current_send_task
        
        tasks_to_stop = []

        if scanner:
            tasks_to_stop.append(scanner.stop_scanning_async())
            scanner = None
        
        if announcer:
            tasks_to_stop.append(announcer.stop_async())
            announcer = None
        
        if server_task and not server_task.done():
            server_task.cancel()
            tasks_to_stop.append(server_task)
            server_task = None

        if subnet_scanner:
            subnet_scanner.cancel()
            subnet_scanner = None

        if current_send_task and not current_send_task.done():
            current_send_task.cancel()
            tasks_to_stop.append(current_send_task)
            current_send_task = None
        
        if tasks_to_stop:
            print("UI Log: Disconnecting, stopping background services...")
            try:
                await asyncio.gather(*tasks_to_stop, return_exceptions=True)
            except Exception as e:
                print(f"UI Log: Error during background service shutdown: {e}")
            print("UI Log: Background services stopped.")

    page.on_disconnect = on_page_disconnect
    page.on_route_change = route_change
    # Trigger the initial route to build the first view.
    route_change(None)
    
    # Send initial ready message after the first route is built and subscriptions are active.
    set_status(localization.get_string("status_ready"))


if __name__ == "__main__":
    ft.run(main, assets_dir="../assets")
