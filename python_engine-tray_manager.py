"""
Automa Shield - System Tray Desktop Integration (tray_manager.py)
Creates a system tray icon with quick actions and alert notifications.
"""

import threading
import logging
from typing import Callable, Optional

logger = logging.getLogger("AutomaShield.TrayManager")

class SystemTrayManager:
    def __init__(self,
                 app_title: str = "Automa Shield Endpoint Protection",
                 on_open_dashboard: Optional[Callable[[], None]] = None,
                 on_quick_scan: Optional[Callable[[], None]] = None,
                 on_toggle_realtime: Optional[Callable[[], None]] = None,
                 on_update_signatures: Optional[Callable[[], None]] = None,
                 on_exit: Optional[Callable[[], None]] = None):
        self.app_title = app_title
        self.on_open_dashboard = on_open_dashboard
        self.on_quick_scan = on_quick_scan
        self.on_toggle_realtime = on_toggle_realtime
        self.on_update_signatures = on_update_signatures
        self.on_exit = on_exit
        self.icon = None
        self._thread = None

    def start(self):
        try:
            import pystray
            from PIL import Image, ImageDraw

            # Generate procedural shield icon
            img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            draw.polygon([(32, 4), (58, 14), (58, 38), (32, 60), (6, 38), (6, 14)], fill="#0284c7", outline="#38bdf8")
            draw.polygon([(32, 14), (48, 22), (48, 36), (32, 48), (16, 36), (16, 22)], fill="#10b981")

            menu = pystray.Menu(
                pystray.MenuItem("🛡️ Open Automa Shield", lambda: self.on_open_dashboard and self.on_open_dashboard()),
                pystray.MenuItem("⚡ Run Quick Scan", lambda: self.on_quick_scan and self.on_quick_scan()),
                pystray.MenuItem("🔄 Update Signatures", lambda: self.on_update_signatures and self.on_update_signatures()),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit Automa Shield", lambda: self._stop_and_exit())
            )

            self.icon = pystray.Icon("AutomaShield", img, self.app_title, menu)
            self._thread = threading.Thread(target=self.icon.run, daemon=True, name="TrayThread")
            self._thread.start()
            logger.info("System Tray integration running.")
        except Exception as e:
            logger.info(f"System tray icon running in headless/background mode: {e}")

    def notify(self, title: str, message: str):
        if self.icon and hasattr(self.icon, "notify"):
            try:
                self.icon.notify(message, title)
            except Exception:
                pass
        logger.info(f"[Tray Notification] {title}: {message}")

    def _stop_and_exit(self):
        self.stop()
        if self.on_exit:
            self.on_exit()

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
        logger.info("System Tray manager stopped.")