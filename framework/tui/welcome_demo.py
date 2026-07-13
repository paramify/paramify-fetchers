"""Standalone preview of the welcome / manifest-selector screen.

    python -m framework.tui.welcome_demo

This does not enter the real app (the 4-tab UI) — it shows the WelcomeScreen
with sample manifests so the look-and-feel can be reviewed. Discovery runs for
real (against this repo) so the verification readout has answers to reveal.
"""

from textual.app import App

from framework import api
from framework.tui.screens.welcome import MOCK_MANIFESTS, WelcomeScreen


class WelcomeDemo(App):
    def on_mount(self) -> None:
        self.theme = "tokyo-night"
        try:
            self.root_path = api.locate_root()
            self.catalog_data = api.catalog(self.root_path)
        except Exception:
            self.root_path = None
            self.catalog_data = None
        self.push_screen(WelcomeScreen(MOCK_MANIFESTS))


def main() -> None:
    WelcomeDemo().run()


if __name__ == "__main__":
    main()
