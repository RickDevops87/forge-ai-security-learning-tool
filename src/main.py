"""AI Security Learning Tool — entry point."""
import sys
from src.ui.app import SecurityLabApp


def main() -> None:
    app = SecurityLabApp()
    app.run()


if __name__ == "__main__":
    main()