"""Smoke test: the app starts and every workspace renders without error.

Run with:
    python tests/test_app_smoke.py
"""

from streamlit.testing.v1 import AppTest


def _app() -> AppTest:
    app = AppTest.from_file("app.py", default_timeout=60)
    app.run()
    return app


def _assert_ok(app: AppTest, where: str) -> None:
    if app.exception:
        raise AssertionError(f"Exception in {where}: {app.exception}")


def main() -> None:
    app = _app()
    _assert_ok(app, "initial load")

    for workspace in ["🔴 Red Team", "🔵 Blue Team", "🧰 Sandbox Repair", "📊 Evaluation", "🔒 Security Audit"]:
        app.sidebar.radio[0].set_value(workspace).run()
        _assert_ok(app, workspace)

    app.sidebar.radio[0].set_value("🔴 Red Team").run()
    app.text_input[0].set_value("smoke-red").run()
    for button in app.button:
        if button.label == "Enter Red Team Workspace":
            button.click().run()
            break
    _assert_ok(app, "red team join")

    app.sidebar.radio[0].set_value("🔵 Blue Team").run()
    for text_input in app.text_input:
        text_input.set_value("smoke-blue")
    app.run()
    for button in app.button:
        if button.label == "Enter Blue Team Workspace":
            button.click().run()
            break
    _assert_ok(app, "blue team join")

    print("SMOKE TEST PASSED — all workspaces rendered without exception")


if __name__ == "__main__":
    main()
