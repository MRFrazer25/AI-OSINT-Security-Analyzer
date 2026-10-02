#!/usr/bin/env python3
"""Install/upgrade dependencies and check the local setup.

Usage: python setup_check.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REQUIRED_MODULES = ["streamlit", "cohere", "shodan", "requests", "dotenv"]


def check_python_version() -> bool:
    if sys.version_info < (3, 10):
        print(f"Python 3.10 or newer is required (found {sys.version.split()[0]}).")
        return False
    print(f"Python {sys.version.split()[0]}")
    return True


def install_requirements() -> bool:
    print("\nInstalling / upgrading packages from requirements.txt ...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "-r",
                               str(ROOT / "requirements.txt")])
        return True
    except subprocess.CalledProcessError as exc:
        print(f"pip failed: {exc}")
        return False


def verify_imports() -> bool:
    print("\nVerifying imports ...")
    ok = True
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
            print(f"  OK       {module}")
        except ImportError:
            print(f"  MISSING  {module}")
            ok = False
    try:
        sys.path.insert(0, str(ROOT))
        from ai import OSINT_TOOLS
        from osint_tools import classify_target

        assert classify_target("8.8.8.8").type == "ip"
        print(f"  OK       agent ({len(OSINT_TOOLS)} tools)")
    except Exception as exc:
        print(f"  FAILED   agent self-test: {exc}")
        ok = False
    return ok


def ensure_env_file() -> None:
    env, example = ROOT / ".env", ROOT / ".env.example"
    if env.exists():
        print("\n.env already exists")
    elif example.exists():
        shutil.copyfile(example, env)
        print("\nCreated .env from .env.example. Add your API keys to it.")


def main() -> None:
    print("AI OSINT Security Analyzer setup\n" + "=" * 40)
    if not check_python_version() or not install_requirements() or not verify_imports():
        sys.exit(1)
    ensure_env_file()
    from osint_tools import KEY_SIGNUP_URLS

    print("\nGet your API keys here (Cohere is required, the rest are optional):")
    for name, url in KEY_SIGNUP_URLS.items():
        print(f"  {name:<11} {url}")
    print("\nSetup complete. Start the app with:\n  python -m streamlit run app.py")


if __name__ == "__main__":
    main()
