#!/usr/bin/env python3
import sys
from getpass import getpass
from pathlib import Path

try:
    from werkzeug.security import generate_password_hash
except ImportError:
    print("Please install werkzeug first: python3 -m pip install werkzeug")
    raise


keycloak_backend_secret = Path(__file__).parent / Path("keycloak_backend/keycloak_backend.secret")
"""Secret file where the admin credentials are stored."""


def main():
    if keycloak_backend_secret.exists():
        print(f"{keycloak_backend_secret} exists, exiting.")
        sys.exit(1)

    keycloak_backend_username = input("Enter keycloak_backend username: ")
    keycloak_backend_password = getpass("Enter keycloak_backend password: ")

    try:
        keycloak_backend_hash = generate_password_hash(keycloak_backend_password)
    except AttributeError:
        # macOS is using another library where scrypt is not present by default.
        keycloak_backend_hash = generate_password_hash(keycloak_backend_password, method="pbkdf2:sha256:600000")

    with keycloak_backend_secret.open("w") as fp:
        fp.write(f"{keycloak_backend_username}@{keycloak_backend_hash}")


if __name__ == "__main__":
    main()
