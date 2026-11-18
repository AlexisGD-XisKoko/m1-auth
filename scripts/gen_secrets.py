"""Genera los secretos locales de M1 y los imprime en formato .env.

Uso:  python scripts/gen_secrets.py >> .env
Nunca subas el resultado a Git. En integración/CI van en GitHub Secrets.
"""

import base64
import secrets


def b64(n: int = 32) -> str:
    return base64.b64encode(secrets.token_bytes(n)).decode()


def pw() -> str:
    return secrets.token_urlsafe(24)


if __name__ == "__main__":
    m1_owner, m1_app = pw(), pw()
    print("# --- Secretos generados por scripts/gen_secrets.py ---")
    print(f"KEK_BASE64={b64()}")
    print(f"PEPPER_BASE64={b64()}")
    print(f"EVENTS_HMAC_KEY_BASE64={b64()}")
    print(f"M1_OWNER_PASSWORD={m1_owner}")
    print(f"M1_APP_PASSWORD={m1_app}")
    print(f"OTHER_MODULES_PASSWORD={pw()}")
    print(f"BOOTSTRAP_ADMIN_PASSWORD={pw()}")
