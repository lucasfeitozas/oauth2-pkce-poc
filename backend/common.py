"""Configuração e dados compartilhados entre os três serviços da POC.

Em um cenário real cada serviço teria sua própria configuração e seu próprio
banco. Aqui ficam juntos só para a POC rodar sem infraestrutura extra.
"""

import base64
import hashlib
import hmac
import os

AUTH_SERVER_URL = "http://localhost:9000"
API_URL = "http://localhost:8000"
FRONT_URL = "http://localhost:3000"

ISSUER = AUTH_SERVER_URL
API_AUDIENCE = "poc-api"

# Em localhost via http o cookie Secure pode ser rejeitado por alguns browsers.
# Em produção (HTTPS) isso deve ser sempre True.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

CLIENTS = {
    # Cliente público: SPA rodando no browser, sem segredo. PKCE é obrigatório.
    "spa-client": {
        "public": True,
        "redirect_uris": [f"{FRONT_URL}/"],
    },
    # Cliente confidencial: o BFF, que roda no servidor e guarda um segredo.
    # Mesmo assim usa PKCE (recomendação do OAuth 2.1).
    "bff-client": {
        "public": False,
        "secret": os.getenv("BFF_CLIENT_SECRET", "bff-secret-only-for-poc"),
        "redirect_uris": [f"{FRONT_URL}/bff/callback"],
    },
}


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


def verify_password(password: str, salt: bytes, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password, salt), expected_hash)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def pkce_challenge(code_verifier: str) -> str:
    """code_challenge = BASE64URL(SHA256(code_verifier)) — método S256."""
    return b64url(hashlib.sha256(code_verifier.encode()).digest())


# O "sub" é um identificador opaco (UUID), não o e-mail nem o ID do banco.
# É a única ligação entre o Authorization Server e a API.
_SALT_ALICE = b"salt-alice-poc"
_SALT_BOB = b"salt-bob-poc"

AUTH_USERS = {
    "alice": {
        "sub": "6f1c2a9e-3b7d-4e8a-9c51-2d4f8b0e7a13",
        "salt": _SALT_ALICE,
        "password_hash": hash_password("alice123", _SALT_ALICE),
    },
    "bob": {
        "sub": "a83d5f02-91c4-4b6e-8f27-c5e1d9a4b3f8",
        "salt": _SALT_BOB,
        "password_hash": hash_password("bob123", _SALT_BOB),
    },
}

# "Banco" da API de recursos, indexado pelo sub.
USER_PROFILES = {
    "6f1c2a9e-3b7d-4e8a-9c51-2d4f8b0e7a13": {
        "name": "Alice Souza",
        "email": "alice@example.com",
        "cpf": "123.456.789-09",
        "plan": "premium",
    },
    "a83d5f02-91c4-4b6e-8f27-c5e1d9a4b3f8": {
        "name": "Bob Lima",
        "email": "bob@example.com",
        "cpf": "987.654.321-00",
        "plan": "free",
    },
}
