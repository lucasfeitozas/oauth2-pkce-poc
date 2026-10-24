"""Authorization Server mínimo com Authorization Code + PKCE (S256).

Só para estudo: em produção use Keycloak, Auth0, Cognito, Entra ID etc.
"""

import html
import secrets
import time
import uuid
from urllib.parse import urlencode

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from common import (
    API_AUDIENCE,
    AUTH_USERS,
    CLIENTS,
    FRONT_URL,
    ISSUER,
    pkce_challenge,
    verify_password,
)

ACCESS_TOKEN_TTL = 300  # 5 minutos: token curto limita o estrago se vazar
CODE_TTL = 60
SUPPORTED_SCOPES = {"profile:read"}

# Chave gerada a cada start. A API descobre a chave pública pelo JWKS.
_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_kid = uuid.uuid4().hex[:16]

# code -> dados da autorização pendente (uso único)
_authorization_codes: dict[str, dict] = {}

app = FastAPI(title="Authorization Server (POC)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONT_URL],  # a SPA chama /token direto do browser
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"  # evita clickjacking na tela de login
    response.headers["Cache-Control"] = "no-store"
    return response


def _validate_authorize_params(params: dict) -> str | None:
    client = CLIENTS.get(params.get("client_id", ""))
    if not client:
        return "client_id desconhecido"
    # Comparação exata da redirect_uri: impede que o code seja enviado para outro lugar.
    if params.get("redirect_uri") not in client["redirect_uris"]:
        return "redirect_uri não registrada para este cliente"
    if params.get("response_type") != "code":
        return "response_type deve ser 'code'"
    if params.get("code_challenge_method") != "S256" or not params.get("code_challenge"):
        return "PKCE obrigatório com code_challenge_method=S256"
    if not params.get("state"):
        return "state obrigatório (proteção contra CSRF)"
    scopes = set(params.get("scope", "").split())
    if not scopes or not scopes <= SUPPORTED_SCOPES:
        return f"scope inválido; suportados: {', '.join(sorted(SUPPORTED_SCOPES))}"
    return None


def _login_page(params: dict, error: str = "") -> HTMLResponse:
    hidden = "\n".join(
        f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
        for k, v in params.items()
    )
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    client = html.escape(params.get("client_id", ""))
    scope = html.escape(params.get("scope", ""))
    return HTMLResponse(f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>Login - Auth Server</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {{ font-family: system-ui, sans-serif; background:#0f172a; color:#e2e8f0;
         display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }}
  form {{ background:#1e293b; padding:2rem; border-radius:12px; width:320px; }}
  h1 {{ font-size:1.2rem; margin-top:0; }}
  label {{ display:block; margin:.8rem 0 .3rem; font-size:.9rem; }}
  input[type=text], input[type=password] {{ width:100%; padding:.6rem; border-radius:6px;
         border:1px solid #334155; background:#0f172a; color:#e2e8f0; box-sizing:border-box; }}
  button {{ margin-top:1.2rem; width:100%; padding:.7rem; border:0; border-radius:6px;
           background:#6366f1; color:white; font-weight:600; cursor:pointer; }}
  .meta {{ font-size:.8rem; color:#94a3b8; }}
  .error {{ color:#f87171; }}
  code {{ color:#a5b4fc; }}
</style></head>
<body><form method="post" action="/authorize">
  <h1>Authorization Server</h1>
  <p class="meta">O cliente <code>{client}</code> pede acesso ao escopo <code>{scope}</code>.</p>
  <p class="meta">Usuários de teste: alice / alice123, bob / bob123</p>
  {error_html}
  <label for="username">Usuário</label>
  <input id="username" name="username" type="text" autocomplete="username" required autofocus>
  <label for="password">Senha</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  {hidden}
  <button type="submit">Entrar e autorizar</button>
</form></body></html>""")


AUTHORIZE_FIELDS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
)


@app.get("/authorize")
def authorize_form(request: Request):
    params = {k: request.query_params.get(k, "") for k in AUTHORIZE_FIELDS}
    error = _validate_authorize_params(params)
    if error:
        # Nunca redireciona para uma redirect_uri não validada.
        return HTMLResponse(f"<h1>Requisição inválida</h1><p>{html.escape(error)}</p>", 400)
    return _login_page(params)


@app.post("/authorize")
def authorize_submit(
    username: str = Form(...),
    password: str = Form(...),
    response_type: str = Form(""),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    scope: str = Form(""),
    state: str = Form(""),
    code_challenge: str = Form(""),
    code_challenge_method: str = Form(""),
):
    params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    error = _validate_authorize_params(params)
    if error:
        return HTMLResponse(f"<h1>Requisição inválida</h1><p>{html.escape(error)}</p>", 400)

    user = AUTH_USERS.get(username)
    if not user or not verify_password(password, user["salt"], user["password_hash"]):
        return _login_page(params, "Usuário ou senha inválidos")

    code = secrets.token_urlsafe(32)
    _authorization_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "scope": scope,
        "sub": user["sub"],
        "expires_at": time.time() + CODE_TTL,
    }
    # O code volta pela URL, mas sozinho não vale nada: sem o code_verifier
    # (que nunca saiu do cliente) ninguém troca ele por token.
    query = urlencode({"code": code, "state": state})
    return RedirectResponse(f"{redirect_uri}?{query}", status_code=303)


def _token_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": description}, status_code=status)


@app.post("/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: str = Form(...),
    client_secret: str = Form(""),
):
    if grant_type != "authorization_code":
        return _token_error("unsupported_grant_type", "apenas authorization_code")

    client = CLIENTS.get(client_id)
    if not client:
        return _token_error("invalid_client", "cliente desconhecido", 401)
    if not client["public"] and not secrets.compare_digest(client_secret, client["secret"]):
        return _token_error("invalid_client", "client_secret inválido", 401)

    # pop: o code é de uso único, mesmo se a validação abaixo falhar.
    data = _authorization_codes.pop(code, None)
    if not data or data["expires_at"] < time.time():
        return _token_error("invalid_grant", "code inválido, expirado ou já usado")
    if data["client_id"] != client_id or data["redirect_uri"] != redirect_uri:
        return _token_error("invalid_grant", "code não pertence a este cliente/redirect_uri")

    # O coração do PKCE: só quem gerou o verifier consegue produzir o challenge.
    if not secrets.compare_digest(pkce_challenge(code_verifier), data["code_challenge"]):
        return _token_error("invalid_grant", "code_verifier não confere com o code_challenge")

    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": data["sub"],  # opaco: não revela e-mail, CPF ou ID do banco
        "aud": API_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "jti": uuid.uuid4().hex,
        "scope": data["scope"],
        "client_id": client_id,
    }
    access_token = jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": _kid})
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL,
            "scope": data["scope"],
        }
    )


@app.get("/.well-known/jwks.json")
def jwks():
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(_private_key.public_key(), as_dict=True)
    jwk.update({"kid": _kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}
