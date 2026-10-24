"""BFF (Backend for Frontend) + servidor do front estático.

No modo BFF o browser nunca vê o access token: o BFF faz o PKCE, guarda o
token na sessão do servidor e entrega ao navegador apenas um cookie HttpOnly
(que o JavaScript não consegue ler).
"""

import secrets
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from common import API_URL, AUTH_SERVER_URL, CLIENTS, COOKIE_SECURE, FRONT_URL, pkce_challenge

CLIENT_ID = "bff-client"
REDIRECT_URI = f"{FRONT_URL}/bff/callback"
SESSION_COOKIE = "bff_session"
LOGIN_COOKIE = "bff_login"
SESSION_TTL = 30 * 60

# Sessões em memória. Em produção: Redis ou banco, com expiração.
_pending_logins: dict[str, dict] = {}  # id -> {state, code_verifier}
_sessions: dict[str, dict] = {}  # id -> {access_token, token_expires_at, expires_at}

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(title="BFF (POC)")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"connect-src 'self' {API_URL} {AUTH_SERVER_URL}; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"  # o ?code= não vaza no Referer
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _set_cookie(response, name: str, value: str, max_age: int) -> None:
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,  # JS não lê: protege contra roubo via XSS
        secure=COOKIE_SECURE,
        samesite="lax",  # não é enviado em POST/fetch de outros sites
        path="/",
    )


def _current_session(request: Request) -> dict | None:
    session = _sessions.get(request.cookies.get(SESSION_COOKIE, ""))
    if not session or session["expires_at"] < time.time():
        return None
    return session


@app.get("/bff/login")
def login():
    login_id = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)  # fica só no servidor
    state = secrets.token_urlsafe(32)
    _pending_logins[login_id] = {
        "state": state,
        "code_verifier": code_verifier,
        "expires_at": time.time() + 300,
    }
    query = urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "profile:read",
            "state": state,
            "code_challenge": pkce_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
    )
    response = RedirectResponse(f"{AUTH_SERVER_URL}/authorize?{query}", status_code=303)
    _set_cookie(response, LOGIN_COOKIE, login_id, 300)
    return response


@app.get("/bff/callback")
async def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    pending = _pending_logins.pop(request.cookies.get(LOGIN_COOKIE, ""), None)
    if error or not pending or pending["expires_at"] < time.time():
        return RedirectResponse("/?mode=bff&error=login_expirado", status_code=303)
    if not secrets.compare_digest(state, pending["state"]):
        return RedirectResponse("/?mode=bff&error=state_invalido", status_code=303)

    # Troca servidor-a-servidor: code + code_verifier + client_secret.
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            f"{AUTH_SERVER_URL}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "client_secret": CLIENTS[CLIENT_ID]["secret"],
                "code_verifier": pending["code_verifier"],
            },
        )
    if token_response.status_code != 200:
        return RedirectResponse("/?mode=bff&error=troca_de_token_falhou", status_code=303)

    tokens = token_response.json()
    # Sessão nova após o login (evita session fixation).
    session_id = secrets.token_urlsafe(32)
    _sessions[session_id] = {
        "access_token": tokens["access_token"],
        "token_expires_at": time.time() + tokens["expires_in"],
        "expires_at": time.time() + SESSION_TTL,
    }
    response = RedirectResponse("/?mode=bff", status_code=303)
    response.delete_cookie(LOGIN_COOKIE, path="/")
    _set_cookie(response, SESSION_COOKIE, session_id, SESSION_TTL)
    return response


@app.get("/bff/session")
def session_info(request: Request):
    return {"authenticated": _current_session(request) is not None}


@app.get("/bff/api/me")
async def proxy_me(request: Request):
    # Header customizado: um site de terceiros não consegue enviá-lo sem CORS,
    # então serve de defesa extra contra CSRF além do SameSite.
    if request.headers.get("X-Requested-With") != "fetch":
        return JSONResponse({"detail": "header X-Requested-With ausente"}, status_code=403)

    session = _current_session(request)
    if not session:
        return JSONResponse({"detail": "não autenticado"}, status_code=401)
    if session["token_expires_at"] < time.time():
        # Num cenário real o BFF usaria o refresh token aqui.
        _sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
        return JSONResponse({"detail": "sessão expirada, faça login de novo"}, status_code=401)

    async with httpx.AsyncClient() as client:
        api_response = await client.get(
            f"{API_URL}/me",
            headers={"Authorization": f"Bearer {session['access_token']}"},
        )
    return JSONResponse(api_response.json(), status_code=api_response.status_code)


@app.post("/bff/logout")
def logout(request: Request):
    if request.headers.get("X-Requested-With") != "fetch":
        return JSONResponse({"detail": "header X-Requested-With ausente"}, status_code=403)
    _sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
