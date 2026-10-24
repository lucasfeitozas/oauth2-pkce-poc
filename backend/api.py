"""API de recursos (Resource Server).

Não existe GET /users/{id}: o usuário é sempre o dono do token. Assim o
cliente não manda nenhum identificador, e trocar um ID na URL (IDOR) não é
possível.
"""

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from common import API_AUDIENCE, AUTH_SERVER_URL, FRONT_URL, ISSUER, USER_PROFILES

_jwks_client = jwt.PyJWKClient(f"{AUTH_SERVER_URL}/.well-known/jwks.json", cache_keys=True)

app = FastAPI(title="Resource API (POC)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONT_URL],
    allow_methods=["GET"],
    allow_headers=["Authorization"],
)


def _unauthorized(description: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=description,
        headers={"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{description}"'},
    )


def require_scope(scope: str):
    def dependency(request: Request) -> dict:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise _unauthorized("token ausente")
        token = auth.removeprefix("Bearer ").strip()
        try:
            signing_key = _jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],  # lista fixa: bloqueia alg=none e troca de algoritmo
                audience=API_AUDIENCE,  # token emitido para outra API não serve aqui
                issuer=ISSUER,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError:
            raise _unauthorized("token expirado")
        except (jwt.PyJWTError, jwt.PyJWKClientError) as exc:
            raise _unauthorized(f"token inválido: {exc}")

        if scope not in claims.get("scope", "").split():
            raise HTTPException(status_code=403, detail=f"escopo '{scope}' necessário")
        return claims

    return dependency


def _mask_cpf(cpf: str) -> str:
    # Minimização: mesmo para o dono, a API devolve só o necessário.
    return f"***.{cpf[4:7]}.***-**"


@app.get("/me")
def me(claims: dict = Depends(require_scope("profile:read"))):
    profile = USER_PROFILES.get(claims["sub"])
    if not profile:
        raise HTTPException(status_code=404, detail="perfil não encontrado")
    return {
        "name": profile["name"],
        "email": profile["email"],
        "cpf": _mask_cpf(profile["cpf"]),
        "plan": profile["plan"],
    }
