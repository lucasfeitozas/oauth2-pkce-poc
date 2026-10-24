# POC: OAuth2 Authorization Code + PKCE

Mostra como buscar os dados do usuário logado com `GET /me` **sem mandar ID nenhum**: a identidade vem do access token validado pela API.

> 📘 **Novo em OAuth2?** Leia antes o [guia de referência](docs/oauth2-pkce-referencia.md). Ele explica OAuth2 e PKCE do zero, com diagramas C4 (contexto, containers, componentes e código), diagramas UML de sequência e de atividade e um checklist de segurança para sistemas reais.

## Como rodar

```bash
./start.sh
```

Abra http://localhost:3000. Usuários de teste: `alice / alice123` e `bob / bob123`.

## Serviços

| Porta | Arquivo | Papel |
|-------|---------|-------|
| 9000 | `backend/auth_server.py` | Authorization Server: `/authorize` (login), `/token` (valida PKCE), JWKS |
| 8000 | `backend/api.py` | Resource Server: `GET /me` valida o JWT e usa o `sub` |
| 3000 | `backend/bff.py` | BFF + serve o front estático (`frontend/`) |

## Os dois modos do front

**Modo SPA**: o JavaScript gera `code_verifier`/`code_challenge` (Web Crypto), faz a troca em `/token` e guarda o token **só em memória**. Chama a API com `Authorization: Bearer`.

**Modo BFF (recomendado)**: o BFF faz todo o PKCE no servidor, troca o code usando `code_verifier` + `client_secret` e guarda o token na sessão do servidor. O browser recebe só um cookie `HttpOnly` e chama `/bff/api/me`, que repassa a chamada para a API com o Bearer.

O painel "Conversa HTTP" mostra cada passo. Botões para testar:

- **GET /me sem token**: 401.
- **GET /me com sub adulterado**: troca o `sub` do JWT pelo de outro usuário. Volta 401, porque a assinatura deixa de bater.
- **O que o JS vê do cookie?**: `document.cookie` vem vazio, pois o cookie de sessão é HttpOnly.

## Decisões de segurança no código

- **Sem `/users/{id}`**: só existe `/me`, então não há como trocar o ID na URL (IDOR).
- **`sub` opaco (UUID)**: o token não carrega e-mail, nome nem CPF. Lembre que o payload de um JWT é legível por qualquer um.
- **Na API, validação de** assinatura RS256 via JWKS, lista fixa de algoritmos, `iss`, `aud`, `exp` e escopo `profile:read`.
- **No Auth Server:** PKCE obrigatório com S256, `redirect_uri` com comparação exata, code de uso único com expiração de 60s, `state` obrigatório.
- **Token curto**: 5 minutos.
- **No BFF:** cookie `HttpOnly` + `SameSite=Lax`, rotação do ID de sessão após o login, header `X-Requested-With` como defesa extra contra CSRF, CSP e `Referrer-Policy: no-referrer`.
- **A API minimiza o que devolve**: o CPF sai mascarado.

## O que ficou de fora (próximos passos para produção)

- Usar um Authorization Server de verdade (Keycloak, Auth0, Cognito, Entra ID).
- Refresh token com rotação.
- Sessões e codes em Redis, em vez de memória.
- HTTPS em tudo, com `COOKIE_SECURE=true`.
- DPoP (RFC 9449) para amarrar o token ao cliente.
- Rate limit e proteção contra brute force no login.
