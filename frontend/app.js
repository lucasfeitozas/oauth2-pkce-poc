const AUTH_SERVER = "http://localhost:9000";
const API = "http://localhost:8000";
const SPA_CLIENT_ID = "spa-client";
const SPA_REDIRECT_URI = `${window.location.origin}/`;

// subs dos usuários de teste, usados só para a demonstração de adulteração
const DEMO_SUBS = {
  alice: "6f1c2a9e-3b7d-4e8a-9c51-2d4f8b0e7a13",
  bob: "a83d5f02-91c4-4b6e-8f27-c5e1d9a4b3f8",
};

// Modo SPA: o token vive só nesta variável. Nada de localStorage.
let accessToken = null;

const $ = (id) => document.getElementById(id);

// ---------- log da conversa (persistido em sessionStorage para sobreviver aos redirects) ----------

function readLog() {
  try {
    return JSON.parse(sessionStorage.getItem("flowLog") || "[]");
  } catch {
    return [];
  }
}

function writeLog(entries) {
  try {
    sessionStorage.setItem("flowLog", JSON.stringify(entries));
  } catch {
    // sem storage o log só não sobrevive aos redirects
  }
}

function log(kind, who, title, note, body) {
  const entries = readLog();
  entries.push({ kind, who, title, note, body });
  writeLog(entries);
  renderLog();
}

function renderLog() {
  const list = $("log");
  const entries = readLog();
  list.replaceChildren();
  $("log-empty").hidden = entries.length > 0;
  for (const entry of entries) {
    // textContent em tudo: nada vindo de fora vira HTML (evita XSS)
    const li = document.createElement("li");
    li.className = entry.kind;
    const who = document.createElement("div");
    who.className = "who";
    who.textContent = entry.who;
    const title = document.createElement("div");
    title.className = "title";
    title.textContent = entry.title;
    li.append(who, title);
    if (entry.note) {
      const note = document.createElement("p");
      note.className = "note";
      note.textContent = entry.note;
      li.append(note);
    }
    if (entry.body !== undefined) {
      const pre = document.createElement("pre");
      pre.textContent = typeof entry.body === "string" ? entry.body : JSON.stringify(entry.body, null, 2);
      li.append(pre);
    }
    list.append(li);
  }
  list.lastElementChild?.scrollIntoView({ block: "nearest" });
}

// ---------- utilitários PKCE / JWT ----------

function base64UrlEncode(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecodeToString(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="));
  return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

function randomString(byteLength) {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
}

async function s256(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

function decodeJwtPayload(token) {
  return JSON.parse(base64UrlDecodeToString(token.split(".")[1]));
}

function shortToken(token) {
  return `${token.slice(0, 24)}…${token.slice(-12)}`;
}

// ---------- Modo SPA ----------

async function spaLogin() {
  const codeVerifier = randomString(32);
  const codeChallenge = await s256(codeVerifier);
  const state = randomString(16);

  // O verifier precisa sobreviver ao redirect; sessionStorage é por aba e some ao fechar.
  // Ele é apagado logo após a troca pelo token.
  sessionStorage.setItem("pkce", JSON.stringify({ codeVerifier, state }));

  log("info", "Front (browser)", "1. Gera o par PKCE", "O code_verifier fica no cliente. Só o hash (code_challenge) vai para o Authorization Server.", {
    code_verifier: codeVerifier,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });

  const params = new URLSearchParams({
    response_type: "code",
    client_id: SPA_CLIENT_ID,
    redirect_uri: SPA_REDIRECT_URI,
    scope: "profile:read",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  const url = `${AUTH_SERVER}/authorize?${params}`;
  log("info", "Front → Auth Server", "2. Redireciona para /authorize", "O usuário faz login no Authorization Server, não na nossa aplicação.", `GET ${url}`);
  window.location.assign(url);
}

async function spaHandleCallback(code, state) {
  // Tira o code da URL (não fica no histórico nem vaza em Referer)
  history.replaceState(null, "", "/");

  let saved = null;
  try {
    saved = JSON.parse(sessionStorage.getItem("pkce"));
  } finally {
    sessionStorage.removeItem("pkce");
  }

  log("info", "Auth Server → Front", "3. Volta com ?code=…&state=…", "O code sozinho não vale nada sem o code_verifier.", { code, state });

  if (!saved || saved.state !== state) {
    log("err", "Front (browser)", "state não confere: login abortado", "Proteção contra CSRF no callback.");
    return;
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: SPA_REDIRECT_URI,
    client_id: SPA_CLIENT_ID,
    code_verifier: saved.codeVerifier,
  });
  log("info", "Front → Auth Server", "4. POST /token com code + code_verifier", "O servidor calcula SHA256(code_verifier) e compara com o code_challenge do passo 1.", `POST ${AUTH_SERVER}/token\n\n${body}`);

  const response = await fetch(`${AUTH_SERVER}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  const json = await response.json();
  if (!response.ok) {
    log("err", "Auth Server → Front", `Falha na troca: ${response.status}`, null, json);
    return;
  }

  accessToken = json.access_token;
  log("ok", "Auth Server → Front", "5. Recebe o access token (guardado só em memória)", "Payload decodificado: um JWT é assinado, não criptografado. Repare que não há e-mail, nome ou CPF, só um sub opaco.", decodeJwtPayload(accessToken));
  updateSpaUi();
}

async function callApiMe(token, label) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  log("info", "Front → API", label, "Nenhum ID na URL, no body ou na query. A API descobre o usuário pelo token.", `GET ${API}/me\nAuthorization: ${token ? `Bearer ${shortToken(token)}` : "(ausente)"}`);
  try {
    const response = await fetch(`${API}/me`, { headers });
    const json = await response.json();
    log(response.ok ? "ok" : "err", "API → Front", `HTTP ${response.status}`, null, json);
  } catch (error) {
    log("err", "API → Front", "Falha de rede", "A API está rodando na porta 8000?", String(error));
  }
}

function tamperedToken() {
  const [header, payload, signature] = accessToken.split(".");
  const claims = JSON.parse(base64UrlDecodeToString(payload));
  const victim = claims.sub === DEMO_SUBS.alice ? DEMO_SUBS.bob : DEMO_SUBS.alice;
  const forged = { ...claims, sub: victim };
  const forgedPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(forged)));
  log("info", "Atacante", "Troca o sub do token para o de outro usuário", "A assinatura RS256 deixa de bater, porque só o Authorization Server tem a chave privada.", { sub_original: claims.sub, sub_forjado: victim });
  return `${header}.${forgedPayload}.${signature}`;
}

function updateSpaUi() {
  const hasToken = accessToken !== null;
  $("spa-status").textContent = hasToken
    ? `Token em memória (expira em ${new Date(decodeJwtPayload(accessToken).exp * 1000).toLocaleTimeString()})`
    : "Sem token";
  $("spa-status").classList.toggle("ok", hasToken);
  for (const id of ["spa-me", "spa-me-tampered", "spa-forget"]) $(id).disabled = !hasToken;
}

// ---------- Modo BFF ----------

async function bffRefreshStatus() {
  try {
    const response = await fetch("/bff/session");
    const { authenticated } = await response.json();
    $("bff-status").textContent = authenticated ? "Sessão ativa (token guardado no BFF)" : "Sem sessão";
    $("bff-status").classList.toggle("ok", authenticated);
    return authenticated;
  } catch {
    $("bff-status").textContent = "BFF indisponível";
    return false;
  }
}

function bffLogin() {
  log("info", "Front → BFF", "1. GET /bff/login", "O BFF gera code_verifier e state no servidor e redireciona para o Authorization Server. O browser nunca vê o verifier.");
  window.location.assign("/bff/login");
}

async function bffMe() {
  log("info", "Front → BFF", "GET /bff/api/me", "Vai só o cookie de sessão (enviado pelo browser automaticamente). Nenhum token, nenhum ID.", "GET /bff/api/me\nCookie: bff_session=<HttpOnly, invisível para o JS>\nX-Requested-With: fetch");
  const response = await fetch("/bff/api/me", {
    credentials: "same-origin",
    headers: { "X-Requested-With": "fetch" },
  });
  const json = await response.json();
  if (response.ok) {
    log("ok", "BFF → API → BFF → Front", `HTTP ${response.status}`, "O BFF trocou o cookie pelo access token no servidor e chamou a API com Authorization: Bearer.", json);
  } else {
    log("err", "BFF → Front", `HTTP ${response.status}`, null, json);
  }
}

function bffShowCookie() {
  log("info", "Front (browser)", "document.cookie", "Cookies HttpOnly não aparecem aqui. Um XSS não consegue roubar a sessão nem o token.", JSON.stringify(document.cookie));
}

async function bffLogout() {
  await fetch("/bff/logout", { method: "POST", headers: { "X-Requested-With": "fetch" } });
  log("info", "Front → BFF", "POST /bff/logout", "A sessão é apagada no servidor e o cookie removido.");
  bffRefreshStatus();
}

// ---------- inicialização ----------

async function init() {
  $("spa-login").addEventListener("click", spaLogin);
  $("spa-me").addEventListener("click", () => callApiMe(accessToken, "GET /me com o token"));
  $("spa-me-no-token").addEventListener("click", () => callApiMe(null, "GET /me sem token"));
  $("spa-me-tampered").addEventListener("click", () => callApiMe(tamperedToken(), "GET /me com token adulterado"));
  $("spa-forget").addEventListener("click", () => {
    accessToken = null;
    updateSpaUi();
    log("info", "Front (browser)", "Token descartado", "É o mesmo que acontece ao recarregar a página: token em memória não persiste.");
  });

  $("bff-login").addEventListener("click", bffLogin);
  $("bff-me").addEventListener("click", bffMe);
  $("bff-cookie").addEventListener("click", bffShowCookie);
  $("bff-logout").addEventListener("click", bffLogout);
  $("clear-log").addEventListener("click", () => {
    writeLog([]);
    renderLog();
  });

  renderLog();

  const params = new URLSearchParams(window.location.search);
  if (params.has("code") && params.has("state")) {
    await spaHandleCallback(params.get("code"), params.get("state"));
  } else if (params.get("mode") === "bff") {
    history.replaceState(null, "", "/");
    if (params.has("error")) {
      log("err", "BFF → Front", `Login falhou: ${params.get("error")}`);
    } else {
      log("ok", "BFF → Front", "2. Login concluído", "O BFF recebeu o code, trocou por token (com code_verifier + client_secret) e criou uma sessão nova. O browser recebeu só Set-Cookie: bff_session (HttpOnly).");
    }
  } else if (params.has("error")) {
    history.replaceState(null, "", "/");
    log("err", "Auth Server → Front", `Erro: ${params.get("error")}`);
  }

  updateSpaUi();
  bffRefreshStatus();
}

init();
