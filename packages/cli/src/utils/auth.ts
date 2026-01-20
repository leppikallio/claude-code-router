import http from "node:http";
import crypto from "node:crypto";
import { setAuth, removeAuth } from "@CCR/shared";

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const ISSUER = "https://auth.openai.com";
const OAUTH_PORT = 1455;
const REDIRECT_PATH = "/auth/callback";

interface PkceCodes {
  verifier: string;
  challenge: string;
}

interface TokenResponse {
  id_token?: string;
  access_token: string;
  refresh_token: string;
  expires_in?: number;
}

export interface IdTokenClaims {
  chatgpt_account_id?: string;
  organizations?: Array<{ id: string }>;
  email?: string;
  "https://api.openai.com/auth"?: {
    chatgpt_account_id?: string;
  };
}

function base64UrlEncode(buffer: Buffer): string {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function generateRandomString(length: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const bytes = crypto.randomBytes(length);
  return Array.from(bytes)
    .map((b) => chars[b % chars.length])
    .join("");
}

async function generatePKCE(): Promise<PkceCodes> {
  const verifier = generateRandomString(43);
  const hash = crypto.createHash("sha256").update(verifier).digest();
  const challenge = base64UrlEncode(hash);
  return { verifier, challenge };
}

function generateState(): string {
  return base64UrlEncode(crypto.randomBytes(32));
}

function buildAuthorizeUrl(redirectUri: string, pkce: PkceCodes, state: string): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    scope: "openid profile email offline_access",
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    id_token_add_organizations: "true",
    codex_cli_simplified_flow: "true",
    state,
    originator: "claude-code-router",
  });
  return `${ISSUER}/oauth/authorize?${params.toString()}`;
}

function parseJwtClaims(token: string): IdTokenClaims | undefined {
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
}

function extractAccountIdFromClaims(claims: IdTokenClaims): string | undefined {
  return (
    claims.chatgpt_account_id ||
    claims["https://api.openai.com/auth"]?.chatgpt_account_id ||
    claims.organizations?.[0]?.id
  );
}

function extractAccountId(tokens: TokenResponse): string | undefined {
  if (tokens.id_token) {
    const claims = parseJwtClaims(tokens.id_token);
    const accountId = claims && extractAccountIdFromClaims(claims);
    if (accountId) return accountId;
  }
  if (tokens.access_token) {
    const claims = parseJwtClaims(tokens.access_token);
    return claims ? extractAccountIdFromClaims(claims) : undefined;
  }
  return undefined;
}

async function exchangeCodeForTokens(code: string, redirectUri: string, pkce: PkceCodes): Promise<TokenResponse> {
  const response = await fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: CLIENT_ID,
      code_verifier: pkce.verifier,
    }).toString(),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Token exchange failed: ${response.status} ${text}`.trim());
  }

  return response.json() as Promise<TokenResponse>;
}

async function waitForOAuthCallback(state: string): Promise<string> {
  return new Promise((resolve, reject) => {
    let timeout: NodeJS.Timeout | undefined;

    const server = http.createServer((req, res) => {
      if (!req.url) {
        res.writeHead(404);
        res.end("Not found");
        return;
      }

      const url = new URL(req.url, `http://localhost:${OAUTH_PORT}`);
      if (url.pathname !== REDIRECT_PATH) {
        res.writeHead(404);
        res.end("Not found");
        return;
      }

      const error = url.searchParams.get("error");
      const errorDescription = url.searchParams.get("error_description");
      if (error) {
        const errorMsg = errorDescription || error;
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end(`Authorization failed: ${errorMsg}`);
        server.close();
        if (timeout) clearTimeout(timeout);
        reject(new Error(errorMsg));
        return;
      }

      const code = url.searchParams.get("code");
      const receivedState = url.searchParams.get("state");

      if (!code) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Missing authorization code");
        server.close();
        if (timeout) clearTimeout(timeout);
        reject(new Error("Missing authorization code"));
        return;
      }

      if (receivedState !== state) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("Invalid state");
        server.close();
        if (timeout) clearTimeout(timeout);
        reject(new Error("Invalid state"));
        return;
      }

      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("Authorization successful. You can close this window.");

      server.close();
      if (timeout) clearTimeout(timeout);
      resolve(code);
    });

    server.listen(OAUTH_PORT, "127.0.0.1");

    timeout = setTimeout(() => {
      server.close();
      reject(new Error("OAuth callback timeout - authorization took too long"));
    }, 5 * 60 * 1000);
  });
}

export async function loginOpenAI(): Promise<void> {
  const pkce = await generatePKCE();
  const state = generateState();
  const redirectUri = `http://localhost:${OAUTH_PORT}${REDIRECT_PATH}`;
  const authUrl = buildAuthorizeUrl(redirectUri, pkce, state);

  console.log("Open this URL in your browser to authorize OpenAI:");
  console.log(authUrl);
  console.log("Waiting for authorization...");

  const code = await waitForOAuthCallback(state);
  const tokens = await exchangeCodeForTokens(code, redirectUri, pkce);

  const accountId = extractAccountId(tokens);
  await setAuth("openai", {
    type: "oauth",
    refresh: tokens.refresh_token,
    access: tokens.access_token,
    expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
    ...(accountId ? { accountId } : {}),
  });

  console.log("OpenAI OAuth token saved.");
}

export async function logoutOpenAI(): Promise<void> {
  await removeAuth("openai");
  console.log("OpenAI OAuth token removed.");
}
