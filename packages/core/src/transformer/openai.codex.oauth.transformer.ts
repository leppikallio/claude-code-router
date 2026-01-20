import { createApiError } from "@/api/middleware";
import { UnifiedChatRequest } from "@/types/llm";
import { Transformer } from "@/types/transformer";
import { getAuth, setAuth } from "@CCR/shared";

const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const ISSUER = "https://auth.openai.com";
const CODEX_API_ENDPOINT = "https://chatgpt.com/backend-api/codex/responses";
const REFRESH_SKEW_MS = 30 * 1000;

interface TokenResponse {
  id_token?: string;
  access_token: string;
  refresh_token: string;
  expires_in?: number;
}

interface IdTokenClaims {
  chatgpt_account_id?: string;
  organizations?: Array<{ id: string }>;
  email?: string;
  "https://api.openai.com/auth"?: {
    chatgpt_account_id?: string;
  };
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

async function refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
  const response = await fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }).toString(),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(`Token refresh failed: ${response.status} ${text}`.trim());
  }

  return response.json() as Promise<TokenResponse>;
}

export class OpenAICodexOAuthTransformer implements Transformer {
  name = "openai-codex-oauth";

  async transformRequestIn(
    request: UnifiedChatRequest
  ): Promise<{ body: UnifiedChatRequest; config: { headers: Record<string, string>; url: string } }> {
    const auth = await getAuth("openai");

    if (!auth || auth.type !== "oauth") {
      throw createApiError(
        "OpenAI OAuth is not configured. Run `ccr auth openai`.",
        401,
        "auth_required"
      );
    }

    if (auth.expires <= Date.now() + REFRESH_SKEW_MS) {
      const tokens = await refreshAccessToken(auth.refresh);
      const accountId = extractAccountId(tokens) || auth.accountId;
      const updated = {
        type: "oauth" as const,
        refresh: tokens.refresh_token,
        access: tokens.access_token,
        expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
        ...(accountId ? { accountId } : {}),
      };
      await setAuth("openai", updated);
      auth.access = updated.access;
      auth.accountId = updated.accountId;
    }

    const headers: Record<string, string> = {
      Authorization: `Bearer ${auth.access}`,
    };

    if (auth.accountId) {
      headers["ChatGPT-Account-Id"] = auth.accountId;
    }

    return {
      body: request,
      config: {
        headers,
        url: CODEX_API_ENDPOINT,
      },
    };
  }
}
