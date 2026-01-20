import fs from "node:fs/promises";
import { AUTH_FILE, HOME_DIR } from "./constants";

export type OAuthAuthInfo = {
  type: "oauth";
  refresh: string;
  access: string;
  expires: number;
  accountId?: string;
};

export type ApiAuthInfo = {
  type: "api";
  key: string;
};

export type AuthInfo = OAuthAuthInfo | ApiAuthInfo;

async function ensureHomeDir(): Promise<void> {
  await fs.mkdir(HOME_DIR, { recursive: true });
}

export async function readAuthFile(): Promise<Record<string, AuthInfo>> {
  try {
    const raw = await fs.readFile(AUTH_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      return {};
    }
    return parsed as Record<string, AuthInfo>;
  } catch {
    return {};
  }
}

export async function writeAuthFile(data: Record<string, AuthInfo>): Promise<void> {
  await ensureHomeDir();
  await fs.writeFile(AUTH_FILE, JSON.stringify(data, null, 2));
  await fs.chmod(AUTH_FILE, 0o600);
}

export async function getAuth(providerId: string): Promise<AuthInfo | undefined> {
  const data = await readAuthFile();
  return data[providerId];
}

export async function setAuth(providerId: string, info: AuthInfo): Promise<void> {
  const data = await readAuthFile();
  data[providerId] = info;
  await writeAuthFile(data);
}

export async function removeAuth(providerId: string): Promise<void> {
  const data = await readAuthFile();
  delete data[providerId];
  await writeAuthFile(data);
}
