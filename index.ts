import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { createSign } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

// ─── Token cache ──────────────────────────────────────────────────────────────
//
// Installation access tokens are valid for 60 minutes. We refresh at 55 minutes
// to maintain a safety buffer. The token is stored in module scope so it
// persists across tool calls within a session, and is injected into
// process.env.GH_TOKEN so every child process Pi spawns inherits it.

const TOKEN_TTL_MS = 55 * 60 * 1000;
let _token     = "";
let _fetchedAt = 0;

// ─── JWT generation ───────────────────────────────────────────────────────────
//
// GitHub App authentication is a two-step process:
//   1. Sign a short-lived JWT (max 10 min) using the App ID + RSA private key.
//   2. POST that JWT to GitHub to receive an installation access token scoped
//      to the specific repos selected when the App was installed.
//
// Uses Node's built-in crypto — no npm dependencies required.

function makeJWT(appId: string, privateKey: string): string {
  const now     = Math.floor(Date.now() / 1000);
  const header  = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iat: now - 60,   // Back-dated 60 s to absorb clock skew between host and GitHub
    exp: now + 600,  // 10 minutes — the maximum GitHub allows for an App JWT
    iss: appId,
  })).toString("base64url");
  const unsigned = `${header}.${payload}`;
  const signer   = createSign("RSA-SHA256");
  signer.update(unsigned);
  return `${unsigned}.${signer.sign(privateKey, "base64url")}`;
}

// ─── Installation token exchange ─────────────────────────────────────────────

async function refreshToken(signal?: AbortSignal): Promise<string> {
  const appId          = process.env.GITHUB_APP_ID;
  const installationId = process.env.GITHUB_INSTALLATION_ID;
  const keyPath        = process.env.GITHUB_PRIVATE_KEY_PATH;

  if (!appId || !installationId || !keyPath) {
    throw new Error(
      "Missing required environment variables: GITHUB_APP_ID, " +
      "GITHUB_INSTALLATION_ID, GITHUB_PRIVATE_KEY_PATH"
    );
  }

  const privateKey = await readFile(resolve(keyPath), "utf8");
  const appJWT     = makeJWT(appId, privateKey);

  const res = await fetch(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization:          `Bearer ${appJWT}`,
        Accept:                 "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal,
    }
  );

  if (!res.ok) {
    const body = await res.text().catch(() => "(no body)");
    throw new Error(`Token exchange failed (${res.status}): ${body}`);
  }

  const { token } = (await res.json()) as { token: string };

  _token               = token;
  _fetchedAt           = Date.now();
  process.env.GH_TOKEN = token;

  return token;
}

async function getToken(signal?: AbortSignal): Promise<string> {
  if (_token && Date.now() - _fetchedAt < TOKEN_TTL_MS) return _token;
  return refreshToken(signal);
}

// ─── Extension factory ────────────────────────────────────────────────────────

export default async function (pi: ExtensionAPI) {

  // ── session_start ──────────────────────────────────────────────────────────
  //
  // On every session start:
  //   1. Confirm all required env vars are present.
  //   2. Fetch a fresh installation token and set GH_TOKEN.
  //   3. Run `gh auth setup-git` to configure gh as a git credential helper
  //      for github.com, making `git push` work without embedding tokens in
  //      remote URLs. This command is idempotent and safe to run on every start.

  pi.on("session_start", async (_event, ctx) => {
    const missing = [
      "GITHUB_APP_ID",
      "GITHUB_INSTALLATION_ID",
      "GITHUB_PRIVATE_KEY_PATH",
    ].filter((k) => !process.env[k]);

    if (missing.length > 0) {
      ctx.ui.notify(
        `GitHub extension: missing env var(s): ${missing.join(", ")}. ` +
        "GitHub tools will not work this session.",
        "warning"
      );
      return;
    }

    try {
      await refreshToken();
      await pi.exec("gh", ["auth", "setup-git"], { timeout: 10_000 });
      ctx.ui.notify("GitHub: authenticated ✓", "info");
    } catch (err) {
      ctx.ui.notify(
        `GitHub: authentication failed — ${(err as Error).message}`,
        "error"
      );
    }
  });

  // ── before_agent_start ────────────────────────────────────────────────────
  //
  // Before each agent turn: silently refresh the token if it has passed its
  // TTL. This handles long sessions automatically. Errors are swallowed here —
  // if the silent refresh fails, the agent will encounter an auth error on the
  // next gh/git command and can call github_refresh_token to surface the cause.

  pi.on("before_agent_start", async (_event, _ctx) => {
    if (_token && Date.now() - _fetchedAt > TOKEN_TTL_MS) {
      await refreshToken().catch(() => {});
    }
  });

  // ── github_refresh_token ──────────────────────────────────────────────────
  //
  // Explicit refresh for two scenarios:
  //   - A gh or git command has returned a 401 or authentication error.
  //   - The agent wants to proactively refresh before a push in a session
  //     that has been running for more than 50 minutes.

  pi.registerTool({
    name: "github_refresh_token",
    label: "GitHub: Refresh Token",
    description:
      "Forces a new GitHub App installation access token to be fetched and sets " +
      "GH_TOKEN in the process environment. Call this if a gh or git command fails " +
      "with a 401 or authentication error, or proactively before git push in a " +
      "session that has been running for more than 50 minutes.",
    promptSnippet: "Refresh the GitHub App installation token",
    promptGuidelines: [
      "Call github_refresh_token if any gh or git command fails with a 401, " +
      "'bad credentials', or 'authentication failed' error — then retry the command.",
      "Call github_refresh_token proactively before git push if the current Pi " +
      "session has been running for more than 50 minutes.",
      "Do not call github_refresh_token on every turn — the before_agent_start " +
      "handler manages routine refresh automatically.",
    ],
    parameters: Type.Object({}),

    async execute(_id, _params, signal) {
      const token   = await refreshToken(signal);
      const preview = `${token.slice(0, 6)}…${token.slice(-4)}`;
      return {
        content: [{
          type: "text",
          text:
            `Token refreshed. GH_TOKEN updated (${preview}). ` +
            "gh and git commands are ready.",
        }],
        details: { refreshedAt: new Date().toISOString() },
      };
    },
  });
}
