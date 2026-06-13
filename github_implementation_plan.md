# GitHub App Integration — Implementation Plan

## Objective

Install and verify a Pi extension that authenticates with GitHub via a GitHub App
installation token, injects that token as `GH_TOKEN` into the process environment,
and configures `gh` as a git credential helper — enabling all subsequent `gh` and
`git` commands to operate against permitted repositories without any further
authentication setup.

This plan is divided into four phases. Complete each phase fully and verify its
success criteria before moving to the next. Do not skip verification steps.

---

## Phase 1: Verify Prerequisites

### 1.1 — Check that the required environment variables are set

Run:
```bash
echo "GITHUB_APP_ID=${GITHUB_APP_ID}"
echo "GITHUB_INSTALLATION_ID=${GITHUB_INSTALLATION_ID}"
echo "GITHUB_PRIVATE_KEY_PATH=${GITHUB_PRIVATE_KEY_PATH}"
```

**Expected output:** All three variables print non-empty values.

**If any variable is empty:** Stop. The variables must be set in the shell
environment before Pi is launched. Do not proceed until they are present.
Inform the user which variables are missing.

### 1.2 — Verify the private key file exists and is a valid RSA PEM key

Run:
```bash
openssl rsa -in "$GITHUB_PRIVATE_KEY_PATH" -check -noout 2>&1
```

**Expected output:** `RSA key ok`

**If the file is not found:** Confirm the path in `GITHUB_PRIVATE_KEY_PATH` is
correct and absolute. Check that the file exists at that path. Report the exact
error to the user.

**If the output is `RSA key error` or similar:** The private key file is corrupt
or in the wrong format. The user needs to regenerate the key from the GitHub App
settings page and replace the file.

### 1.3 — Check whether `gh` is installed

Run:
```bash
gh --version
```

**Expected output:** A version string such as `gh version 2.x.x (...)`.

**If `gh` is not found:** Install it:

```bash
# Detect distro and install accordingly
if command -v apt-get &>/dev/null; then
  # Debian / Ubuntu
  (type -p wget >/dev/null || (sudo apt update && sudo apt-get install wget -y)) \
    && sudo mkdir -p -m 755 /etc/apt/keyrings \
    && out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    && cat $out | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
    && sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && sudo apt update \
    && sudo apt install gh -y
elif command -v dnf &>/dev/null; then
  sudo dnf install 'dnf-command(config-manager)' -y
  sudo dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
  sudo dnf install gh -y
else
  echo "Unsupported package manager. See https://github.com/cli/cli/blob/trunk/docs/install_linux.md"
fi
```

After installation, re-run `gh --version` and confirm a version string is printed
before continuing.

### 1.4 — Verify Node.js is at least version 18

The extension uses `Buffer.from(...).toString("base64url")`, which requires
Node 18+. Run:

```bash
node --version
```

**Expected output:** `v18.x.x` or higher.

**If Node is below v18:** The extension will fail at runtime. The user needs to
upgrade Node before proceeding.

---

## Phase 2: Write the Extension

### 2.1 — Create the extension directory

Run:
```bash
mkdir -p ~/.pi/agent/extensions/github
```

Verify it was created:
```bash
ls -la ~/.pi/agent/extensions/github
```

**Expected output:** An empty directory listing.

### 2.2 — Write the extension file

Create the file `~/.pi/agent/extensions/github/index.ts` with exactly the
following content. Do not modify any logic; comments are part of the specification.

```typescript
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
```

### 2.3 — Confirm the file was written correctly

Run:
```bash
wc -l ~/.pi/agent/extensions/github/index.ts
```

**Expected output:** A line count above 100. If the file is empty or very short,
the write failed — repeat step 2.2.

Also confirm there are no obvious syntax errors by checking that the structure
is intact:
```bash
grep -n "export default\|pi\.on\|pi\.registerTool\|makeJWT\|refreshToken\|getToken" \
  ~/.pi/agent/extensions/github/index.ts
```

**Expected output:** Lines matching all six of those identifiers. If any are
missing, the file is incomplete.

---

## Phase 3: Load and Verify the Extension

### 3.1 — Reload Pi to pick up the new extension

In the Pi session, run:
```
/reload
```

Watch the notification area.

**Expected output:** The notification `GitHub: authenticated ✓` appears in green.

**If the notification shows a warning about missing env vars:** The environment
variables are not visible to the Pi process. They may have been exported after Pi
was launched, or they may be set in a different shell. Restart Pi from a shell
where all three variables are present, then repeat.

**If the notification shows an authentication error:** Check the error message.
Common causes:
- `Token exchange failed (401)` — the App ID or installation ID is wrong. Verify
  both values against the GitHub App settings page.
- `Token exchange failed (404)` — the installation ID does not match an active
  installation for this App. Re-check the URL at `github.com/settings/installations`.
- `ENOENT` or file-not-found — `GITHUB_PRIVATE_KEY_PATH` points to a file that
  does not exist at that path.
- `error:09091064` or similar OpenSSL error — the `.pem` file is corrupt. The user
  needs to generate a new private key from the App settings page.

Do not continue to Phase 4 until the success notification appears.

### 3.2 — Call the refresh tool explicitly to confirm it works end-to-end

In the Pi session, invoke the tool:
```
github_refresh_token
```

**Expected output:** A response along the lines of:
```
Token refreshed. GH_TOKEN updated (ghs_ab…ef12). gh and git commands are ready.
```

The token preview (`ghs_ab…ef12`) should begin with `ghs_` — this is the prefix
GitHub uses for installation access tokens. If it begins with `ghp_` something
is wrong (that is a PAT format). Verify the App credentials and retry.

### 3.3 — Confirm GH_TOKEN is set in the shell environment

Run in bash:
```bash
echo "GH_TOKEN is set: $([ -n "$GH_TOKEN" ] && echo yes || echo NO)"
echo "Token prefix: ${GH_TOKEN:0:4}"
```

**Expected output:**
```
GH_TOKEN is set: yes
Token prefix: ghs_
```

### 3.4 — Confirm gh can authenticate

Run:
```bash
gh auth status
```

**Expected output:** Output referencing `GH_TOKEN` as the active token. The
displayed username may be blank or show as the App's bot account — this is
expected and normal for installation tokens.

---

## Phase 4: Verify GitHub Connectivity

### 4.1 — List accessible repositories

Run:
```bash
gh repo list --json nameWithOwner,defaultBranchRef --limit 100 | \
  jq -r '.[] | "\(.nameWithOwner)  [default: \(.defaultBranchRef.name)]"'
```

**Expected output:** A list of one or more repositories in `owner/repo` format.

**If the list is empty:** The GitHub App installation exists but has not been
granted access to any repositories. The user needs to go to
`github.com/settings/installations`, select the App, and add at least one
repository under "Repository access".

**If `gh` returns a 401:** Call `github_refresh_token` and repeat. If the 401
persists after a fresh token, the App credentials are wrong.

Record the full name (e.g. `owner/repo-name`) of the repository you will use
for the end-to-end test in Phase 5. Use a repository where opening a test PR
is acceptable.

### 4.2 — Confirm git credential helper is configured

Run:
```bash
git config --list --global | grep credential
```

**Expected output:** A line containing `credential.helper` referencing `gh`,
for example:
```
credential.helper=/usr/bin/gh auth git-credential
```

If this line is absent, `gh auth setup-git` did not run or did not persist.
Run it manually:
```bash
gh auth setup-git
```

Then re-run the `git config` check to confirm it appears.

---

## Phase 5: End-to-End Workflow Test

This phase performs a complete clone → branch → commit → push → PR cycle to
confirm the full integration works before it is relied upon for real tasks.

Use the repository identified in step 4.1. Replace `OWNER/REPO` in every
command below with that repository's full name.

### 5.1 — Clone the repository

```bash
gh repo clone OWNER/REPO ~/github-integration-test
```

**Expected output:** A `Cloning into '...'` message and no errors.

**If authentication fails during clone:** Run `github_refresh_token` and retry.

### 5.2 — Confirm the remote is set up correctly

```bash
git -C ~/github-integration-test remote -v
```

**Expected output:** Two lines showing `origin` pointing to
`https://github.com/OWNER/REPO.git`.

### 5.3 — Create a test branch

```bash
BRANCH="agent/integration-test-$(date +%s)"
git -C ~/github-integration-test checkout -b "$BRANCH"
echo "$BRANCH"
```

Record the branch name printed — you will need it in step 5.6.

### 5.4 — Make a trivial commit

```bash
echo "# Integration test $(date -u)" >> ~/github-integration-test/.github-integration-test.md
git -C ~/github-integration-test add .github-integration-test.md
git -C ~/github-integration-test commit -m "chore: github app integration test"
```

**Expected output:** A commit confirmation line such as:
```
[agent/integration-test-1234567890 abc1234] chore: github app integration test
```

### 5.5 — Push the branch

```bash
git -C ~/github-integration-test push origin "$BRANCH"
```

**Expected output:** Lines reporting the push, ending with something like:
```
* [new branch]      agent/integration-test-... -> agent/integration-test-...
```

**If push fails with `remote: Permission to ... denied`:** The installation token
does not have write access to this repository. Check the GitHub App's permissions
include "Contents: Read & Write" and that the repo is in the installation's
permitted list.

**If push fails with `authentication failed`:** Run `github_refresh_token`,
then retry the push.

**If push fails with `protected branch`:** You pushed to a protected branch.
This should not happen if the `agent/` branch was created correctly in step 5.3.
Confirm the branch name begins with `agent/`.

### 5.6 — Open a pull request

```bash
gh pr create \
  --repo OWNER/REPO \
  --title "chore: github app integration test" \
  --body "Automated integration test confirming Pi's GitHub App authentication is working. Safe to close." \
  --head "$BRANCH" \
  --base main
```

**Expected output:** A URL to the newly created PR, e.g.:
```
https://github.com/OWNER/REPO/pull/42
```

Print this URL clearly so the user can verify the PR exists on GitHub.

**If `gh pr create` returns a 422 with "A pull request already exists":** A PR
for this branch was already created. This should not happen on a fresh test branch
— check that `$BRANCH` is set to the value from step 5.3.

### 5.7 — Clean up the test clone

```bash
rm -rf ~/github-integration-test
```

The test PR and branch on GitHub should be left for the user to close and delete
at their discretion — do not attempt to close or merge the PR.

---

## Definition of Done

The implementation is complete and correct when all of the following are true:

- `~/.pi/agent/extensions/github/index.ts` exists and matches the content in
  Phase 2.
- Pi displays `GitHub: authenticated ✓` on session start and reload.
- `github_refresh_token` returns a token with the `ghs_` prefix.
- `gh repo list` returns the expected repositories.
- `git config --list --global` includes a `credential.helper` entry referencing `gh`.
- A test PR was successfully created and its URL was reported to the user.

If any of these criteria are not met, identify which phase failed, resolve the
issue using the error guidance in that phase, and re-run from that phase onward.
