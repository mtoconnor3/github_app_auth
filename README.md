# GitHub App Integration Extension

This extension provides seamless, authenticated access to GitHub repositories for the Pi coding agent via a GitHub App installation. It handles JWT generation, token exchange, and automatic token refreshing, ensuring that `gh` and `git` commands work seamlessly without manual authentication.

## Features

- **Automatic Authentication**: Uses a GitHub App installation token to authenticate.
- **Token Lifecycle Management**: 
  - Generates short-lived JWTs for token exchange.
  - Automatically refreshes tokens every 55 minutes to maintain continuous access.
- **Environment Integration**: Injects the access token into `process.env.GH_TOKEN`, enabling all child processes (like `git` or `gh`) to use it.
- **Git Credential Helper**: Automatically configures `gh auth setup-git` on session start.
- **Manual Refresh Tool**: Provides a `github_refresh_token` tool for explicit token renewal.

## Prerequisites

The extension requires the following environment variables to be set in the shell before launching Pi:

| Variable | Description |
| :--- | :--- |
| `GITHUB_APP_ID` | The unique ID of your GitHub App. |
| `GITHUB_INSTALLATION_ID` | The ID of the specific installation of your GitHub App. |
| `GITHUB_PRIVATE_KEY_PATH` | The absolute path to your GitHub App's RSA private key (`.pem`). |

## Setup

1. **Configure GitHub App**: 
   - Create a GitHub App in your organization or user account.
   - Grant necessary permissions (e.g., "Repository contents: Read & Write").
   - Install the App to the desired repositories.
2. **Set Environment Variables**:
   ```bash
   export GITHUB_APP_ID="your_app_id"
   export GITHUB_INSTALLATION_ID="your_installation_id"
   export GITHUB_PRIVATE_KEY_PATH="/path/to/your/private-key.pem"
   ```
3. **Load the Extension**: Restart Pi or use the `/reload` command.

## Tools

### `github_refresh_token`
Forces a new GitHub App installation access token to be fetched and sets `GH_TOKEN` in the process environment.

**Use this when:**
- A `gh` or `git` command returns a 401 or authentication error.
- You want to proactively refresh the token during a long-running session (recommended before `git push`).
