# Jira & Bitbucket Integration Setup Guide

This guide walks you through setting up Jira and Bitbucket integrations for the Remote Agentic Coding System, including Docker deployment and the automated PR review feature.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Docker Setup](#docker-setup)
3. [Jira Setup](#jira-setup)
4. [Bitbucket Setup](#bitbucket-setup)
5. [Auto-Clone & Branch Checkout](#auto-clone--branch-checkout)
6. [Automated PR Review Setup](#automated-pr-review-setup)
7. [Testing Your Setup](#testing-your-setup)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have:

- Docker and Docker Compose installed
- Admin access to your Jira Cloud instance
- Admin access to your Bitbucket workspace
- A publicly accessible URL for webhooks (or use ngrok for local testing)
- Claude API key or OAuth token

---

## Docker Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/remote-agentic-coding-system.git
cd remote-agentic-coding-system
```

### Step 2: Create Your Environment File

```bash
cp .env.example .env
```

Edit `.env` with your credentials (see sections below for specific values).

### Step 3: Start Docker

**With local PostgreSQL database:**
```bash
docker compose --profile with-db up -d --build
```

**With external database (Supabase, Neon, etc.):**
```bash
docker compose up -d --build
```

### Step 4: Verify Startup

```bash
docker compose logs -f app-with-db
```

You should see:
```
[App] Starting Remote Coding Agent (Telegram + Claude MVP)
[Database] Connected successfully
[Jira] Adapter initialized for https://your-domain.atlassian.net
[Jira] Bitbucket auto-clone enabled for: workspace/repo
[App] Remote Coding Agent is ready!
```

### Step 5: Set Up ngrok (for Local Testing)

If testing locally, you need a public URL for webhooks:

```bash
ngrok http 3000
```

Copy the HTTPS URL (e.g., `https://abc123.ngrok.io`) for webhook configuration.

**Note:** ngrok URLs change each time you restart. Update your webhooks when restarting ngrok.

### Docker Commands Reference

```bash
# Start services
docker compose --profile with-db up -d --build

# View logs
docker compose logs -f app-with-db

# Stop services
docker compose down

# Stop and remove volumes (full reset)
docker compose down --volumes

# Rebuild after code changes
docker compose --profile with-db up -d --build
```

---

## Jira Setup

### Step 1: Create a Jira API Token

1. Go to [Atlassian API Tokens](https://id.atlassian.com/manage/api-tokens)
2. Click **Create API token**
3. Enter a label (e.g., "Remote Coding Agent")
4. Click **Create**
5. **Copy the token immediately** - you won't see it again

### Step 2: Configure Environment Variables

Add these to your `.env` file:

```env
# Jira Configuration
JIRA_BASE_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your_api_token_from_step_1
JIRA_WEBHOOK_SECRET=generate_a_random_secret_string
JIRA_MENTION=@remote-agent
```

**Generate a webhook secret:**
```bash
openssl rand -hex 32
```

### Step 3: Create a Jira Webhook

1. Go to your Jira instance → **Settings** (gear icon) → **System**
2. Under **Advanced**, click **WebHooks**
3. Click **Create a WebHook**
4. Configure:
   - **Name**: Remote Coding Agent
   - **URL**: `https://your-server.com/webhooks/jira`
   - **Secret**: Same value as `JIRA_WEBHOOK_SECRET` in your `.env`
   - **Events**: Select:
     - Issue: created, updated
     - Comment: created

5. Click **Create**

### Step 4: Usage

Once configured, mention the agent in any Jira issue comment:

```
@remote-agent /command-invoke plan "implement this feature"
```

The agent will:
- Read the full issue context (title, description, status, etc.)
- Execute the command
- Post the response as a comment on the issue

---

## Bitbucket Setup

### Step 1: Create a Bitbucket App Password

1. Go to [Bitbucket App Passwords](https://bitbucket.org/account/settings/app-passwords/)
2. Click **Create app password**
3. Enter a label (e.g., "Remote Coding Agent")
4. Select permissions:
   - **Repositories**: Read, Write
   - **Pull requests**: Read, Write
   - **Issues**: Read, Write (if using Bitbucket Issues)
5. Click **Create**
6. **Copy the password immediately** - you won't see it again

### Step 2: Configure Environment Variables

Add these to your `.env` file:

```env
# Bitbucket Configuration
BITBUCKET_WORKSPACE=your_workspace_name
BITBUCKET_USERNAME=your_bitbucket_username
BITBUCKET_APP_PASSWORD=your_app_password_from_step_1
BITBUCKET_WEBHOOK_SECRET=generate_a_random_secret_string
BITBUCKET_MENTION=@remote-agent
```

**Note**: `BITBUCKET_WORKSPACE` is the workspace slug (found in your Bitbucket URL: `bitbucket.org/WORKSPACE/repo`)

### Step 3: Create a Bitbucket Webhook

1. Go to your repository in Bitbucket
2. Click **Repository settings** → **Webhooks**
3. Click **Add webhook**
4. Configure:
   - **Title**: Remote Coding Agent
   - **URL**: `https://your-server.com/webhooks/bitbucket`
   - **Secret**: Same value as `BITBUCKET_WEBHOOK_SECRET`
   - **Triggers**: Select:
     - Pull Request: Created, Updated, Comment created
     - Issue: Created, Updated, Comment created (if using Bitbucket Issues)

5. Click **Save**

### Step 4: Usage

Mention the agent in any PR or issue comment:

```
@remote-agent /command-invoke review
```

Or for free-form requests:

```
@remote-agent please review this PR for security issues
```

---

## Auto-Clone & Branch Checkout

When you mention `@remote-agent` in a Jira issue, the system can automatically:
1. Clone your Bitbucket repository (using your app password for authentication)
2. Checkout the branch matching the Jira ticket key (e.g., `ORDEV-123`)
3. Sync (git pull) on subsequent requests

This means you can simply ask questions about your code without manually cloning first.

### Configuration

Add these to your `.env` file:

```env
# Bitbucket credentials for authenticated cloning
BITBUCKET_USERNAME=your_bitbucket_username
BITBUCKET_APP_PASSWORD=your_app_password

# Default repository to clone (workspace/repo-name format)
BITBUCKET_DEFAULT_REPO=your-workspace/your-repo-name
```

**Note:** `BITBUCKET_DEFAULT_REPO` uses the format `workspace/repo-name` without `https://` or `.git`.

### How It Works

```
1. You comment in Jira issue ORDEV-123:
   "@remote-agent explain the changes in this ticket"

2. System checks if repo is cloned:
   ├── Not cloned: Clone from Bitbucket with authentication
   └── Already cloned: Fetch latest changes

3. System checks out branch:
   ├── Branch "ORDEV-123" exists: Checkout and pull
   └── Branch doesn't exist: Stay on default branch

4. AI processes your request with full codebase context
```

### Example Workflow

**First comment on ORDEV-123:**
```
@remote-agent what files were changed for this feature?
```

Server logs:
```
[Jira] Processing comment_created: ORDEV-123
[Jira] Using default Bitbucket repo: https://bitbucket.org/myworkspace/myrepo.git
[Jira] Cloning repository to /workspace/myrepo
[Jira] Fetching and checking out branch: ORDEV-123
[Jira] Checked out remote branch: ORDEV-123
```

**Subsequent comments:**
```
@remote-agent review the authentication logic
```

Server logs:
```
[Jira] Processing comment_created: ORDEV-123
[Jira] Fetching and checking out branch: ORDEV-123
[Jira] Pulled latest changes for branch: ORDEV-123
```

### Branch Naming Convention

The system expects branches to be named with the Jira ticket key:
- `ORDEV-123`
- `feature/ORDEV-123`
- `ORDEV-123-add-dark-mode`

All of these will match when working on issue `ORDEV-123`.

---

## Automated PR Review Setup

The automated PR review feature automatically reviews every new PR without requiring an @mention.

### Prerequisites

- Bitbucket adapter configured (see above)
- Jira adapter configured (for cross-posting reviews)
- PR titles or branches containing Jira ticket keys (e.g., `ORDEV-123`)

### Step 1: Enable Auto-Review

Add to your `.env` file:

```env
# Enable Automated PR Reviews
BITBUCKET_AUTO_REVIEW=true
```

### Step 2: Ensure Jira Credentials Are Set

The auto-review feature uses Jira credentials to:
1. Fetch ticket details for context
2. Post review comments to the linked Jira ticket

Required environment variables (should already be set from Jira setup):

```env
JIRA_BASE_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your_api_token
```

### Step 3: Configure Bitbucket Webhook for PR Creation

Ensure your Bitbucket webhook includes the **Pull Request: Created** trigger.

### Step 4: Naming Convention for Jira Linking

The system extracts Jira ticket keys from PRs using this pattern: `[A-Z]+-\d+`

Examples that will be detected:
- PR Title: `ORDEV-123: Add dark mode feature`
- Branch Name: `feature/ORDEV-123-dark-mode`
- PR Description: `This PR implements ORDEV-123`

### How It Works

```
1. Developer creates PR in Bitbucket
   └── Title: "ORDEV-123: Add user authentication"
   └── Branch: feature/ORDEV-123-auth

2. Bitbucket sends webhook to your server
   └── Event: pullrequest:created

3. System extracts Jira key: ORDEV-123

4. System fetches context:
   ├── Bitbucket: PR diff, changed files
   └── Jira: Ticket summary, description, acceptance criteria

5. AI performs Senior Developer code review:
   ├── Code quality
   ├── Security (OWASP top 10)
   ├── Architecture
   ├── Performance
   └── Requirements alignment

6. Review posted to:
   ├── Bitbucket PR (as comment)
   └── Jira ticket ORDEV-123 (as comment)
```

### Review Output Format

The automated review includes:

```markdown
## 🤖 Automated Code Review

### Summary
Brief overview of what the PR does and overall impression.

### Findings

#### 🔴 Critical Issues (must fix before merge)
- Security vulnerabilities, bugs, breaking changes

#### 🟡 Suggestions (should consider)
- Code quality improvements, better patterns

#### 🟢 Positive Observations
- Good practices noticed in the code

### Recommendation
**APPROVE** / **REQUEST CHANGES** / **NEEDS DISCUSSION**
```

---

## Testing Your Setup

### Test Jira Integration

1. Start your server:
   ```bash
   npm run dev
   ```

2. Create a test issue in Jira

3. Add a comment:
   ```
   @remote-agent /help
   ```

4. Check server logs for:
   ```
   [Jira] Processing comment_created: PROJ-123
   ```

5. Verify a response comment appears on the issue

### Test Bitbucket Integration

1. Create a test PR in Bitbucket

2. Add a comment:
   ```
   @remote-agent /status
   ```

3. Check server logs for:
   ```
   [Bitbucket] Processing pullrequest:comment_created: workspace/repo#pr:1
   ```

4. Verify a response comment appears on the PR

### Test Automated PR Review

1. Ensure `BITBUCKET_AUTO_REVIEW=true` is set

2. Create a new PR with a Jira key in the title:
   ```
   ORDEV-123: Add new feature
   ```

3. Check server logs for:
   ```
   [Bitbucket] Starting auto-review for PR #1: ORDEV-123: Add new feature
   [Bitbucket] Found Jira key: ORDEV-123
   [Bitbucket] Fetched diff (12345 chars) and 5 changed files
   [Bitbucket] Sending to AI for review...
   [Bitbucket] Auto-review completed for PR #1
   ```

4. Verify:
   - Review comment appears on Bitbucket PR
   - Review comment appears on Jira ticket ORDEV-123

---

## Troubleshooting

### Webhook Not Receiving Events

1. **Check URL accessibility**: Ensure your server is publicly accessible
2. **Check webhook secret**: Must match between Jira/Bitbucket and your `.env`
3. **Check server logs**: Look for incoming webhook requests
4. **Use ngrok for testing**:
   ```bash
   ngrok http 3000
   # Use the ngrok URL for webhooks
   ```

### Signature Verification Failed

```
[Jira] Invalid webhook signature
[Bitbucket] Signature mismatch
```

**Solution**: Ensure the webhook secret in your platform settings exactly matches `JIRA_WEBHOOK_SECRET` or `BITBUCKET_WEBHOOK_SECRET` in your `.env`

### @mention Not Detected

1. Check `JIRA_MENTION` or `BITBUCKET_MENTION` matches what you're typing
2. Ensure there's a space or punctuation after the mention:
   - ✅ `@remote-agent please help`
   - ✅ `@remote-agent, review this`
   - ❌ `@remote-agentplease help`

### Jira Ticket Not Found for Auto-Review

```
[Bitbucket] No Jira key found in PR title/branch/description
```

**Solution**: Include the Jira key in your PR:
- Title: `ORDEV-123: Feature description`
- Branch: `feature/ORDEV-123-feature-name`

### API Rate Limits

Both Jira and Bitbucket have API rate limits. If you're hitting limits:
- Reduce webhook frequency
- Implement request batching
- Consider upgrading your Atlassian plan

### Auto-Review Not Triggering

1. Verify `BITBUCKET_AUTO_REVIEW=true` is set
2. Verify Jira credentials are configured
3. Check the webhook includes `pullrequest:created` trigger
4. Check server logs for errors

---

## Environment Variables Summary

```env
# === DATABASE ===
DATABASE_URL=postgresql://postgres:postgres@postgres:5432/remote_coding_agent

# === AI ASSISTANT ===
CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
# OR use API key:
# CLAUDE_API_KEY=sk-ant-...
DEFAULT_AI_ASSISTANT=claude  # or 'codex'

# === JIRA ===
JIRA_BASE_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@example.com
JIRA_API_TOKEN=your_jira_api_token
JIRA_WEBHOOK_SECRET=your_random_secret
JIRA_MENTION=@remote-agent

# === BITBUCKET ===
BITBUCKET_WORKSPACE=your_workspace
BITBUCKET_USERNAME=your_username
BITBUCKET_APP_PASSWORD=your_app_password
BITBUCKET_WEBHOOK_SECRET=your_random_secret
BITBUCKET_MENTION=@remote-agent
BITBUCKET_DEFAULT_REPO=workspace/repo-name  # For Jira auto-clone

# === AUTOMATED PR REVIEW ===
BITBUCKET_AUTO_REVIEW=true  # Set to 'true' to enable
```

---

## Security Considerations

1. **Never commit `.env` to version control**
2. **Use strong, unique webhook secrets** (32+ random characters)
3. **Rotate API tokens periodically**
4. **Use HTTPS for all webhook URLs**
5. **Restrict App Password permissions** to minimum required
6. **Consider IP allowlisting** for webhook endpoints in production
