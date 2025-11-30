/**
 * Jira platform adapter using Jira REST API and Webhooks
 * Handles issue comments with @mention detection
 */
import { createHmac } from 'crypto';
import { IPlatformAdapter } from '../types';
import { handleMessage } from '../orchestrator/orchestrator';
import * as db from '../db/conversations';
import * as codebaseDb from '../db/codebases';
import { exec } from 'child_process';
import { promisify } from 'util';
import { readdir, access } from 'fs/promises';
import { join } from 'path';

const execAsync = promisify(exec);

/**
 * Jira webhook event payload structure
 */
interface JiraWebhookEvent {
  webhookEvent: string;
  issue_event_type_name?: string;
  timestamp: number;
  user: {
    accountId: string;
    displayName: string;
    emailAddress?: string;
  };
  issue: {
    id: string;
    key: string;
    self: string;
    fields: {
      summary: string;
      description: string | null;
      issuetype: {
        name: string;
        subtask: boolean;
      };
      project: {
        key: string;
        name: string;
      };
      status: {
        name: string;
      };
      priority?: {
        name: string;
      };
      labels?: string[];
      reporter?: {
        displayName: string;
      };
      assignee?: {
        displayName: string;
      } | null;
    };
  };
  comment?: {
    id: string;
    body: string;
    author: {
      accountId: string;
      displayName: string;
    };
    created: string;
    updated: string;
  };
  changelog?: {
    items: {
      field: string;
      fromString: string | null;
      toString: string | null;
    }[];
  };
}

/**
 * Jira development info (linked repositories)
 */
interface JiraDevelopmentInfo {
  detail: {
    repositories: {
      name: string;
      url: string;
      commits?: { url: string }[];
    }[];
  }[];
}

export class JiraAdapter implements IPlatformAdapter {
  private baseUrl: string;
  private email: string;
  private apiToken: string;
  private webhookSecret: string;
  private mention: string;
  private bitbucketUsername?: string;
  private bitbucketAppPassword?: string;
  private bitbucketDefaultRepo?: string;

  constructor(config: {
    baseUrl: string;
    email: string;
    apiToken: string;
    webhookSecret: string;
    mention?: string;
    bitbucket?: {
      username: string;
      appPassword: string;
      defaultRepo?: string; // Format: workspace/repo-name
    };
  }) {
    this.baseUrl = config.baseUrl.replace(/\/$/, ''); // Remove trailing slash
    this.email = config.email;
    this.apiToken = config.apiToken;
    this.webhookSecret = config.webhookSecret;
    this.mention = config.mention || '@remote-agent';
    this.bitbucketUsername = config.bitbucket?.username;
    this.bitbucketAppPassword = config.bitbucket?.appPassword;
    this.bitbucketDefaultRepo = config.bitbucket?.defaultRepo;
    console.log(
      '[Jira] Adapter initialized for',
      this.baseUrl,
      'with secret:',
      this.webhookSecret.substring(0, 8) + '...'
    );
    if (this.bitbucketUsername && this.bitbucketDefaultRepo) {
      console.log('[Jira] Bitbucket auto-clone enabled for:', this.bitbucketDefaultRepo);
    }
  }

  /**
   * Get authorization header for Jira API
   */
  private getAuthHeader(): string {
    const credentials = Buffer.from(`${this.email}:${this.apiToken}`).toString('base64');
    return `Basic ${credentials}`;
  }

  /**
   * Send a message to a Jira issue as a comment
   */
  async sendMessage(conversationId: string, message: string): Promise<void> {
    const issueKey = conversationId;

    try {
      const response = await fetch(`${this.baseUrl}/rest/api/3/issue/${issueKey}/comment`, {
        method: 'POST',
        headers: {
          Authorization: this.getAuthHeader(),
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          body: {
            type: 'doc',
            version: 1,
            content: [
              {
                type: 'paragraph',
                content: [
                  {
                    type: 'text',
                    text: message,
                  },
                ],
              },
            ],
          },
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Jira API error: ${response.status} - ${errorText}`);
      }

      console.log(`[Jira] Comment posted to ${issueKey}`);
    } catch (error) {
      console.error('[Jira] Failed to post comment:', { error, issueKey });
    }
  }

  /**
   * Get streaming mode (always batch for Jira to avoid comment spam)
   */
  getStreamingMode(): 'batch' {
    return 'batch';
  }

  /**
   * Get platform type
   */
  getPlatformType(): string {
    return 'jira';
  }

  /**
   * Start the adapter (no-op for webhook-based adapter)
   */
  async start(): Promise<void> {
    console.log('[Jira] Webhook adapter ready');
  }

  /**
   * Stop the adapter (no-op for webhook-based adapter)
   */
  stop(): void {
    console.log('[Jira] Adapter stopped');
  }

  /**
   * Verify webhook signature using HMAC SHA-256
   * Jira Cloud webhooks use the secret as the key for HMAC-SHA256
   */
  private verifySignature(payload: string, signature: string): boolean {
    try {
      // Jira uses x-hub-signature format: sha256=<signature>
      const hmac = createHmac('sha256', this.webhookSecret);
      const digest = 'sha256=' + hmac.update(payload).digest('hex');
      const isValid = digest === signature;

      if (!isValid) {
        console.error('[Jira] Signature mismatch:', {
          received: signature?.substring(0, 15) + '...',
          computed: digest.substring(0, 15) + '...',
          secretLength: this.webhookSecret.length,
        });
      }

      return isValid;
    } catch (error) {
      console.error('[Jira] Signature verification error:', error);
      return false;
    }
  }

  /**
   * Check if text contains @mention
   */
  private hasMention(text: string): boolean {
    const escapedMention = this.mention.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`${escapedMention}[\\s,:;]|^${escapedMention}$`);
    return regex.test(text);
  }

  /**
   * Strip @mention from text
   */
  private stripMention(text: string): string {
    const escapedMention = this.mention.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`${escapedMention}[\\s,:;]+`, 'g');
    return text.replace(regex, '').trim();
  }

  /**
   * Parse webhook event and extract relevant data
   */
  private parseEvent(event: JiraWebhookEvent): {
    issueKey: string;
    comment: string;
    eventType: 'issue_created' | 'issue_updated' | 'comment_created';
    issue: JiraWebhookEvent['issue'];
  } | null {
    const { webhookEvent, issue, comment } = event;

    // Handle comment events
    if (webhookEvent === 'comment_created' && comment) {
      return {
        issueKey: issue.key,
        comment: comment.body,
        eventType: 'comment_created',
        issue,
      };
    }

    // Handle issue created with @mention in description
    if (webhookEvent === 'jira:issue_created' && issue.fields.description) {
      return {
        issueKey: issue.key,
        comment: issue.fields.description,
        eventType: 'issue_created',
        issue,
      };
    }

    // Handle issue updated (check if description changed and has mention)
    if (webhookEvent === 'jira:issue_updated' && event.changelog) {
      const descriptionChange = event.changelog.items.find(item => item.field === 'description');
      if (descriptionChange?.toString) {
        return {
          issueKey: issue.key,
          comment: descriptionChange.toString,
          eventType: 'issue_updated',
          issue,
        };
      }
    }

    return null;
  }

  /**
   * Build context-rich message for Jira issue
   */
  private buildIssueContext(issue: JiraWebhookEvent['issue'], userComment: string): string {
    const { key, fields } = issue;
    const labels = fields.labels?.join(', ') || 'None';

    return `[Jira Issue Context]
Issue ${key}: "${fields.summary}"
Type: ${fields.issuetype.name}
Project: ${fields.project.name} (${fields.project.key})
Status: ${fields.status.name}
Priority: ${fields.priority?.name || 'Not set'}
Labels: ${labels}
Reporter: ${fields.reporter?.displayName || 'Unknown'}
Assignee: ${fields.assignee?.displayName || 'Unassigned'}

Description:
${fields.description || 'No description'}

---

${userComment}`;
  }

  /**
   * Try to find linked repository from Jira development info
   */
  private async getLinkedRepository(issueKey: string): Promise<string | null> {
    try {
      // Jira Cloud development info endpoint
      const response = await fetch(
        `${this.baseUrl}/rest/dev-status/latest/issue/detail?issueId=${issueKey}&applicationType=bitbucket&dataType=repository`,
        {
          headers: {
            Authorization: this.getAuthHeader(),
            Accept: 'application/json',
          },
        }
      );

      if (!response.ok) {
        return null;
      }

      const data = (await response.json()) as JiraDevelopmentInfo;
      const repo = data.detail?.[0]?.repositories?.[0];

      if (repo?.url) {
        return repo.url;
      }

      return null;
    } catch (error) {
      console.log('[Jira] Could not fetch development info:', error);
      return null;
    }
  }

  /**
   * Build authenticated clone URL for Bitbucket
   */
  private getAuthenticatedCloneUrl(repoUrl: string): string {
    if (!this.bitbucketUsername || !this.bitbucketAppPassword) {
      return repoUrl;
    }

    // URL-encode username and password to handle special characters like @ in email addresses
    const encodedUsername = encodeURIComponent(this.bitbucketUsername);
    const encodedPassword = encodeURIComponent(this.bitbucketAppPassword);

    // Handle various Bitbucket URL formats
    // https://bitbucket.org/workspace/repo.git -> https://user:pass@bitbucket.org/workspace/repo.git
    if (repoUrl.includes('bitbucket.org')) {
      if (repoUrl.startsWith('https://bitbucket.org')) {
        return repoUrl.replace(
          'https://bitbucket.org',
          `https://${encodedUsername}:${encodedPassword}@bitbucket.org`
        );
      } else if (repoUrl.startsWith('http://bitbucket.org')) {
        return repoUrl.replace(
          'http://bitbucket.org',
          `https://${encodedUsername}:${encodedPassword}@bitbucket.org`
        );
      }
    }

    return repoUrl;
  }

  /**
   * Ensure repository is cloned, synced, and on the correct branch
   */
  private async ensureRepoReady(
    repoUrl: string,
    repoPath: string,
    issueKey: string,
    shouldSync: boolean
  ): Promise<void> {
    const branchName = issueKey; // Branch name matches Jira ticket key (e.g., ORDEV-123)
    let repoExists = false;

    try {
      await access(repoPath);
      repoExists = true;
    } catch {
      repoExists = false;
    }

    if (!repoExists) {
      // Clone the repo with authentication
      const authUrl = this.getAuthenticatedCloneUrl(repoUrl);
      console.log(`[Jira] Cloning repository to ${repoPath}`);
      await execAsync(`git clone ${authUrl} ${repoPath}`);
      await execAsync(`git config --global --add safe.directory '${repoPath}'`);
    }

    // Fetch and checkout branch
    try {
      console.log(`[Jira] Fetching and checking out branch: ${branchName}`);
      await execAsync(`cd ${repoPath} && git fetch origin`);

      // Try to checkout the branch (may be local or remote)
      try {
        await execAsync(`cd ${repoPath} && git checkout ${branchName}`);
        console.log(`[Jira] Checked out branch: ${branchName}`);
      } catch {
        // Branch doesn't exist locally, try to checkout from remote
        try {
          await execAsync(`cd ${repoPath} && git checkout -b ${branchName} origin/${branchName}`);
          console.log(`[Jira] Checked out remote branch: ${branchName}`);
        } catch {
          // Branch doesn't exist at all, stay on current branch
          console.log(`[Jira] Branch ${branchName} not found, staying on default branch`);
        }
      }

      // Pull latest changes if syncing
      if (shouldSync) {
        try {
          await execAsync(`cd ${repoPath} && git pull origin ${branchName}`);
          console.log(`[Jira] Pulled latest changes for branch: ${branchName}`);
        } catch {
          console.log(`[Jira] Could not pull branch ${branchName}, may not track remote`);
        }
      }
    } catch (error) {
      console.error('[Jira] Git operation failed:', error);
    }
  }

  /**
   * Auto-detect and load commands from .claude/commands or .agents/commands
   */
  private async autoDetectAndLoadCommands(repoPath: string, codebaseId: string): Promise<void> {
    const commandFolders = ['.claude/commands', '.agents/commands'];

    for (const folder of commandFolders) {
      try {
        const fullPath = join(repoPath, folder);
        await access(fullPath);

        const files = (await readdir(fullPath)).filter(f => f.endsWith('.md'));
        if (files.length === 0) continue;

        const commands = await codebaseDb.getCodebaseCommands(codebaseId);
        files.forEach(file => {
          commands[file.replace('.md', '')] = {
            path: join(folder, file),
            description: `From ${folder}`,
          };
        });

        await codebaseDb.updateCodebaseCommands(codebaseId, commands);
        console.log(`[Jira] Loaded ${files.length} commands from ${folder}`);
        return;
      } catch {
        continue;
      }
    }
  }

  /**
   * Get or create codebase for repository
   */
  private async getOrCreateCodebaseForRepo(
    repoUrl: string,
    repoName: string
  ): Promise<{ codebase: { id: string; name: string }; repoPath: string; isNew: boolean }> {
    const existing = await codebaseDb.findCodebaseByRepoUrl(repoUrl);

    if (existing) {
      console.log(`[Jira] Using existing codebase: ${existing.name} at ${existing.default_cwd}`);
      return { codebase: existing, repoPath: existing.default_cwd, isNew: false };
    }

    const repoPath = `/workspace/${repoName}`;
    const codebase = await codebaseDb.createCodebase({
      name: repoName,
      repository_url: repoUrl,
      default_cwd: repoPath,
    });

    console.log(`[Jira] Created new codebase: ${codebase.name} at ${repoPath}`);
    return { codebase, repoPath, isNew: true };
  }

  /**
   * Handle incoming webhook event
   */
  async handleWebhook(payload: string, signature: string): Promise<void> {
    // 1. Verify signature (if provided - some Jira setups may not use it)
    if (signature && !this.verifySignature(payload, signature)) {
      console.error('[Jira] Invalid webhook signature');
      return;
    }

    // 2. Parse event
    const event: JiraWebhookEvent = JSON.parse(payload);
    const parsed = this.parseEvent(event);
    if (!parsed) return;

    const { issueKey, comment, eventType, issue } = parsed;

    // 3. Check @mention
    if (!this.hasMention(comment)) return;

    console.log(`[Jira] Processing ${eventType}: ${issueKey}`);

    // 4. Build conversationId (Jira issue key is unique)
    const conversationId = issueKey;

    // 5. Check if new conversation
    const existingConv = await db.getOrCreateConversation('jira', conversationId);
    const isNewConversation = !existingConv.codebase_id;

    // 6. Try to find linked repository (or use default Bitbucket repo)
    let repoUrl = await this.getLinkedRepository(issueKey);

    // Fall back to default Bitbucket repo if no linked repo found
    if (!repoUrl && this.bitbucketDefaultRepo) {
      repoUrl = `https://bitbucket.org/${this.bitbucketDefaultRepo}.git`;
      console.log(`[Jira] Using default Bitbucket repo: ${repoUrl}`);
    }

    let codebase: { id: string; name: string } | null = null;
    let repoPath: string | null = null;
    let isNewCodebase = false;

    if (repoUrl) {
      // Extract repo name from URL
      const repoName =
        repoUrl.split('/').pop()?.replace('.git', '') || issue.fields.project.key.toLowerCase();
      const result = await this.getOrCreateCodebaseForRepo(repoUrl, repoName);
      codebase = result.codebase;
      repoPath = result.repoPath;
      isNewCodebase = result.isNew;

      // Always ensure repo is cloned and on correct branch
      // - First time: clone and checkout branch
      // - Subsequent times: fetch and sync branch
      await this.ensureRepoReady(repoUrl, repoPath, issueKey, !isNewConversation);

      // Auto-load commands if new codebase
      if (isNewCodebase) {
        await this.autoDetectAndLoadCommands(repoPath, codebase.id);
      }

      // Update conversation with codebase
      await db.updateConversation(existingConv.id, {
        codebase_id: codebase.id,
        cwd: repoPath,
      });
    }

    // 7. Build message with context
    const strippedComment = this.stripMention(comment);
    let finalMessage = strippedComment;
    let contextToAppend: string | undefined;

    // Handle slash commands
    const isSlashCommand = strippedComment.trim().startsWith('/');
    const isCommandInvoke = strippedComment.trim().startsWith('/command-invoke');

    if (isSlashCommand) {
      const firstLine = strippedComment.split('\n')[0].trim();
      finalMessage = firstLine;
      console.log(`[Jira] Processing slash command: ${firstLine}`);

      if (isCommandInvoke) {
        // Always include full issue context for /command-invoke so the AI understands the ticket
        console.log('[Jira] Adding full issue context for /command-invoke');
        contextToAppend = this.buildIssueContext(issue, '').trim();
      }
    } else if (isNewConversation) {
      finalMessage = this.buildIssueContext(issue, strippedComment);
    }

    // 8. Route to orchestrator
    try {
      await handleMessage(this, conversationId, finalMessage, contextToAppend);
    } catch (error) {
      console.error('[Jira] Message handling error:', error);
      await this.sendMessage(conversationId, '⚠️ An error occurred. Please try again or use /reset.');
    }
  }
}
