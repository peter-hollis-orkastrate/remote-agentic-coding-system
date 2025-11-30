/**
 * Bitbucket platform adapter using Bitbucket REST API and Webhooks
 * Handles pull request and issue comments with @mention detection
 * Supports automated PR reviews on creation
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
import {
  AutoReviewService,
  AutoReviewConfig,
  PRContext,
} from '../services/auto-review';
import { getAssistantClient } from '../clients/factory';

const execAsync = promisify(exec);

/**
 * Bitbucket webhook event types we handle
 */
type BitbucketEventType =
  | 'pullrequest:created'
  | 'pullrequest:updated'
  | 'pullrequest:comment_created'
  | 'issue:created'
  | 'issue:updated'
  | 'issue:comment_created';

/**
 * Bitbucket webhook event payload structure
 */
interface BitbucketWebhookEvent {
  event?: BitbucketEventType;
  actor: {
    uuid: string;
    display_name: string;
    account_id?: string;
  };
  repository: {
    uuid: string;
    name: string;
    full_name: string; // workspace/repo-slug
    links: {
      html: { href: string };
      clone: { href: string; name: string }[];
    };
  };
  pullrequest?: {
    id: number;
    title: string;
    description: string | null;
    state: string;
    author: {
      display_name: string;
    };
    source: {
      branch: { name: string };
      repository: { full_name: string };
    };
    destination: {
      branch: { name: string };
    };
    links: {
      html: { href: string };
      diff: { href: string };
    };
  };
  issue?: {
    id: number;
    title: string;
    content: { raw: string | null };
    state: string;
    priority: string;
    kind: string;
    reporter: {
      display_name: string;
    };
  };
  comment?: {
    id: number;
    content: { raw: string };
    user: {
      display_name: string;
    };
    created_on: string;
  };
}

export class BitbucketAdapter implements IPlatformAdapter {
  private workspace: string;
  private username: string;
  private appPassword: string;
  private webhookSecret: string;
  private mention: string;

  // Auto-review configuration
  private autoReviewEnabled: boolean;
  private autoReviewService: AutoReviewService | null = null;
  private defaultAssistantType: string;

  constructor(config: {
    workspace: string;
    username: string;
    appPassword: string;
    webhookSecret: string;
    mention?: string;
    // Auto-review configuration
    autoReview?: {
      enabled: boolean;
      jiraBaseUrl: string;
      jiraEmail: string;
      jiraApiToken: string;
      jiraKeyPattern?: RegExp;
    };
    defaultAssistantType?: string;
  }) {
    this.workspace = config.workspace;
    this.username = config.username;
    this.appPassword = config.appPassword;
    this.webhookSecret = config.webhookSecret;
    this.mention = config.mention ?? '@remote-agent';
    this.defaultAssistantType = config.defaultAssistantType ?? 'claude';

    // Initialize auto-review if configured
    this.autoReviewEnabled = config.autoReview?.enabled ?? false;
    if (this.autoReviewEnabled && config.autoReview) {
      const autoReviewConfig: AutoReviewConfig = {
        bitbucketUsername: config.username,
        bitbucketAppPassword: config.appPassword,
        jiraBaseUrl: config.autoReview.jiraBaseUrl,
        jiraEmail: config.autoReview.jiraEmail,
        jiraApiToken: config.autoReview.jiraApiToken,
        jiraKeyPattern: config.autoReview.jiraKeyPattern,
      };
      this.autoReviewService = new AutoReviewService(autoReviewConfig);
      console.log('[Bitbucket] Auto-review enabled');
    }

    console.log(
      '[Bitbucket] Adapter initialized for workspace',
      this.workspace,
      'with secret:',
      this.webhookSecret.substring(0, 8) + '...'
    );
  }

  /**
   * Get authorization header for Bitbucket API
   */
  private getAuthHeader(): string {
    const credentials = Buffer.from(`${this.username}:${this.appPassword}`).toString('base64');
    return `Basic ${credentials}`;
  }

  /**
   * Send a message to a Bitbucket PR or issue as a comment
   * conversationId format: "workspace/repo#pr:123" or "workspace/repo#issue:123"
   */
  async sendMessage(conversationId: string, message: string): Promise<void> {
    const parsed = this.parseConversationId(conversationId);
    if (!parsed) {
      console.error('[Bitbucket] Invalid conversationId:', conversationId);
      return;
    }

    const { workspace, repoSlug, type, number } = parsed;

    try {
      let url: string;
      if (type === 'pr') {
        url = `https://api.bitbucket.org/2.0/repositories/${workspace}/${repoSlug}/pullrequests/${number}/comments`;
      } else {
        url = `https://api.bitbucket.org/2.0/repositories/${workspace}/${repoSlug}/issues/${number}/comments`;
      }

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: this.getAuthHeader(),
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          content: {
            raw: message,
          },
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Bitbucket API error: ${response.status} - ${errorText}`);
      }

      console.log(`[Bitbucket] Comment posted to ${conversationId}`);
    } catch (error) {
      console.error('[Bitbucket] Failed to post comment:', { error, conversationId });
    }
  }

  /**
   * Get streaming mode (always batch for Bitbucket to avoid comment spam)
   */
  getStreamingMode(): 'batch' {
    return 'batch';
  }

  /**
   * Get platform type
   */
  getPlatformType(): string {
    return 'bitbucket';
  }

  /**
   * Start the adapter (no-op for webhook-based adapter)
   */
  async start(): Promise<void> {
    console.log('[Bitbucket] Webhook adapter ready');
  }

  /**
   * Stop the adapter (no-op for webhook-based adapter)
   */
  stop(): void {
    console.log('[Bitbucket] Adapter stopped');
  }

  /**
   * Verify webhook signature using HMAC SHA-256
   * Bitbucket uses X-Hub-Signature header with sha256= prefix
   */
  private verifySignature(payload: string, signature: string): boolean {
    try {
      // Bitbucket webhook signature format: sha256=<signature>
      const hmac = createHmac('sha256', this.webhookSecret);
      const digest = 'sha256=' + hmac.update(payload).digest('hex');
      const isValid = digest === signature;

      if (!isValid) {
        console.error('[Bitbucket] Signature mismatch:', {
          received: signature?.substring(0, 15) + '...',
          computed: digest.substring(0, 15) + '...',
          secretLength: this.webhookSecret.length,
        });
      }

      return isValid;
    } catch (error) {
      console.error('[Bitbucket] Signature verification error:', error);
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
   * Build conversationId from workspace, repo, type, and number
   */
  private buildConversationId(
    workspace: string,
    repoSlug: string,
    type: 'pr' | 'issue',
    number: number
  ): string {
    return `${workspace}/${repoSlug}#${type}:${number}`;
  }

  /**
   * Parse conversationId into components
   */
  private parseConversationId(conversationId: string): {
    workspace: string;
    repoSlug: string;
    type: 'pr' | 'issue';
    number: number;
  } | null {
    // Format: workspace/repo#pr:123 or workspace/repo#issue:123
    const regex = /^([^/]+)\/([^#]+)#(pr|issue):(\d+)$/;
    const match = regex.exec(conversationId);
    if (!match) return null;
    return {
      workspace: match[1],
      repoSlug: match[2],
      type: match[3] as 'pr' | 'issue',
      number: parseInt(match[4], 10),
    };
  }

  /**
   * Parse webhook event and extract relevant data
   */
  private parseEvent(
    event: BitbucketWebhookEvent,
    eventType: string
  ): {
    workspace: string;
    repoSlug: string;
    type: 'pr' | 'issue';
    number: number;
    comment: string;
    eventName: string;
    pullRequest?: BitbucketWebhookEvent['pullrequest'];
    issue?: BitbucketWebhookEvent['issue'];
  } | null {
    const fullName = event.repository.full_name;
    const [workspace, repoSlug] = fullName.split('/');

    // Pull request events
    if (eventType.startsWith('pullrequest:')) {
      if (!event.pullrequest) return null;

      let comment = '';
      if (eventType === 'pullrequest:comment_created' && event.comment) {
        comment = event.comment.content.raw;
      } else if (
        (eventType === 'pullrequest:created' || eventType === 'pullrequest:updated') &&
        event.pullrequest.description
      ) {
        comment = event.pullrequest.description;
      }

      if (!comment) return null;

      return {
        workspace,
        repoSlug,
        type: 'pr',
        number: event.pullrequest.id,
        comment,
        eventName: eventType,
        pullRequest: event.pullrequest,
      };
    }

    // Issue events
    if (eventType.startsWith('issue:')) {
      if (!event.issue) return null;

      let comment = '';
      if (eventType === 'issue:comment_created' && event.comment) {
        comment = event.comment.content.raw;
      } else if (
        (eventType === 'issue:created' || eventType === 'issue:updated') &&
        event.issue.content.raw
      ) {
        comment = event.issue.content.raw;
      }

      if (!comment) return null;

      return {
        workspace,
        repoSlug,
        type: 'issue',
        number: event.issue.id,
        comment,
        eventName: eventType,
        issue: event.issue,
      };
    }

    return null;
  }

  /**
   * Build context-rich message for pull request
   */
  private buildPRContext(pr: BitbucketWebhookEvent['pullrequest'], userComment: string): string {
    if (!pr) return userComment;

    return `[Bitbucket Pull Request Context]
PR #${pr.id}: "${pr.title}"
Author: ${pr.author.display_name}
Status: ${pr.state}
Branch: ${pr.source.branch.name} → ${pr.destination.branch.name}

Description:
${pr.description || 'No description'}

---

${userComment}`;
  }

  /**
   * Build context-rich message for issue
   */
  private buildIssueContext(issue: BitbucketWebhookEvent['issue'], userComment: string): string {
    if (!issue) return userComment;

    return `[Bitbucket Issue Context]
Issue #${issue.id}: "${issue.title}"
Reporter: ${issue.reporter.display_name}
Status: ${issue.state}
Priority: ${issue.priority}
Kind: ${issue.kind}

Description:
${issue.content.raw || 'No description'}

---

${userComment}`;
  }

  /**
   * Get clone URL for repository
   */
  private getCloneUrl(event: BitbucketWebhookEvent): string {
    // Some webhook events may not include clone links, so we need to handle that
    const cloneLinks = event.repository?.links?.clone;
    if (cloneLinks && Array.isArray(cloneLinks)) {
      const httpsClone = cloneLinks.find(c => c.name === 'https');
      if (httpsClone?.href) {
        return httpsClone.href;
      }
    }

    // Fallback: construct URL from html link or workspace/repo info
    if (event.repository?.links?.html?.href) {
      return event.repository.links.html.href + '.git';
    }

    // Last resort: construct from full_name or workspace/repo info
    if (event.repository?.full_name) {
      return `https://bitbucket.org/${event.repository.full_name}.git`;
    }

    const repoSlug = event.repository?.name;
    return `https://bitbucket.org/${this.workspace}/${repoSlug}.git`;
  }

  /**
   * Ensure repository is cloned and ready
   */
  private async ensureRepoReady(
    repoUrl: string,
    repoPath: string,
    defaultBranch: string,
    shouldSync: boolean
  ): Promise<void> {
    try {
      await access(repoPath);
      if (shouldSync) {
        console.log('[Bitbucket] Syncing repository');
        await execAsync(
          `cd ${repoPath} && git fetch origin && git reset --hard origin/${defaultBranch}`
        );
      }
    } catch {
      console.log(`[Bitbucket] Cloning repository to ${repoPath}`);

      // Add auth to URL if available
      let cloneUrl = repoUrl;
      if (this.username && this.appPassword) {
        const url = new URL(repoUrl);
        url.username = this.username;
        url.password = this.appPassword;
        cloneUrl = url.toString();
      }

      await execAsync(`git clone ${cloneUrl} ${repoPath}`);
      await execAsync(`git config --global --add safe.directory '${repoPath}'`);
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
        console.log(`[Bitbucket] Loaded ${files.length} commands from ${folder}`);
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
    // Try both with and without .git suffix
    const repoUrlNoGit = repoUrl.replace(/\.git$/, '');
    const repoUrlWithGit = repoUrlNoGit + '.git';

    let existing = await codebaseDb.findCodebaseByRepoUrl(repoUrlNoGit);
    if (!existing) {
      existing = await codebaseDb.findCodebaseByRepoUrl(repoUrlWithGit);
    }

    if (existing) {
      console.log(`[Bitbucket] Using existing codebase: ${existing.name} at ${existing.default_cwd}`);
      return { codebase: existing, repoPath: existing.default_cwd, isNew: false };
    }

    const repoPath = `/workspace/${repoName}`;
    const codebase = await codebaseDb.createCodebase({
      name: repoName,
      repository_url: repoUrlNoGit,
      default_cwd: repoPath,
    });

    console.log(`[Bitbucket] Created new codebase: ${codebase.name} at ${repoPath}`);
    return { codebase, repoPath, isNew: true };
  }

  /**
   * Get default branch for repository
   */
  private async getDefaultBranch(workspace: string, repoSlug: string): Promise<string> {
    try {
      const response = await fetch(
        `https://api.bitbucket.org/2.0/repositories/${workspace}/${repoSlug}`,
        {
          headers: {
            Authorization: this.getAuthHeader(),
            Accept: 'application/json',
          },
        }
      );

      if (response.ok) {
        const data = (await response.json()) as { mainbranch?: { name: string } };
        return data.mainbranch?.name || 'main';
      }
    } catch (error) {
      console.log('[Bitbucket] Could not fetch default branch:', error);
    }

    return 'main';
  }

  /**
   * Handle automated PR review
   * Triggered on PR creation when auto-review is enabled
   */
  private async handleAutoReview(
    event: BitbucketWebhookEvent,
    workspace: string,
    repoSlug: string
  ): Promise<void> {
    if (!this.autoReviewService || !event.pullrequest) {
      return;
    }

    const pr = event.pullrequest;
    console.log(`[Bitbucket] Starting auto-review for PR #${pr.id}: ${pr.title}`);

    // Build PR context
    const prContext: PRContext = {
      workspace,
      repoSlug,
      prId: pr.id,
      title: pr.title,
      description: pr.description,
      author: pr.author.display_name,
      sourceBranch: pr.source.branch.name,
      destinationBranch: pr.destination.branch.name,
      diffUrl: pr.links.diff.href,
    };

    // Extract Jira key from PR
    const jiraKey = this.autoReviewService.extractJiraKey(prContext);
    if (jiraKey) {
      console.log(`[Bitbucket] Found Jira key: ${jiraKey}`);
    } else {
      console.log('[Bitbucket] No Jira key found in PR title/branch/description');
    }

    // Fetch PR diff and changed files
    const [diff, changedFiles] = await Promise.all([
      this.autoReviewService.fetchPRDiff(prContext),
      this.autoReviewService.fetchChangedFiles(prContext),
    ]);

    if (!diff) {
      console.error('[Bitbucket] Could not fetch PR diff, skipping auto-review');
      return;
    }

    console.log(`[Bitbucket] Fetched diff (${diff.length} chars) and ${changedFiles.length} changed files`);

    // Fetch Jira ticket if we have a key
    const jiraTicket = jiraKey ? await this.autoReviewService.fetchJiraTicket(jiraKey) : null;
    if (jiraTicket) {
      console.log(`[Bitbucket] Fetched Jira ticket: ${jiraTicket.key} - ${jiraTicket.summary}`);
    }

    // Build review prompt
    const reviewPrompt = this.autoReviewService.buildReviewPrompt(
      prContext,
      diff,
      changedFiles,
      jiraTicket
    );

    // Send to AI for review
    console.log('[Bitbucket] Sending to AI for review...');
    const aiClient = getAssistantClient(this.defaultAssistantType);

    // Collect the AI response
    let reviewContent = '';
    try {
      // Use a temporary working directory (we don't need file access for reviews)
      for await (const msg of aiClient.sendQuery(reviewPrompt, '/tmp')) {
        if (msg.type === 'assistant' && msg.content) {
          reviewContent += msg.content;
        }
      }
    } catch (error) {
      console.error('[Bitbucket] AI review failed:', error);
      await this.autoReviewService.postBitbucketComment(
        prContext,
        '⚠️ Automated code review failed. Please trigger a manual review.'
      );
      return;
    }

    if (!reviewContent) {
      console.error('[Bitbucket] AI returned empty review');
      return;
    }

    console.log(`[Bitbucket] Received review (${reviewContent.length} chars)`);

    // Format and post reviews
    const bitbucketReview = this.autoReviewService.formatBitbucketReview(reviewContent, jiraKey);
    const bitbucketPosted = await this.autoReviewService.postBitbucketComment(prContext, bitbucketReview);

    if (jiraKey) {
      const jiraReview = this.autoReviewService.formatJiraReview(reviewContent, prContext);
      await this.autoReviewService.postJiraComment(jiraKey, jiraReview);
    }

    if (bitbucketPosted) {
      console.log(`[Bitbucket] Auto-review completed for PR #${pr.id}`);
    }
  }

  /**
   * Handle incoming webhook event
   */
  async handleWebhook(payload: string, signature: string, eventType: string): Promise<void> {
    // 1. Verify signature
    if (signature && !this.verifySignature(payload, signature)) {
      console.error('[Bitbucket] Invalid webhook signature');
      return;
    }

    // 2. Parse event
    const event: BitbucketWebhookEvent = JSON.parse(payload);

    // 3. Check for auto-review trigger (PR created, no @mention needed)
    if (
      this.autoReviewEnabled &&
      eventType === 'pullrequest:created' &&
      event.pullrequest
    ) {
      const fullName = event.repository.full_name;
      const [workspace, repoSlug] = fullName.split('/');

      // Fire auto-review asynchronously
      this.handleAutoReview(event, workspace, repoSlug).catch(error => {
        console.error('[Bitbucket] Auto-review error:', error);
      });

      // Don't return - still allow @mention handling if present
    }

    // 4. Parse event for @mention handling
    const parsed = this.parseEvent(event, eventType);
    if (!parsed) return;

    const { workspace, repoSlug, type, number, comment, eventName, pullRequest, issue } = parsed;

    // 5. Check @mention (required for manual interactions)
    if (!this.hasMention(comment)) return;

    console.log(`[Bitbucket] Processing ${eventName}: ${workspace}/${repoSlug}#${type}:${number}`);

    // 4. Build conversationId
    const conversationId = this.buildConversationId(workspace, repoSlug, type, number);

    // 5. Check if new conversation
    const existingConv = await db.getOrCreateConversation('bitbucket', conversationId);
    const isNewConversation = !existingConv.codebase_id;

    // 6. Get/create codebase
    const repoUrl = this.getCloneUrl(event);
    const { codebase, repoPath, isNew: isNewCodebase } = await this.getOrCreateCodebaseForRepo(
      repoUrl,
      repoSlug
    );

    // 7. Get default branch
    const defaultBranch = await this.getDefaultBranch(workspace, repoSlug);

    // 8. Ensure repo ready
    await this.ensureRepoReady(repoUrl, repoPath, defaultBranch, isNewConversation);

    // 9. Auto-load commands if new codebase
    if (isNewCodebase) {
      await this.autoDetectAndLoadCommands(repoPath, codebase.id);
    }

    // 10. Update conversation
    if (isNewConversation) {
      await db.updateConversation(existingConv.id, {
        codebase_id: codebase.id,
        cwd: repoPath,
      });
    }

    // 11. Build message with context
    const strippedComment = this.stripMention(comment);
    let finalMessage = strippedComment;
    let contextToAppend: string | undefined;

    // Handle slash commands
    const isSlashCommand = strippedComment.trim().startsWith('/');
    const isCommandInvoke = strippedComment.trim().startsWith('/command-invoke');

    if (isSlashCommand) {
      const firstLine = strippedComment.split('\n')[0].trim();
      finalMessage = firstLine;
      console.log(`[Bitbucket] Processing slash command: ${firstLine}`);

      if (isCommandInvoke) {
        // Always include full PR/issue context for /command-invoke so the AI understands the context
        console.log('[Bitbucket] Adding full PR/issue context for /command-invoke');
        if (type === 'pr' && pullRequest) {
          contextToAppend = this.buildPRContext(pullRequest, '').trim();
        } else if (type === 'issue' && issue) {
          contextToAppend = this.buildIssueContext(issue, '').trim();
        }
      }
    } else if (isNewConversation) {
      if (type === 'pr' && pullRequest) {
        finalMessage = this.buildPRContext(pullRequest, strippedComment);
      } else if (type === 'issue' && issue) {
        finalMessage = this.buildIssueContext(issue, strippedComment);
      }
    }

    // 12. Route to orchestrator
    try {
      await handleMessage(this, conversationId, finalMessage, contextToAppend);
    } catch (error) {
      console.error('[Bitbucket] Message handling error:', error);
      await this.sendMessage(conversationId, '⚠️ An error occurred. Please try again or use /reset.');
    }
  }
}
