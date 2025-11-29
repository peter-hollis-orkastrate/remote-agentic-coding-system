/**
 * Automated PR Review Service
 * Triggers on PR creation, reviews code changes, and posts to both Bitbucket and Jira
 */

/**
 * Configuration for the auto-review service
 */
export interface AutoReviewConfig {
  // Bitbucket credentials (for fetching PR diff and posting comments)
  bitbucketUsername: string;
  bitbucketAppPassword: string;

  // Jira credentials (for fetching ticket details and posting comments)
  jiraBaseUrl: string;
  jiraEmail: string;
  jiraApiToken: string;

  // Pattern to extract Jira key from PR title/branch (default: /([A-Z]+-\d+)/)
  jiraKeyPattern?: RegExp;
}

/**
 * PR context for review
 */
export interface PRContext {
  workspace: string;
  repoSlug: string;
  prId: number;
  title: string;
  description: string | null;
  author: string;
  sourceBranch: string;
  destinationBranch: string;
  diffUrl: string;
}

/**
 * Jira ticket context
 */
export interface JiraTicketContext {
  key: string;
  summary: string;
  description: string | null;
  type: string;
  status: string;
  priority: string | null;
  acceptanceCriteria?: string;
}

/**
 * Review result to be posted
 */
export interface ReviewResult {
  summary: string;
  findings: string;
  recommendation: 'APPROVE' | 'REQUEST_CHANGES' | 'COMMENT';
}

export class AutoReviewService {
  private config: AutoReviewConfig;
  private jiraKeyPattern: RegExp;

  constructor(config: AutoReviewConfig) {
    this.config = config;
    this.jiraKeyPattern = config.jiraKeyPattern ?? /([A-Z]+-\d+)/;
  }

  /**
   * Get Bitbucket auth header
   */
  private getBitbucketAuthHeader(): string {
    const credentials = Buffer.from(
      `${this.config.bitbucketUsername}:${this.config.bitbucketAppPassword}`
    ).toString('base64');
    return `Basic ${credentials}`;
  }

  /**
   * Get Jira auth header
   */
  private getJiraAuthHeader(): string {
    const credentials = Buffer.from(
      `${this.config.jiraEmail}:${this.config.jiraApiToken}`
    ).toString('base64');
    return `Basic ${credentials}`;
  }

  /**
   * Extract Jira key from PR title or branch name
   */
  extractJiraKey(pr: PRContext): string | null {
    // Try title first
    const titleMatch = this.jiraKeyPattern.exec(pr.title);
    if (titleMatch) {
      return titleMatch[1];
    }

    // Try source branch
    const branchMatch = this.jiraKeyPattern.exec(pr.sourceBranch);
    if (branchMatch) {
      return branchMatch[1];
    }

    // Try description
    if (pr.description) {
      const descMatch = this.jiraKeyPattern.exec(pr.description);
      if (descMatch) {
        return descMatch[1];
      }
    }

    return null;
  }

  /**
   * Fetch PR diff from Bitbucket
   */
  async fetchPRDiff(pr: PRContext): Promise<string> {
    try {
      const response = await fetch(
        `https://api.bitbucket.org/2.0/repositories/${pr.workspace}/${pr.repoSlug}/pullrequests/${pr.prId}/diff`,
        {
          headers: {
            Authorization: this.getBitbucketAuthHeader(),
            Accept: 'text/plain',
          },
        }
      );

      if (!response.ok) {
        console.error(`[AutoReview] Failed to fetch PR diff: ${response.status}`);
        return '';
      }

      const diff = await response.text();

      // Truncate if too large (keep first 50KB to avoid token limits)
      const maxLength = 50000;
      if (diff.length > maxLength) {
        console.log(`[AutoReview] Diff truncated from ${diff.length} to ${maxLength} chars`);
        return diff.substring(0, maxLength) + '\n\n... [diff truncated due to size]';
      }

      return diff;
    } catch (error) {
      console.error('[AutoReview] Error fetching PR diff:', error);
      return '';
    }
  }

  /**
   * Fetch list of changed files from Bitbucket
   */
  async fetchChangedFiles(pr: PRContext): Promise<string[]> {
    try {
      const response = await fetch(
        `https://api.bitbucket.org/2.0/repositories/${pr.workspace}/${pr.repoSlug}/pullrequests/${pr.prId}/diffstat`,
        {
          headers: {
            Authorization: this.getBitbucketAuthHeader(),
            Accept: 'application/json',
          },
        }
      );

      if (!response.ok) {
        console.error(`[AutoReview] Failed to fetch diffstat: ${response.status}`);
        return [];
      }

      const data = (await response.json()) as {
        values: { new?: { path: string }; old?: { path: string }; status: string }[];
      };

      return data.values.map(file => {
        const path = file.new?.path ?? file.old?.path ?? 'unknown';
        return `${file.status}: ${path}`;
      });
    } catch (error) {
      console.error('[AutoReview] Error fetching changed files:', error);
      return [];
    }
  }

  /**
   * Fetch Jira ticket details
   */
  async fetchJiraTicket(ticketKey: string): Promise<JiraTicketContext | null> {
    try {
      const response = await fetch(
        `${this.config.jiraBaseUrl}/rest/api/3/issue/${ticketKey}`,
        {
          headers: {
            Authorization: this.getJiraAuthHeader(),
            Accept: 'application/json',
          },
        }
      );

      if (!response.ok) {
        console.error(`[AutoReview] Failed to fetch Jira ticket ${ticketKey}: ${response.status}`);
        return null;
      }

      const data = (await response.json()) as {
        key: string;
        fields: {
          summary: string;
          description: { content?: { content?: { text?: string }[] }[] } | string | null;
          issuetype: { name: string };
          status: { name: string };
          priority?: { name: string };
          customfield_10016?: string; // Common field for acceptance criteria
        };
      };

      // Parse description (Jira uses Atlassian Document Format)
      let description: string | null = null;
      if (typeof data.fields.description === 'string') {
        description = data.fields.description;
      } else if (data.fields.description?.content) {
        // Extract text from ADF format
        description = data.fields.description.content
          .flatMap(block => block.content?.map(item => item.text) ?? [])
          .join('\n');
      }

      return {
        key: data.key,
        summary: data.fields.summary,
        description,
        type: data.fields.issuetype.name,
        status: data.fields.status.name,
        priority: data.fields.priority?.name ?? null,
        acceptanceCriteria: data.fields.customfield_10016,
      };
    } catch (error) {
      console.error('[AutoReview] Error fetching Jira ticket:', error);
      return null;
    }
  }

  /**
   * Post comment to Bitbucket PR
   */
  async postBitbucketComment(pr: PRContext, comment: string): Promise<boolean> {
    try {
      const response = await fetch(
        `https://api.bitbucket.org/2.0/repositories/${pr.workspace}/${pr.repoSlug}/pullrequests/${pr.prId}/comments`,
        {
          method: 'POST',
          headers: {
            Authorization: this.getBitbucketAuthHeader(),
            Accept: 'application/json',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            content: {
              raw: comment,
            },
          }),
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`[AutoReview] Failed to post Bitbucket comment: ${response.status} - ${errorText}`);
        return false;
      }

      console.log(`[AutoReview] Posted review comment to Bitbucket PR #${pr.prId}`);
      return true;
    } catch (error) {
      console.error('[AutoReview] Error posting Bitbucket comment:', error);
      return false;
    }
  }

  /**
   * Post comment to Jira ticket
   */
  async postJiraComment(ticketKey: string, comment: string): Promise<boolean> {
    try {
      const response = await fetch(
        `${this.config.jiraBaseUrl}/rest/api/3/issue/${ticketKey}/comment`,
        {
          method: 'POST',
          headers: {
            Authorization: this.getJiraAuthHeader(),
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
                      text: comment,
                    },
                  ],
                },
              ],
            },
          }),
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`[AutoReview] Failed to post Jira comment: ${response.status} - ${errorText}`);
        return false;
      }

      console.log(`[AutoReview] Posted review comment to Jira ticket ${ticketKey}`);
      return true;
    } catch (error) {
      console.error('[AutoReview] Error posting Jira comment:', error);
      return false;
    }
  }

  /**
   * Build the review prompt for the AI
   */
  buildReviewPrompt(
    pr: PRContext,
    diff: string,
    changedFiles: string[],
    jiraTicket: JiraTicketContext | null
  ): string {
    let prompt = `# Senior Developer Code Review

You are a Senior Developer performing a technical code review. Your role is to review the code changes critically but constructively.

## Review Guidelines

1. **DO NOT** suggest any code changes or attempt to modify files
2. **DO NOT** create commits or PRs
3. **ONLY** provide a written review assessment

## What to Review

- **Code Quality**: Clean code principles, readability, maintainability
- **Architecture**: Design patterns, separation of concerns, SOLID principles
- **Security**: OWASP top 10, input validation, authentication/authorization issues
- **Performance**: Potential bottlenecks, N+1 queries, memory leaks
- **Error Handling**: Proper exception handling, edge cases
- **Testing**: Are changes adequately tested?
- **Best Practices**: Language/framework conventions, naming, documentation

## Pull Request Details

**PR #${pr.prId}**: ${pr.title}
**Author**: ${pr.author}
**Branch**: ${pr.sourceBranch} → ${pr.destinationBranch}

**Description**:
${pr.description ?? 'No description provided'}

## Changed Files

${changedFiles.length > 0 ? changedFiles.join('\n') : 'No file list available'}

`;

    if (jiraTicket) {
      prompt += `## Linked Jira Ticket

**${jiraTicket.key}**: ${jiraTicket.summary}
**Type**: ${jiraTicket.type}
**Status**: ${jiraTicket.status}
**Priority**: ${jiraTicket.priority ?? 'Not set'}

**Requirements**:
${jiraTicket.description ?? 'No description'}

${jiraTicket.acceptanceCriteria ? `**Acceptance Criteria**:\n${jiraTicket.acceptanceCriteria}` : ''}

**Important**: Verify that the code changes align with the Jira ticket requirements and acceptance criteria.

`;
    }

    prompt += `## Code Diff

\`\`\`diff
${diff}
\`\`\`

## Your Task

Provide a comprehensive code review with the following structure:

### Summary
A brief 2-3 sentence overview of what this PR does and your overall impression.

### Findings

#### 🔴 Critical Issues (must fix before merge)
List any security vulnerabilities, bugs, or breaking changes.

#### 🟡 Suggestions (should consider)
List code quality improvements, better patterns, or potential issues.

#### 🟢 Positive Observations
Highlight good practices you noticed in the code.

### Recommendation
State one of: **APPROVE**, **REQUEST CHANGES**, or **NEEDS DISCUSSION**

Provide your reasoning for the recommendation.
`;

    return prompt;
  }

  /**
   * Format the review for Bitbucket (Markdown)
   */
  formatBitbucketReview(review: string, jiraKey: string | null): string {
    let formatted = `## 🤖 Automated Code Review\n\n`;
    formatted += review;

    if (jiraKey) {
      formatted += `\n\n---\n*This review was also posted to [${jiraKey}]*`;
    }

    return formatted;
  }

  /**
   * Format the review for Jira (plain text works better)
   */
  formatJiraReview(review: string, pr: PRContext): string {
    let formatted = `🤖 Automated Code Review for PR #${pr.prId}\n\n`;
    formatted += `Branch: ${pr.sourceBranch} → ${pr.destinationBranch}\n`;
    formatted += `PR Link: https://bitbucket.org/${pr.workspace}/${pr.repoSlug}/pull-requests/${pr.prId}\n\n`;
    formatted += '---\n\n';
    formatted += review;

    return formatted;
  }
}
