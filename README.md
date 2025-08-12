# GitLab MCP Server

## @anupsahu/gitlab-mcp

MCP (Model Context Protocol) server for GitLab API with OAuth 2.0 PKCE authentication.

## Features

- 🔐 **OAuth 2.0 PKCE Authentication** - Secure authentication with token persistence
- 🔄 **Automatic Token Refresh** - Seamless token renewal with retry logic
- 📁 **Complete GitLab API Coverage** - Merge requests, issues, files, commits, and more
- 💾 **Token Persistence** - Sessions survive server restarts
- 🛡️ **Production Ready** - Clean codebase with comprehensive error handling
- 🔧 **Easy Configuration** - Simple setup with environment variables

## Installation

```bash
npm install -g @anupsahu/gitlab-mcp
```

## Quick Start

### 1. OAuth Authentication (Recommended)

```json
{
  "mcpServers": {
    "gitlab": {
      "command": "npx",
      "args": ["-y", "@anupsahu/gitlab-mcp"],
      "env": {
        "USE_OAUTH": "true",
        "GITLAB_API_URL": "https://gitlab.com/api/v4"
      }
    }
  }
}
```

### 2. Personal Access Token (Alternative)

```json
{
  "mcpServers": {
    "gitlab": {
      "command": "npx",
      "args": ["-y", "@anupsahu/gitlab-mcp"],
      "env": {
        "GITLAB_PERSONAL_ACCESS_TOKEN": "your_gitlab_token",
        "GITLAB_API_URL": "https://gitlab.com/api/v4"
      }
    }
  }
}
```

## OAuth Authentication

The server supports OAuth 2.0 PKCE authentication for secure access to GitLab:

1. **Start the server** with `USE_OAUTH=true`
2. **Authenticate** using the `oauth_login_pkce` tool
3. **Tokens are automatically saved** and persist across restarts
4. **Automatic token refresh** handles expiration seamlessly

### OAuth Tools

- `oauth_login_pkce` - Initiate OAuth authentication
- `oauth_status` - Check authentication status
- `oauth_logout` - Logout and clear tokens

## Configuration

### Environment Variables

| Variable                       | Description                                 | Default                     |
| ------------------------------ | ------------------------------------------- | --------------------------- |
| `USE_OAUTH`                    | Enable OAuth 2.0 authentication             | `false`                     |
| `GITLAB_API_URL`               | GitLab API URL                              | `https://gitlab.com/api/v4` |
| `GITLAB_PERSONAL_ACCESS_TOKEN` | Personal access token (if not using OAuth)  | -                           |
| `GITLAB_PROJECT_ID`            | Default project ID                          | -                           |
| `GITLAB_ALLOWED_PROJECT_IDS`   | Comma-separated list of allowed project IDs | -                           |
| `GITLAB_READ_ONLY_MODE`        | Enable read-only mode                       | `false`                     |

## Available Tools

### Repository Operations

- `search_repositories` - Search for repositories
- `get_repository_tree` - Get repository file tree
- `get_file_contents` - Read file contents
- `create_or_update_file` - Create or update files
- `push_files` - Push multiple files

### Merge Request Operations

- `get_merge_request` - Get merge request details
- `get_merge_request_diffs` - Get merge request changes
- `create_merge_request` - Create new merge request
- `update_merge_request` - Update merge request
- `merge_merge_request` - Merge a merge request

### Issue Operations

- `create_issue` - Create new issue
- `get_issue` - Get issue details
- `update_issue` - Update issue
- `list_issues` - List issues

### Commit Operations

- `list_commits` - List repository commits
- `get_commit` - Get commit details
- `get_commit_diff` - Get commit changes

### Branch Operations

- `create_branch` - Create new branch
- `fork_repository` - Fork repository

## Token Storage

OAuth tokens are automatically saved to:

- **Path**: `~/.config/gitlab-mcp/oauth-config.json`
- **Format**: JSON configuration file
- **Persistence**: Tokens survive server restarts
- **Security**: Automatic token refresh and expiration handling

## Examples

### Authenticate with OAuth

```javascript
// Use the oauth_login_pkce tool
{
  "sessionId": "my-session" // optional
}
```

### Get Merge Request Details

```javascript
{
  "project_id": "12345",
  "merge_request_iid": "123",
  "sessionId": "my-session"
}
```

### Create Issue

```javascript
{
  "project_id": "12345",
  "title": "Bug Report",
  "description": "Description of the issue",
  "sessionId": "my-session"
}
```

## Development

```bash
# Clone repository
git clone https://gitlab.com/anupsahu/gitlab-mcp.git
cd gitlab-mcp

# Install dependencies
npm install

# Build
npm run build

# Run with OAuth
USE_OAUTH=true GITLAB_API_URL=https://gitlab.com/api/v4 node build/index.js
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a merge request

## Support

For issues and questions:

- Create an issue in the [GitLab repository](https://gitlab.com/anupsahu/gitlab-mcp)
- Check existing documentation and examples

---

**Built with ❤️ for the MCP ecosystem**
