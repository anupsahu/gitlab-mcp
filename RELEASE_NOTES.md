## [1.0.0] - 2025-08-11

### 🎉 Initial Release - Production-Ready GitLab MCP Server

#### ✨ New Features

- 🔐 **OAuth 2.0 PKCE Authentication** - Secure authentication with automatic token refresh
- 💾 **Token Persistence** - Sessions survive server restarts via JSON config
- 🔄 **Automatic Token Refresh** - Seamless token renewal with retry logic
- 📁 **Complete GitLab API Coverage** - Merge requests, issues, files, commits, branches
- 🛡️ **Production Ready** - Clean codebase with comprehensive error handling
- 🔧 **Universal sessionId Support** - All MCP tools support OAuth sessions

#### 🏗️ Architecture Improvements

- **Clean OAuth Implementation** - PKCE flow only, removed experimental code
- **JSON Configuration** - Reliable token storage in `~/.config/gitlab-mcp/oauth-config.json`
- **Dynamic Authentication** - Automatically uses OAuth when sessionId provided
- **Error Recovery** - Built-in retry logic for expired tokens
- **Type Safety** - Comprehensive TypeScript types throughout

#### 🧹 Code Quality

- **Removed Dead Code** - Eliminated unused functions and experimental features
- **Fixed Duplicates** - Removed duplicate authentication functions
- **Updated Documentation** - Clean, professional README and examples
- **Production Testing** - Verified across all major operations

---
