import { pino } from "pino";
import { randomBytes, createHash } from "crypto";
import { createServer, Server } from "http";
import { URL } from "url";
import { promises as fs } from 'fs';
import { dirname, join } from 'path';
import { homedir } from 'os';

const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: {
    target: "pino-pretty",
    options: {
      colorize: true,
      levelFirst: true,
      destination: 2,
    },
  },
});

export interface OAuthTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  scope: string;
  created_at: number;
}

export interface OAuthSession {
  sessionId: string;
  tokens: OAuthTokens;
  codeVerifier: string;
  state: string;
  expiresAt: number;
  // Dynamic redirect URI used for this session's OAuth code exchange
  redirectUri?: string;
  user?: {
    id: string;
    username: string;
    name: string;
    email: string;
  };
}

export interface GitLabConfig {
  hosts: {
    [hostname: string]: {
      api_protocol: string;
      api_host: string;
      token: string;
      is_oauth2: boolean;
      oauth2_refresh_token: string;
      oauth2_expiry_date: string;
    };
  };
}

/**
 * Clean GitLab OAuth Manager - PKCE Flow Only with Token Persistence
 * Implements glab CLI-compatible OAuth with config.yml storage
 */
export class GitLabOAuthManager {
  private baseUrl: string;
  private scopes: string;
  private sessions: Map<string, OAuthSession> = new Map();
  private configPath: string;
  private hostname: string;
  private callbackServer?: Server;

  constructor(baseUrl: string, scopes: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.scopes = scopes;
    this.hostname = new URL(baseUrl).hostname;
    this.configPath = join(homedir(), '.config', 'gitlab-mcp', 'oauth-config.json');

    // Load existing config on startup
    this.loadConfigFromFile().catch(err => {
      logger.debug('No existing config found or failed to load:', err.message);
    });
  }

  /**
   * Get GitLab MCP config directory path
   */
  private getConfigDir(): string {
    return join(homedir(), '.config', 'gitlab-mcp');
  }

  /**
   * Load OAuth tokens from JSON config file
   */
  private async loadConfigFromFile(): Promise<void> {
    try {
      logger.debug(`Loading config from: ${this.configPath}`);
      const configContent = await fs.readFile(this.configPath, 'utf-8');
      logger.debug(`Config content: ${configContent}`);

      const config: GitLabConfig = JSON.parse(configContent);
      logger.debug(`Parsed config:`, config);

      const hostConfig = config.hosts?.[this.hostname];
      logger.debug(`Host config for ${this.hostname}:`, hostConfig);

      if (hostConfig?.is_oauth2 === true && hostConfig.token) {
        // Create session from stored config
        const sessionId = 'persistent-session';
        const expiryDate = new Date(hostConfig.oauth2_expiry_date || Date.now() + 3600000);

        const session: OAuthSession = {
          sessionId,
          tokens: {
            access_token: hostConfig.token,
            refresh_token: hostConfig.oauth2_refresh_token || '',
            expires_in: 3600,
            token_type: 'Bearer',
            scope: this.scopes,
            created_at: Date.now(),
          },
          codeVerifier: '',
          state: '',
          expiresAt: expiryDate.getTime(),
        };

        this.sessions.set(sessionId, session);
        logger.info(`Loaded OAuth session from config file: ${sessionId}`);
      } else {
        logger.debug('No valid OAuth config found in file');
      }
    } catch (error) {
      logger.debug('Failed to load config:', error);
    }
  }

  /**
   * Save OAuth tokens to JSON config file
   */
  private async saveConfigToFile(session: OAuthSession): Promise<void> {
    try {
      // Ensure config directory exists
      await fs.mkdir(this.getConfigDir(), { recursive: true });

      const config: GitLabConfig = {
        hosts: {
          [this.hostname]: {
            api_protocol: 'https',
            api_host: this.hostname,
            token: session.tokens.access_token,
            is_oauth2: true,
            oauth2_refresh_token: session.tokens.refresh_token,
            oauth2_expiry_date: new Date(session.expiresAt).toISOString(),
          }
        }
      };

      // Save as JSON
      const jsonContent = JSON.stringify(config, null, 2);
      await fs.writeFile(this.configPath, jsonContent, 'utf-8');

      logger.info('OAuth tokens saved to config file');
    } catch (error) {
      logger.error('Failed to save config:', error);
    }
  }



  /**
   * Check if token is expired and needs refresh
   */
  private isTokenExpired(session: OAuthSession): boolean {
    const now = Date.now();
    const bufferTime = 5 * 60 * 1000; // 5 minutes buffer
    return now >= (session.expiresAt - bufferTime);
  }

  /**
   * Refresh OAuth token using refresh token
   */
  private async refreshToken(session: OAuthSession): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: session.tokens.refresh_token,
          client_id: '41d48f9422ebd655dd9cf2947d6979681dfaddc6d0c56f7628f6ada59559af1e',
        }),
      });

      if (!response.ok) {
        logger.error('Token refresh failed:', response.status, response.statusText);
        return false;
      }

      const tokens = await response.json() as OAuthTokens;
      tokens.created_at = Date.now();

      // Update session with new tokens
      session.tokens = tokens;
      session.expiresAt = Date.now() + (tokens.expires_in * 1000);

      // Save to config file
      await this.saveConfigToFile(session);

      logger.info('OAuth token refreshed successfully');
      return true;
    } catch (error) {
      logger.error('Token refresh error:', error);
      return false;
    }
  }

  /**
   * Get valid access token, refreshing if necessary
   */
  async getValidAccessToken(sessionId: string): Promise<string | null> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      logger.debug('No session found for ID:', sessionId);
      return null;
    }

    // Check if token is expired
    if (this.isTokenExpired(session)) {
      logger.info('Token expired, attempting refresh...');
      const refreshed = await this.refreshToken(session);
      if (!refreshed) {
        logger.error('Token refresh failed, session invalid');
        this.sessions.delete(sessionId);
        return null;
      }
    }

    return session.tokens.access_token;
  }

  /**
   * Get session information
   */
  getSession(sessionId: string): OAuthSession | null {
    return this.sessions.get(sessionId) || null;
  }

  /**
   * Remove session and clean up
   */
  async logout(sessionId: string): Promise<void> {
    this.sessions.delete(sessionId);

    // Remove from config file
    try {
      const configContent = await fs.readFile(this.configPath, 'utf-8');
      const config: GitLabConfig = JSON.parse(configContent);

      if (config.hosts[this.hostname]) {
        delete config.hosts[this.hostname];
        const jsonContent = JSON.stringify(config, null, 2);
        await fs.writeFile(this.configPath, jsonContent, 'utf-8');
      }
    } catch (error) {
      logger.debug('Failed to clean config file:', error);
    }

    // Stop callback server if running
    if (this.callbackServer) {
      this.callbackServer.close();
      this.callbackServer = undefined;
    }

    logger.info('Session logged out and cleaned up');
  }

  /**
   * Start callback server for OAuth redirect (like glab CLI)
   */
  private async startCallbackServer(port: number): Promise<Server> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => {
        const url = new URL(req.url!, `http://localhost:${port}`);

        if (url.pathname === '/auth/redirect') {
          const code = url.searchParams.get('code');
          const state = url.searchParams.get('state');
          const error = url.searchParams.get('error');

          if (error) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <body>
                  <h1>❌ Authentication Error</h1>
                  <p>Error: ${error}</p>
                  <p>Description: ${url.searchParams.get('error_description') || 'Unknown error'}</p>
                  <p>You can close this window.</p>
                </body>
              </html>
            `);
            return;
          }

          if (code && state) {
            this.handleAuthorizationCallback(code, state)
              .then(() => {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(`
                  <html>
                    <body>
                      <h1>✅ Authentication Successful!</h1>
                      <p>You have been successfully authenticated with GitLab.</p>
                      <p>You can close this window and return to your application.</p>
                      <script>
                        setTimeout(() => window.close(), 3000);
                      </script>
                    </body>
                  </html>
                `);
              })
              .catch((error) => {
                res.writeHead(500, { 'Content-Type': 'text/html' });
                res.end(`
                  <html>
                    <body>
                      <h1>❌ Authentication Failed</h1>
                      <p>Error: ${error.message}</p>
                      <p>You can close this window.</p>
                    </body>
                  </html>
                `);
              });
          } else {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(`
              <html>
                <body>
                  <h1>Invalid Request</h1>
                  <p>Missing code or state parameter.</p>
                  <p>You can close this window.</p>
                </body>
              </html>
            `);
          }
        } else if (url.pathname === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', service: 'gitlab-mcp-oauth-callback' }));
        } else {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('Not Found');
        }
      });

      server.listen(port, 'localhost', () => {
        logger.info(`OAuth callback server started on http://localhost:${port}`);
        resolve(server);
      });

      server.on('error', (error) => {
        logger.error('Failed to start callback server:', error);
        reject(error);
      });
    });
  }

  /**
   * Handle OAuth authorization callback
   */
  private async handleAuthorizationCallback(code: string, state: string): Promise<void> {
    // Find session by state
    let targetSession: OAuthSession | null = null;
    for (const session of this.sessions.values()) {
      if (session.state === state) {
        targetSession = session;
        break;
      }
    }

    if (!targetSession) {
      throw new Error('Invalid state parameter - session not found');
    }

    // Exchange code for tokens
    const response = await fetch(`${this.baseUrl}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: '41d48f9422ebd655dd9cf2947d6979681dfaddc6d0c56f7628f6ada59559af1e',
        code,
        redirect_uri: targetSession.redirectUri || 'http://localhost:7171/auth/redirect',
        code_verifier: targetSession.codeVerifier,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token exchange failed: ${response.status} ${errorText}`);
    }

    const tokens = await response.json() as OAuthTokens;
    tokens.created_at = Date.now();

    // Update session with tokens
    targetSession.tokens = tokens;
    targetSession.expiresAt = Date.now() + (tokens.expires_in * 1000);

    // Get user info
    const userResponse = await fetch(`${this.baseUrl}/api/v4/user`, {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`,
      },
    });

    if (userResponse.ok) {
      const user = await userResponse.json();
      targetSession.user = {
        id: user.id.toString(),
        username: user.username,
        name: user.name,
        email: user.email,
      };
    }

    // Save to config file
    await this.saveConfigToFile(targetSession);

    logger.info(`OAuth authentication completed for user: ${targetSession.user?.username}`);
  }

  /**
   * Initiate PKCE OAuth flow (like glab CLI)
   */
  async initiateOAuthFlow(sessionId?: string): Promise<{ authUrl: string; sessionId: string; callbackUrl: string; server: Server }> {
    // Generate PKCE parameters
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const state = randomBytes(32).toString('base64url');

    // Determine callback port with reuse-first strategy and fallback range
    const preferredPort = Number(process.env.OAUTH_REDIRECT_PORT_PREFERRED || 7171);
    const rangeEnv = String(process.env.OAUTH_REDIRECT_PORT_RANGE || "7171-7199");
    const [rangeStartStr, rangeEndStr] = rangeEnv.split('-');
    const rangeStart = Number(rangeStartStr) || preferredPort;
    const rangeEnd = Number(rangeEndStr) || preferredPort;

    const port = await this.findReusableOrAvailablePort(preferredPort, rangeStart, rangeEnd);
    const redirectUri = `http://localhost:${port}/auth/redirect`;

    // Use provided sessionId or generate new one
    const finalSessionId = sessionId || `oauth-session-${Date.now()}`;

    // Create session
    const session: OAuthSession = {
      sessionId: finalSessionId,
      tokens: {
        access_token: "",
        refresh_token: "",
        expires_in: 0,
        token_type: "",
        scope: "",
        created_at: 0,
      },
      codeVerifier,
      state,
      expiresAt: 0,
      redirectUri,
    };

    this.sessions.set(finalSessionId, session);

    // Build authorization URL
    const authUrl = new URL(`${this.baseUrl}/oauth/authorize`);
    authUrl.searchParams.set('client_id', '41d48f9422ebd655dd9cf2947d6979681dfaddc6d0c56f7628f6ada59559af1e');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', this.scopes);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', state);

    // Start callback server on chosen port
    const server = await this.startCallbackServer(port);
    this.callbackServer = server;

    logger.info(`PKCE OAuth flow initiated for session: ${finalSessionId}`);

    return {
      authUrl: authUrl.toString(),
      sessionId: finalSessionId,
      callbackUrl: redirectUri,
      server
    };
  }

  /**
   * Check if user is authenticated and get session info
   */
  async getAuthStatus(sessionId: string): Promise<{
    authenticated: boolean;
    user?: any;
    expiresAt?: number;
    sessionId: string;
    message: string;
  }> {
    const session = this.sessions.get(sessionId);

    if (!session || !session.tokens.access_token) {
      return {
        authenticated: false,
        sessionId,
        message: "Session not found. Please use oauth_login to authenticate first."
      };
    }

    // Check if token is expired
    if (this.isTokenExpired(session)) {
      // Try to refresh
      const refreshed = await this.refreshToken(session);
      if (!refreshed) {
        this.sessions.delete(sessionId);
        return {
          authenticated: false,
          sessionId,
          message: "Session expired and refresh failed. Please re-authenticate."
        };
      }
    }

    return {
      authenticated: true,
      user: session.user,
      expiresAt: session.expiresAt,
      sessionId,
      message: "Authentication is valid"
    };
  }

  /**
   * Try to reuse preferredPort if an MCP-compatible server is already running.
   * Otherwise, find the first available port in [rangeStart, rangeEnd].
   */
  private async findReusableOrAvailablePort(preferredPort: number, rangeStart: number, rangeEnd: number): Promise<number> {
    // Prefer preferredPort if it's actually free
    const availablePreferred = await this.isPortFree(preferredPort);
    if (availablePreferred) return preferredPort;

    // Scan range for first free port (skip preferred since it's busy)
    for (let p = Math.max(rangeStart, preferredPort + 1); p <= rangeEnd; p++) {
      const isFree = await this.isPortFree(p);
      if (isFree) return p;
    }

    // No free port in range; fall back to preferred (will cause a clear bind error)
    return preferredPort;
  }

  /**
   * Check if a port is free by attempting to listen and immediately closing.
   */
  private async isPortFree(port: number): Promise<boolean> {
    const net = await import('net');
    return new Promise(resolve => {
      const tester = net.createServer()
        .once('error', (err: NodeJS.ErrnoException) => {
          if (err.code === 'EADDRINUSE') resolve(false);
          else resolve(false);
        })
        .once('listening', () => {
          tester.close(() => resolve(true));
        })
        .listen(port, '127.0.0.1');
    });
  }

  /**
   * Probe health endpoint to see if an MCP OAuth callback server is already running.
   */
  private async probeHealth(port: number): Promise<boolean> {
    try {
      const resp = await fetch(`http://127.0.0.1:${port}/health`, { method: 'GET' });
      if (!resp.ok) return false;
      const data = await resp.json().catch(() => ({} as any));
      // Minimal signature: status: healthy
      return data && data.status === 'healthy';
    } catch {
      return false;
    }
  }

  /**
   * Get persistent session ID (for loading from config)
   */
  getPersistentSessionId(): string | null {
    for (const [sessionId, session] of this.sessions.entries()) {
      if (sessionId === 'persistent-session' && session.tokens.access_token) {
        return sessionId;
      }
    }
    return null;
  }
}
