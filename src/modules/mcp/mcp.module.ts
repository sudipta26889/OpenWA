import { type DynamicModule, Module, type MiddlewareConsumer, type NestModule, Optional } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { ToolRegistryService } from '../../core/agent-tools/tool-registry.service';
import { AuthService } from '../auth/auth.service';
import { AuditService } from '../audit/audit.service';
import { OAuthService } from '../oauth/oauth.service';
import { KeyRateLimiter, readRateLimitConfig, readIpRateLimitConfig } from './mcp-rate-limit';
import { mountMcpServer, type McpOAuthBridge } from './mcp.server';

export interface McpModuleOptions {
  basePath?: string;
  serverInfo?: { name: string; version: string };
}

// Module-level options store: set by forRoot(), read by configure().
// Safe because configure() runs after DI resolution (i.e., after forRoot() has been called).
let _moduleOptions: McpModuleOptions = {};

@Module({})
export class McpModule implements NestModule {
  constructor(
    private readonly registry: ToolRegistryService,
    private readonly authService: AuthService,
    private readonly httpAdapterHost: HttpAdapterHost,
    // AuditModule is @Global(), so AuditService is injectable here without an explicit import.
    private readonly auditService: AuditService,
    // Present only when OAUTH_ENABLED loads the (global) OAuthModule; undefined otherwise.
    @Optional() private readonly oauthService?: OAuthService,
  ) {}

  static forRoot(options: McpModuleOptions = {}): DynamicModule {
    _moduleOptions = options;
    return {
      module: McpModule,
      global: false,
      providers: [],
      exports: [],
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  configure(_consumer: MiddlewareConsumer): void {
    const httpAdapter = this.httpAdapterHost.httpAdapter;
    if (!httpAdapter) {
      throw new Error('McpModule: HttpAdapterHost.httpAdapter is not available.');
    }
    const { basePath, serverInfo } = _moduleOptions;
    const { max, windowMs } = readRateLimitConfig();
    const rateLimiter = new KeyRateLimiter(max, windowMs);
    const ipCfg = readIpRateLimitConfig();
    const ipRateLimiter = new KeyRateLimiter(ipCfg.max, ipCfg.windowMs);
    // Build the OAuth bridge only when the AS is enabled; otherwise MCP stays static-key-only.
    let oauth: McpOAuthBridge | undefined;
    if (this.oauthService && process.env.OAUTH_ENABLED === 'true') {
      const svc = this.oauthService;
      oauth = {
        verify: (bearer: string) => svc.verifyAccessToken(bearer) !== null,
        resolve: (bearer: string) => svc.resolveApiKey(bearer),
        resourceMetadataUrl: svc.protectedResourceMetadataUrl(),
      };
    }
    mountMcpServer(
      httpAdapter,
      this.registry,
      this.authService,
      rateLimiter,
      ipRateLimiter,
      { basePath, serverInfo, oauth },
      this.auditService,
    );
  }
}
