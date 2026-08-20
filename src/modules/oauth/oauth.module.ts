import { Module, Global, type MiddlewareConsumer, type NestModule } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { TypeOrmModule } from '@nestjs/typeorm';
import { OAuthClient } from './entities/oauth-client.entity';
import { OAuthAuthCode } from './entities/oauth-auth-code.entity';
import { OAuthRefreshToken } from './entities/oauth-refresh-token.entity';
import { OAuthService } from './oauth.service';
import { mountOAuthRoutes } from './oauth.routes';

/**
 * Self-hosted OAuth 2.1 Authorization Server + Resource-Server support for the MCP endpoint.
 * Global so McpModule can inject OAuthService to validate bearer tokens. Opt-in via OAUTH_ENABLED.
 */
@Global()
@Module({
  imports: [TypeOrmModule.forFeature([OAuthClient, OAuthAuthCode, OAuthRefreshToken], 'main')],
  providers: [OAuthService],
  exports: [OAuthService],
})
export class OAuthModule implements NestModule {
  constructor(
    private readonly oauthService: OAuthService,
    private readonly httpAdapterHost: HttpAdapterHost,
  ) {}

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  configure(_consumer: MiddlewareConsumer): void {
    const httpAdapter = this.httpAdapterHost.httpAdapter;
    if (!httpAdapter) throw new Error('OAuthModule: HttpAdapterHost.httpAdapter is not available.');
    mountOAuthRoutes(httpAdapter, this.oauthService);
  }
}
