import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * LOCAL: creates the self-hosted OAuth 2.1 tables (src/modules/oauth) on the main connection.
 *
 * Until v0.23 the main connection synchronized by default, which is how these tables were first
 * created. From v0.24 it is migration-managed, and boot refuses an entity column no migration
 * creates, so the oauth entities need their own migration. DDL mirrors what synchronize built.
 * Idempotent (IF NOT EXISTS), so a database created by synchronize is adopted in place.
 */
export class LocalCreateOAuthTables1790000000000 implements MigrationInterface {
  name = 'LocalCreateOAuthTables1790000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE IF NOT EXISTS "oauth_clients" ("clientId" varchar(64) PRIMARY KEY NOT NULL, "clientName" varchar(200), "redirectUris" text NOT NULL, "grantTypes" text, "tokenEndpointAuthMethod" varchar(40) NOT NULL DEFAULT ('none'), "scope" varchar(300), "createdAt" datetime NOT NULL DEFAULT (datetime('now')))`,
    );
    await queryRunner.query(
      `CREATE TABLE IF NOT EXISTS "oauth_auth_codes" ("codeHash" varchar(64) PRIMARY KEY NOT NULL, "clientId" varchar(64) NOT NULL, "redirectUri" varchar(500) NOT NULL, "codeChallenge" varchar(200) NOT NULL, "codeChallengeMethod" varchar(20) NOT NULL DEFAULT ('S256'), "apiKeyId" varchar(64) NOT NULL, "resource" varchar(300), "scope" varchar(300), "expiresAt" datetime NOT NULL, "used" boolean NOT NULL DEFAULT (0), "createdAt" datetime NOT NULL DEFAULT (datetime('now')))`,
    );
    await queryRunner.query(
      `CREATE TABLE IF NOT EXISTS "oauth_refresh_tokens" ("tokenHash" varchar(64) PRIMARY KEY NOT NULL, "clientId" varchar(64) NOT NULL, "apiKeyId" varchar(64) NOT NULL, "resource" varchar(300), "scope" varchar(300), "expiresAt" datetime NOT NULL, "revoked" boolean NOT NULL DEFAULT (0), "createdAt" datetime NOT NULL DEFAULT (datetime('now')))`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "oauth_refresh_tokens"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "oauth_auth_codes"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "oauth_clients"`);
  }
}
