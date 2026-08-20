import { Entity, Column, PrimaryColumn, CreateDateColumn } from 'typeorm';

/** Rotating refresh token (OAuth 2.1 requires rotation for public clients), stored hashed. */
@Entity('oauth_refresh_tokens')
export class OAuthRefreshToken {
  /** sha256(refresh_token). */
  @PrimaryColumn({ type: 'varchar', length: 64 })
  tokenHash!: string;

  @Column({ type: 'varchar', length: 64 })
  clientId!: string;

  @Column({ type: 'varchar', length: 64 })
  apiKeyId!: string;

  @Column({ type: 'varchar', length: 300, nullable: true })
  resource!: string | null;

  @Column({ type: 'varchar', length: 300, nullable: true })
  scope!: string | null;

  @Column({ type: 'datetime' })
  expiresAt!: Date;

  @Column({ type: 'boolean', default: false })
  revoked!: boolean;

  @CreateDateColumn()
  createdAt!: Date;
}
