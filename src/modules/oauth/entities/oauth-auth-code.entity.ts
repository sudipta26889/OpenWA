import { Entity, Column, PrimaryColumn, CreateDateColumn } from 'typeorm';

/** Short-lived authorization code, stored hashed. Bound to PKCE challenge + the approving API key. */
@Entity('oauth_auth_codes')
export class OAuthAuthCode {
  /** sha256(code) — the raw code is only ever returned to the client, never stored. */
  @PrimaryColumn({ type: 'varchar', length: 64 })
  codeHash: string;

  @Column({ type: 'varchar', length: 64 })
  clientId: string;

  @Column({ type: 'varchar', length: 500 })
  redirectUri: string;

  @Column({ type: 'varchar', length: 200 })
  codeChallenge: string;

  @Column({ type: 'varchar', length: 20, default: 'S256' })
  codeChallengeMethod: string;

  /** The OpenWA API key id this authorization is bound to (token principal). */
  @Column({ type: 'varchar', length: 64 })
  apiKeyId: string;

  @Column({ type: 'varchar', length: 300, nullable: true })
  resource: string | null;

  @Column({ type: 'varchar', length: 300, nullable: true })
  scope: string | null;

  @Column({ type: 'datetime' })
  expiresAt: Date;

  @Column({ type: 'boolean', default: false })
  used: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
