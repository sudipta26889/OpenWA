import { Entity, Column, PrimaryColumn, CreateDateColumn } from 'typeorm';

/** A dynamically-registered (RFC 7591) OAuth client, e.g. Claude registering itself. */
@Entity('oauth_clients')
export class OAuthClient {
  @PrimaryColumn({ type: 'varchar', length: 64 })
  clientId: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  clientName: string | null;

  @Column({ type: 'simple-array' })
  redirectUris: string[];

  @Column({ type: 'simple-array', nullable: true })
  grantTypes: string[] | null;

  @Column({ type: 'varchar', length: 40, default: 'none' })
  tokenEndpointAuthMethod: string;

  @Column({ type: 'varchar', length: 300, nullable: true })
  scope: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
