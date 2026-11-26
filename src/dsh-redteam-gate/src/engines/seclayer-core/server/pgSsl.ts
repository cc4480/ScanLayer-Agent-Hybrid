/**
 * TLS settings for the Postgres connection, shared by the server and the migration scripts.
 *
 * A local database (localhost, 127.0.0.1) gets no TLS. Anything else is always encrypted. By default the
 * server's certificate is not verified, because managed Postgres (Supabase, Railway) presents a chain we do not
 * bundle a CA for. Set PG_SSL_CA to the provider's CA certificate (PEM text, "\n" escapes allowed) and the
 * certificate is verified too, so the connection cannot be redirected to an impostor.
 */
export type PgSsl = undefined | { rejectUnauthorized: boolean; ca?: string };

export function pgSsl(url: string, env: NodeJS.ProcessEnv = process.env): PgSsl {
  if (/localhost|127\.0\.0\.1/.test(url)) return undefined;
  const ca = env.PG_SSL_CA?.replace(/\\n/g, "\n").trim();
  if (ca) return { rejectUnauthorized: true, ca };
  return { rejectUnauthorized: false };
}
