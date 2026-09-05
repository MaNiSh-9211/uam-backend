import { Pool } from 'pg';
import { drizzle } from 'drizzle-orm/node-postgres';
import { users, userIdentityIndexes } from './schema';
import { config } from './config';

export const pool = new Pool({
    connectionString: config.postgres.url,
    max: config.postgres.pool.max,
    idleTimeoutMillis: config.postgres.pool.idleTimeoutMs,
    connectionTimeoutMillis: config.postgres.pool.connectTimeoutMs,
    ssl: config.postgres.ssl
        ? { rejectUnauthorized: false }
        : undefined,
    application_name: config.postgres.appName,
});

pool.on('error', (err) => {
    console.error('PostgreSQL pool error:', err.message);
});

pool.on('connect', () => {
    console.log('PostgreSQL driver pool ready');
});

export const db = drizzle(pool, { schema: { users, userIdentityIndexes } });