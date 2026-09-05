import { Pool } from 'pg';
import * as fs from 'node:fs';
import { drizzle } from 'drizzle-orm/node-postgres';
import { users, userIdentityIndexes } from './schema';

export const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: Number(process.env.PG_POOL_MAX) || 10,
    idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS) || 30_000,
    connectionTimeoutMillis: Number(process.env.PG_CONNECT_TIMEOUT_MS) || 10_000,
    ssl: process.env.PG_SSL === 'true'
        ? { rejectUnauthorized: false, ca: fs.readFileSync('/app/ca.crt') }
        : undefined,
    application_name: process.env.PG_APP_NAME || 'uam-backend',
});

pool.on('error', (err) => {
    console.error('PostgreSQL pool error:', err.message);
});

pool.on('connect', () => {
    console.log('PostgreSQL driver pool ready');
});

export const db = drizzle(pool, { schema: { users, userIdentityIndexes } });