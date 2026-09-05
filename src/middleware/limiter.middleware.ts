import rateLimit, { type Store } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { redisRateLimit, isRedisRateLimitAvailable, runRateLimitCommand } from '../config/redis';
import { config } from '../config/index';
import { rateLimitConfig } from '../config/rateLimit.config';

const relaxAuthLimits = config.nodeEnv !== 'production' && (
    process.env.UAM_RELAX_AUTH_LIMITS === '1'
    || process.env.UAM_RELAX_AUTH_LIMITS === 'true'
);

let storeModeLogged = false;

/** Fail-closed store when Redis is down but distributed limits are required. */
class FailClosedRateLimitStore implements Store {
    async increment(_key: string): Promise<{ totalHits: number; resetTime: Date }> {
        return { totalHits: Number.MAX_SAFE_INTEGER, resetTime: new Date(Date.now() + 60_000) };
    }

    async decrement(_key: string): Promise<void> {}

    async resetKey(_key: string): Promise<void> {}
}

/** In-memory fallback when Redis is unavailable but distributed is not required. */
class InMemoryRateLimitStore implements Store {
    private hits = new Map<string, { count: number; resetTime: Date }>();

    async increment(key: string): Promise<{ totalHits: number; resetTime: Date }> {
        const now = Date.now();
        const entry = this.hits.get(key);
        if (!entry || entry.resetTime.getTime() <= now) {
            const resetTime = new Date(now + 60_000);
            this.hits.set(key, { count: 1, resetTime });
            return { totalHits: 1, resetTime };
        }
        entry.count++;
        return { totalHits: entry.count, resetTime: entry.resetTime };
    }

    async decrement(_key: string): Promise<void> {}

    async resetKey(_key: string): Promise<void> {
        this.hits.delete(_key);
    }
}

// Each limiter needs its own RedisStore prefix so counters do not collide on the same IP key.
const getStore = (prefix: string): Store | undefined => {
    if (config.redis.enabled && redisRateLimit) {
        if (!storeModeLogged) {
            console.log('⚡ Rate Limiting: Redis Store (distributed across UAM replicas)');
            storeModeLogged = true;
        }
        return new RedisStore({
            prefix,
            sendCommand: (...args: string[]) => {
                return runRateLimitCommand(() => {
                    return (redisRateLimit as any).call(...args);
                }).then((res) => {
                    if (!res.ok) {
                        console.warn(`Redis circuit ${res.outcome} - falling back to in-memory`);
                        throw new Error(`redis circuit ${res.outcome}`);
                    }
                    return res.value;
                }) as any;
            },
        });
    }

    if (!storeModeLogged) {
        console.log('⚠️ Rate Limiting: in-memory store (Redis unavailable or disabled)');
        storeModeLogged = true;
    }
    return new InMemoryRateLimitStore();
};

/** Warn if production expects fleet-wide limits but Redis rate-limit pool is down. */
export function assertDistributedRateLimitReady(): void {
    if (!config.rateLimit.requireDistributed) return;
    if (!config.redis.enabled) {
        console.warn('⚠️ UAM_REQUIRE_DISTRIBUTED_RATE_LIMIT set but REDIS_ENABLED=false - using in-memory fallback');
        return;
    }
    if (!isRedisRateLimitAvailable()) {
        console.warn('⚠️ Redis rate-limit pool not ready - using in-memory fallback');
        return;
    }
    console.log('✅ Distributed rate limiting ready (Redis)');
}
// General API Limiter - 1000 requests per minute (very generous for development)
export const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 1000,
    standardHeaders: true,
    legacyHeaders: false,
    store: getStore('rl:api:'),
    message: {
        success: false,
        message: 'Too many requests from this IP, please try again after 15 minutes.',
    },
});

// Strict Auth Limiter - Fallback for other auth routes
export const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: relaxAuthLimits ? 10_000 : 20,
    standardHeaders: true,
    legacyHeaders: false,
    store: getStore('rl:auth:'),
    message: {
        success: false,
        message: 'Too many authentication attempts, please try again after an hour.',
    },
});

// Email Existence Check Limiter
export const emailCheckLimiter = rateLimit({
    windowMs: rateLimitConfig.emailCheck.windowMs,
    limit: rateLimitConfig.emailCheck.limit,
    standardHeaders: true,
    legacyHeaders: false,
    store: getStore('rl:email:'),
    message: {
        success: false,
        message: 'Too many email checks, please slow down.',
    },
});

// Password Reset Limiter
export const passwordResetLimiter = rateLimit({
    windowMs: rateLimitConfig.passwordReset.windowMs,
    limit: relaxAuthLimits ? 10_000 : rateLimitConfig.passwordReset.limitPerWindow,
    standardHeaders: true,
    legacyHeaders: false,
    store: getStore('rl:pwd:'),
    message: {
        success: false,
        message: 'Too many password reset requests, please try again after 12 hours.',
    },
});

// Refresh + logout — limit brute-force of refresh tokens
export const sessionLimiter = rateLimit({
    windowMs: rateLimitConfig.session.windowMs,
    limit: relaxAuthLimits ? 10_000 : rateLimitConfig.session.limit,
    standardHeaders: true,
    legacyHeaders: false,
    store: getStore('rl:session:'),
    message: {
        success: false,
        message: 'Too many session requests, please slow down.',
    },
});

// Email migration — init/verify/resend (ADR-0063)
export const migrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: relaxAuthLimits ? 10_000 : 15,
    standardHeaders: true,
    legacyHeaders: false,
    store: getStore('rl:migrate:'),
    message: {
        success: false,
        message: 'Too many migration requests, please try again later.',
    },
});
