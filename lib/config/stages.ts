/**
 * Per-stage, non-secret configuration (auth_design.md §3.1).
 *
 * Committed to a public repository: never put account ids, ARNs, secrets, or personal data
 * here. The alarm email and the prod SES sender come from context (`-c alarmEmail=...`,
 * `-c sesFromEmail=... -c sesVerifiedDomain=...`), and IdP credentials live in Secrets Manager.
 */
import type { IdpId } from './identity-providers';

/** Deployable stages. */
export type StageName = 'dev' | 'prod';

/** API Gateway throttle, shared by all callers (REQ-OPS-1). */
export interface ThrottleConfig {
  /** Steady-state requests per second. */
  readonly rate: number;
  /** Burst capacity. */
  readonly burst: number;
}

/** Token lifetimes (D-4, REQ-ID-4). */
export interface TokenLifetimes {
  readonly accessTokenMinutes: number;
  readonly idTokenMinutes: number;
  /**
   * Refresh-token lifetime in whole days, in [1, {@link MAX_REFRESH_TOKEN_DAYS}] (Cognito's
   * ceiling is 10 years). Bounds the longest a signed-in device stays signed in without
   * re-entering credentials; rotation (REQ-ID-5) still replaces the token on every refresh.
   */
  readonly refreshTokenDays: number;
  /** Hosted UI / SRP session validity (3–15 min). */
  readonly authSessionMinutes: number;
  /** Refresh-token rotation retry grace period (REQ-ID-5). */
  readonly refreshRotationGraceSeconds: number;
}

/** SES delivery for Cognito email (REQ-PW-7). Supplied through context: see `ses.ts`. */
export interface SesConfig {
  readonly fromEmail: string;
  readonly sesVerifiedDomain: string;
  /** Region of the SES identity. Defaults to the stack's region. */
  readonly sesRegion?: string;
}

/** Everything that differs between stages. */
export interface StageConfig {
  readonly stage: StageName;
  /** Globally unique Cognito prefix domain. */
  readonly domainPrefix: string;
  readonly callbackUrls: readonly string[];
  readonly logoutUrls: readonly string[];
  /** Providers enabled in this stage; each needs its secret to exist first (REQ-FED-9). */
  readonly enabledIdps: readonly IdpId[];
  /**
   * Optional override of the Secrets Manager names of IdP credentials. Defaults to
   * `ourlore/<stage>/idp/<id>`. Tests use it to inject fixture names.
   */
  readonly idpSecretNames?: Partial<Readonly<Record<IdpId, string>>>;
  readonly tokens: TokenLifetimes;
  readonly throttle: {
    /** Stage-wide default route throttle. */
    readonly default: ThrottleConfig;
    /** Per-route overrides keyed by API Gateway route key (`METHOD /path`). */
    readonly routes: Readonly<Record<string, ThrottleConfig>>;
  };
  /**
   * SES sender. Never committed: `prod` gets it from context (`-c sesFromEmail=...
   * -c sesVerifiedDomain=...`, see `ses.ts`) and fails synth without it. When absent in `dev`,
   * Cognito's default sender is used.
   */
  readonly ses?: SesConfig;
  /** Attach a WAF web ACL with an IP rate rule to the user pool (REQ-OPS-2). */
  readonly waf: boolean;
  /** CloudFormation stack termination protection (REQ-OPS-3). */
  readonly terminationProtection: boolean;
  /** CloudWatch Logs retention for Lambda and access logs. */
  readonly logRetentionDays: number;
  /** Powertools log level for every function. */
  readonly logLevel: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR';
  /**
   * Seconds between ACC-1 acceptance and the start of the data purge (`purgeNotBefore`,
   * auth_design.md §4.3), passed to the `account` function as `PURGE_DELAY_SECONDS`. It covers
   * work already in flight when the tombstone committed (access tokens, presigned UPL-1
   * POSTs). `prod` must be at least the access-token lifetime + 60 s and the UPL-1 POST
   * expiry + 60 s (see `validateStageConfig`).
   */
  readonly purgeDelaySeconds: number;
}

/** Longest UPL-1 presigned POST policy expiry (api_interface.md §8; app `PRESIGN_EXPIRY_SECONDS`). */
export const UPLOAD_POST_EXPIRY_SECONDS = 900;
/** Margin added on top of each lifetime the prod purge delay must outlast. */
export const PURGE_DELAY_MARGIN_SECONDS = 60;
/** Cognito's maximum refresh-token validity: 10 years, expressed in days (3650). */
export const MAX_REFRESH_TOKEN_DAYS = 3650;

/** AUTH-5, the only unauthenticated route. */
export const AUTH5_ROUTE_KEY = 'GET /v1/usernames/{username}/availability';
/** ACC-1, account deletion. */
export const ACC1_ROUTE_KEY = 'POST /v1/me/deletion';

const TOKENS: TokenLifetimes = {
  accessTokenMinutes: 15,
  idTokenMinutes: 15,
  refreshTokenDays: 365,
  authSessionMinutes: 3,
  refreshRotationGraceSeconds: 10,
};

const THROTTLE: StageConfig['throttle'] = {
  default: { rate: 50, burst: 100 },
  routes: {
    [AUTH5_ROUTE_KEY]: { rate: 10, burst: 20 },
    [ACC1_ROUTE_KEY]: { rate: 2, burst: 5 },
  },
};

/** Committed stage definitions. */
export const STAGES: Readonly<Record<StageName, StageConfig>> = {
  dev: {
    stage: 'dev',
    domainPrefix: 'ourlore-dev-auth',
    callbackUrls: ['ourlore://auth/callback/'],
    logoutUrls: ['ourlore://auth/signout/'],
    // Empty until the operator creates ourlore/dev/idp/<id> (REQ-FED-9).
    enabledIdps: [],
    tokens: TOKENS,
    throttle: THROTTLE,
    waf: false,
    terminationProtection: false,
    logRetentionDays: 14,
    logLevel: 'INFO',
    // Short so the deletion E2E finishes in minutes; raise to 960 to rehearse prod timing.
    purgeDelaySeconds: 120,
  },
  prod: {
    stage: 'prod',
    domainPrefix: 'ourlore-prod-auth',
    callbackUrls: ['ourlore://auth/callback/'],
    logoutUrls: ['ourlore://auth/signout/'],
    enabledIdps: [],
    tokens: TOKENS,
    throttle: THROTTLE,
    // SES (REQ-PW-7) is operator-specific and comes from context at synth: see ses.ts.
    waf: true,
    terminationProtection: true,
    logRetentionDays: 90,
    logLevel: 'INFO',
    // UPL-1 POST expiry (900 s) + 60 s; also >= access-token lifetime (15 min) + 60 s.
    purgeDelaySeconds: 960,
  },
};

/** Smallest `purgeDelaySeconds` a prod stage may use (auth_design.md §4.3). */
export function minimumProdPurgeDelaySeconds(config: Pick<StageConfig, 'tokens'>): number {
  return Math.max(
    config.tokens.accessTokenMinutes * 60 + PURGE_DELAY_MARGIN_SECONDS,
    UPLOAD_POST_EXPIRY_SECONDS + PURGE_DELAY_MARGIN_SECONDS,
  );
}

/**
 * Synth-time validation of values the stack can't express as types.
 *
 * `purgeDelaySeconds` must be a non-negative integer no larger than a day (the purge must
 * finish within 24 h, REQ-DEL-5). In `prod` it must also outlast every access token and
 * presigned upload issued before the tombstone committed.
 *
 * `tokens.refreshTokenDays` must be an integer in [1, {@link MAX_REFRESH_TOKEN_DAYS}]: Cognito
 * rejects longer lifetimes at deploy time, so fail at synth instead.
 */
export function validateStageConfig(config: StageConfig): StageConfig {
  const refreshDays = config.tokens.refreshTokenDays;
  if (!Number.isInteger(refreshDays) || refreshDays < 1 || refreshDays > MAX_REFRESH_TOKEN_DAYS) {
    throw new Error(
      `tokens.refreshTokenDays must be an integer in [1, ${MAX_REFRESH_TOKEN_DAYS}]; got ${String(refreshDays)}.`,
    );
  }
  const delay = config.purgeDelaySeconds;
  if (!Number.isInteger(delay) || delay < 0 || delay > 86_400) {
    throw new Error(`purgeDelaySeconds must be an integer in [0, 86400]; got ${String(delay)}.`);
  }
  if (config.stage === 'prod') {
    const minimum = minimumProdPurgeDelaySeconds(config);
    if (delay < minimum) {
      throw new Error(
        `prod purgeDelaySeconds (${delay}) must be >= ${minimum}: the access-token lifetime ` +
          `(${config.tokens.accessTokenMinutes * 60} s) + ${PURGE_DELAY_MARGIN_SECONDS} s and the UPL-1 POST ` +
          `expiry (${UPLOAD_POST_EXPIRY_SECONDS} s) + ${PURGE_DELAY_MARGIN_SECONDS} s (auth_design.md §4.3).`,
      );
    }
  }
  return config;
}

/** Resolve a stage name (from `-c stage=...`) to its config, failing on unknown names. */
export function stageConfig(name: string | undefined): StageConfig {
  if (name === undefined || !(name in STAGES)) {
    throw new Error(`Unknown or missing stage '${name}'. Use -c stage=dev or -c stage=prod.`);
  }
  return STAGES[name as StageName];
}
