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
}

/** AUTH-5, the only unauthenticated route. */
export const AUTH5_ROUTE_KEY = 'GET /v1/usernames/{username}/availability';
/** ACC-1, account deletion. */
export const ACC1_ROUTE_KEY = 'POST /v1/me/deletion';

const TOKENS: TokenLifetimes = {
  accessTokenMinutes: 15,
  idTokenMinutes: 15,
  refreshTokenDays: 90,
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
  },
};

/** Resolve a stage name (from `-c stage=...`) to its config, failing on unknown names. */
export function stageConfig(name: string | undefined): StageConfig {
  if (name === undefined || !(name in STAGES)) {
    throw new Error(`Unknown or missing stage '${name}'. Use -c stage=dev or -c stage=prod.`);
  }
  return STAGES[name as StageName];
}
