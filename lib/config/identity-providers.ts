/**
 * Federated identity-provider registry (auth_design.md §3.4, REQ-FED-4/7/8/9).
 *
 * This is the single list of providers the system knows about. A stage enables a subset of
 * them through `StageConfig.enabledIdps`; a provider that is not enabled creates no
 * resources and appears in no client configuration (REQ-FED-9).
 *
 * Adding a provider of an existing kind: add an entry here, create its secret at
 * `ourlore/<stage>/idp/<id>`, add the id to the stage's `enabledIdps`, and add the iOS
 * provider case. A new `kind` adds one branch to `createIdentityProvider`.
 *
 * Nothing in this file is secret. Credentials live in Secrets Manager and reach the
 * template only as `{{resolve:secretsmanager:...}}` dynamic references.
 */

/** Stable Ourlore provider ids. Extend the union when a provider is added. */
export type IdpId = 'apple' | 'google';

/** Provider kinds with a factory branch in `createIdentityProvider`. */
export type IdpKind = 'apple' | 'google' | 'oidc'; // extend with 'saml' | 'facebook' | 'amazon'

/**
 * How a provider's email is trusted at sign-up (REQ-FED-4).
 *
 * - `always`: the provider only releases verified emails (Apple).
 * - `claim`: trusted only when the provider asserts `email_verified = true` at sign-up; the
 *   claim is mapped to `custom:idp_email_verified` and checked by the pre-sign-up trigger.
 */
export type EmailVerifiedPolicy = 'always' | 'claim';

/** One registry entry. */
export interface IdpDefinition {
  /** Stable Ourlore id; also the last segment of the secret name. */
  readonly id: IdpId;
  /** Which factory branch builds the Cognito provider. */
  readonly kind: IdpKind;
  /** Cognito provider name (`SignInWithApple`, `Google`, or a custom OIDC name). */
  readonly cognitoProviderName: string;
  /** Scopes requested from the provider. */
  readonly scopes: readonly string[];
  /** Email trust policy (REQ-FED-4). */
  readonly emailVerified: EmailVerifiedPolicy;
  /** Provider claim names mapped into the user pool. */
  readonly attributeMapping: {
    /** Provider claim mapped to the standard `email` attribute. */
    readonly email: string;
    /** Provider claim mapped to `custom:idp_email_verified`; required for `claim` providers. */
    readonly emailVerifiedClaim?: string;
  };
  /** Only for `kind === 'oidc'`. */
  readonly oidc?: { readonly issuerUrl: string };
}

/**
 * JSON field names each kind expects in its Secrets Manager secret.
 *
 * - apple: `{ servicesId, teamId, keyId, privateKey, bundleId }` (`bundleId` is read by the
 *   backend's ACC-1 Apple revocation, not by Cognito)
 * - google / oidc: `{ clientId, clientSecret }`
 */
export const SECRET_FIELDS: Readonly<Record<IdpKind, readonly string[]>> = {
  apple: ['servicesId', 'teamId', 'keyId', 'privateKey', 'bundleId'],
  google: ['clientId', 'clientSecret'],
  oidc: ['clientId', 'clientSecret'],
};

/** The registry. Order is display order hint only; the iOS client puts Apple first. */
export const IDENTITY_PROVIDERS: Readonly<Record<IdpId, IdpDefinition>> = {
  apple: {
    id: 'apple',
    kind: 'apple',
    cognitoProviderName: 'SignInWithApple',
    scopes: ['email'],
    emailVerified: 'always',
    attributeMapping: { email: 'email' },
  },
  google: {
    id: 'google',
    kind: 'google',
    cognitoProviderName: 'Google',
    scopes: ['openid', 'email'],
    emailVerified: 'claim',
    attributeMapping: { email: 'email', emailVerifiedClaim: 'email_verified' },
  },
};

/** Default Secrets Manager name of a provider's credentials in a stage. */
export function defaultIdpSecretName(stage: string, id: IdpId): string {
  return `ourlore/${stage}/idp/${id}`;
}

/** One entry of the `IDP_REGISTRY` env var, keyed by lower-cased Cognito provider name. */
export interface IdpRegistryEntry {
  readonly id: IdpId;
  readonly emailVerified: EmailVerifiedPolicy;
}

/**
 * Render the `IDP_REGISTRY` env var for the enabled providers:
 * `{"<cognitoProviderNameLower>": {"id": "...", "emailVerified": "always"|"claim"}}`.
 *
 * Keys are sorted so the value (and therefore the template) is deterministic.
 */
export function renderIdpRegistry(defs: readonly IdpDefinition[]): string {
  const entries = [...defs]
    .sort((a, b) => a.cognitoProviderName.toLowerCase().localeCompare(b.cognitoProviderName.toLowerCase()))
    .map((d): [string, IdpRegistryEntry] => [
      d.cognitoProviderName.toLowerCase(),
      { id: d.id, emailVerified: d.emailVerified },
    ]);
  return JSON.stringify(Object.fromEntries(entries));
}

/**
 * Validate the registry's internal consistency. Throws on the first problem.
 *
 * - `claim` providers must name the claim to map (REQ-FED-4)
 * - `oidc` providers must have an issuer
 * - ids and Cognito provider names (case-insensitively) are unique
 */
export function validateRegistry(registry: Readonly<Record<string, IdpDefinition>>): void {
  const names = new Set<string>();
  for (const [key, def] of Object.entries(registry)) {
    if (key !== def.id) {
      throw new Error(`IdP registry key '${key}' does not match its id '${def.id}'.`);
    }
    if (def.emailVerified === 'claim' && !def.attributeMapping.emailVerifiedClaim) {
      throw new Error(`IdP '${def.id}' is 'claim' but has no attributeMapping.emailVerifiedClaim.`);
    }
    if (def.kind === 'oidc' && !def.oidc?.issuerUrl) {
      throw new Error(`OIDC IdP '${def.id}' has no oidc.issuerUrl.`);
    }
    const lower = def.cognitoProviderName.toLowerCase();
    if (names.has(lower)) {
      throw new Error(`Duplicate Cognito provider name '${def.cognitoProviderName}'.`);
    }
    names.add(lower);
  }
}
