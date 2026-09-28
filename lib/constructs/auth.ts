/**
 * Identity: user pool, prefix domain, iOS app client, federated IdPs, pre-sign-up trigger,
 * and the optional WAF (auth_design.md §3.2–§3.5, §3.9).
 */
import { Duration, RemovalPolicy, SecretValue, Stack } from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Construct } from 'constructs';
import type { Contract } from '../contract';
import {
  IDENTITY_PROVIDERS,
  IdpDefinition,
  IdpId,
  defaultIdpSecretName,
  renderIdpRegistry,
  validateRegistry,
} from '../config/identity-providers';
import type { StageConfig } from '../config/stages';
import { ContractBindings, ContractFunction } from './contract-function';

export const USER_POOL_LOGICAL_ID = 'UserPool';
export const USER_POOL_CLIENT_LOGICAL_ID = 'UserPoolClientIos';
export const USER_POOL_DOMAIN_LOGICAL_ID = 'UserPoolDomain';

/** Custom attribute holding the IdP's `email_verified` claim at sign-up (§3.2, §3.4). */
export const IDP_EMAIL_VERIFIED_ATTR = 'idp_email_verified';

/** OAuth scopes of the iOS client. `aws.cognito.signin.user.admin` is the API route scope. */
export const OAUTH_SCOPES: readonly cognito.OAuthScope[] = [
  cognito.OAuthScope.OPENID,
  cognito.OAuthScope.EMAIL,
  cognito.OAuthScope.COGNITO_ADMIN,
];

/**
 * Build the Cognito identity provider for one registry entry.
 *
 * Every credential comes from `SecretValue.secretsManager(secretName, { jsonField })`, so the
 * template holds only `{{resolve:secretsmanager:...}}` dynamic references (REQ-FED-8).
 */
export function createIdentityProvider(
  scope: Construct,
  pool: cognito.IUserPool,
  def: IdpDefinition,
  secretName: string,
): cognito.IUserPoolIdentityProvider {
  const field = (jsonField: string): SecretValue => SecretValue.secretsManager(secretName, { jsonField });
  // `unsafeUnwrap()` here does NOT expose a value: it renders the same dynamic reference as a
  // string for props the L2 types as `string`. These fields (client/team/key ids) are not
  // secret, but keeping them in the secret gives the operator one place to manage a provider.
  const ref = (jsonField: string): string => field(jsonField).unsafeUnwrap();
  const custom: Record<string, cognito.ProviderAttribute> = {};
  if (def.attributeMapping.emailVerifiedClaim) {
    custom[`custom:${IDP_EMAIL_VERIFIED_ATTR}`] = cognito.ProviderAttribute.other(def.attributeMapping.emailVerifiedClaim);
  }
  const attributeMapping: cognito.AttributeMapping = {
    email: cognito.ProviderAttribute.other(def.attributeMapping.email),
    custom: Object.keys(custom).length > 0 ? custom : undefined,
  };
  const id = `Idp${def.id.charAt(0).toUpperCase()}${def.id.slice(1)}`;

  switch (def.kind) {
    case 'apple':
      return new cognito.UserPoolIdentityProviderApple(scope, id, {
        userPool: pool,
        clientId: ref('servicesId'),
        teamId: ref('teamId'),
        keyId: ref('keyId'),
        privateKeyValue: field('privateKey'),
        scopes: [...def.scopes],
        attributeMapping,
      });
    case 'google':
      return new cognito.UserPoolIdentityProviderGoogle(scope, id, {
        userPool: pool,
        clientId: ref('clientId'),
        clientSecretValue: field('clientSecret'),
        scopes: [...def.scopes],
        attributeMapping,
      });
    case 'oidc':
      if (!def.oidc) throw new Error(`OIDC IdP '${def.id}' has no issuer.`);
      return new cognito.UserPoolIdentityProviderOidc(scope, id, {
        userPool: pool,
        name: def.cognitoProviderName,
        clientId: ref('clientId'),
        clientSecret: ref('clientSecret'),
        issuerUrl: def.oidc.issuerUrl,
        scopes: [...def.scopes],
        attributeMapping,
      });
    default: {
      const never: never = def.kind;
      throw new Error(`Unsupported IdP kind '${String(never)}'.`);
    }
  }
}

export interface AuthProps {
  readonly config: StageConfig;
  readonly contract: Contract;
  readonly bindings: ContractBindings;
  readonly code: lambda.Code;
  /** Registry to resolve `enabledIdps` against; tests may inject one. */
  readonly registry?: Readonly<Record<string, IdpDefinition>>;
}

/** User pool and everything attached to it. */
export class Auth extends Construct {
  readonly userPool: cognito.UserPool;
  readonly client: cognito.UserPoolClient;
  readonly domain: cognito.UserPoolDomain;
  readonly enabledIdps: readonly IdpDefinition[];
  readonly identityProviders: readonly cognito.IUserPoolIdentityProvider[];
  readonly preSignUp: ContractFunction;
  /** `IDP_REGISTRY` env value for the enabled providers. */
  readonly idpRegistryJson: string;
  /** `<prefix>.auth.<region>.amazoncognito.com` */
  readonly domainHost: string;

  constructor(scope: Construct, id: string, props: AuthProps) {
    super(scope, id);
    const { config, contract, bindings } = props;
    const registry = props.registry ?? IDENTITY_PROVIDERS;
    validateRegistry(registry);

    this.enabledIdps = config.enabledIdps.map((idpId) => {
      const def = registry[idpId];
      if (!def) throw new Error(`Stage '${config.stage}' enables unknown IdP '${idpId}'.`);
      return def;
    });
    if (new Set(config.enabledIdps).size !== config.enabledIdps.length) {
      throw new Error(`Stage '${config.stage}' lists an IdP twice.`);
    }
    this.idpRegistryJson = renderIdpRegistry(this.enabledIdps);
    bindings.setEnv('IDP_REGISTRY', this.idpRegistryJson);

    // --- Pre-sign-up trigger (§3.5). Its grant is a standalone policy in *this* scope
    // (outside the function's and role's subtrees) so the function does not depend on it.
    const trigger = contract.cognito_triggers.pre_sign_up;
    if (!trigger) throw new Error('contract.json has no cognito_triggers.pre_sign_up.');
    if (trigger.env.includes('COGNITO_USER_POOL_ID')) {
      throw new Error('pre_sign_up must not receive COGNITO_USER_POOL_ID (pool ↔ function cycle).');
    }
    const prod = config.stage === 'prod';

    // --- User pool (§3.2)
    if (prod && !config.ses) {
      // Defense in depth: OurloreStack already resolves prod SES from context or throws.
      throw new Error("Stage 'prod' requires an SES sender (REQ-PW-7); see lib/config/ses.ts.");
    }
    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `ourlore-${config.stage}`,
      selfSignUpEnabled: true,
      signInAliases: { email: true },
      signInCaseSensitive: false,
      autoVerify: { email: true },
      keepOriginal: { email: true },
      standardAttributes: { email: { required: true, mutable: true } },
      customAttributes: {
        [IDP_EMAIL_VERIFIED_ATTR]: new cognito.StringAttribute({ maxLen: 8, mutable: true }),
      },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: Duration.days(3),
        passwordHistorySize: 5,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      mfa: cognito.Mfa.OFF,
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN,
      userVerification: {
        emailStyle: cognito.VerificationEmailStyle.CODE,
        emailSubject: 'Your Ourlore verification code',
        emailBody: 'Your Ourlore verification code is {####}. It expires in 24 hours.',
      },
      email: config.ses
        ? cognito.UserPoolEmail.withSES({
            fromEmail: config.ses.fromEmail,
            fromName: 'Ourlore',
            sesVerifiedDomain: config.ses.sesVerifiedDomain,
            // The stack region token works env-agnostic; withSES needs a value either way.
            sesRegion: config.ses.sesRegion ?? Stack.of(this).region,
          })
        : cognito.UserPoolEmail.withCognito(),
    });
    (this.userPool.node.defaultChild as cognito.CfnUserPool).overrideLogicalId(USER_POOL_LOGICAL_ID);
    bindings.setUserPoolArn(this.userPool.userPoolArn);
    bindings.setEnv('COGNITO_USER_POOL_ID', this.userPool.userPoolId);

    this.preSignUp = new ContractFunction(this, 'PreSignUp', {
      spec: trigger,
      bindings,
      code: props.code,
      serviceName: 'ourlore-pre-sign-up',
      logLevel: config.logLevel,
      logRetentionDays: config.logRetentionDays,
      logRemovalPolicy: prod ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
      description: 'Cognito pre-sign-up: best-effort duplicate-email guard (read-only)',
      standalonePolicyScope: this,
    });
    this.userPool.addTrigger(cognito.UserPoolOperation.PRE_SIGN_UP, this.preSignUp.function);

    // --- Domain (§3.3): Cognito prefix domain, classic hosted UI.
    this.domain = this.userPool.addDomain('Domain', {
      cognitoDomain: { domainPrefix: config.domainPrefix },
      managedLoginVersion: cognito.ManagedLoginVersion.CLASSIC_HOSTED_UI,
    });
    (this.domain.node.defaultChild as cognito.CfnUserPoolDomain).overrideLogicalId(USER_POOL_DOMAIN_LOGICAL_ID);
    this.domainHost = `${config.domainPrefix}.auth.${Stack.of(this).region}.amazoncognito.com`;

    // --- Federated IdPs (§3.4): only the enabled ones create resources (REQ-FED-9).
    this.identityProviders = this.enabledIdps.map((def) =>
      createIdentityProvider(
        this,
        this.userPool,
        def,
        config.idpSecretNames?.[def.id as IdpId] ?? defaultIdpSecretName(config.stage, def.id),
      ),
    );

    // --- App client (§3.3)
    this.client = this.userPool.addClient('IosClient', {
      userPoolClientName: 'ios',
      generateSecret: false,
      // With a rotation grace period the L2 omits ALLOW_REFRESH_TOKEN_AUTH, leaving only SRP;
      // refresh goes through GetTokensFromRefreshToken / the OAuth refresh grant.
      authFlows: { userSrp: true },
      refreshTokenRotationGracePeriod: Duration.seconds(config.tokens.refreshRotationGraceSeconds),
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [...OAUTH_SCOPES],
        callbackUrls: [...config.callbackUrls],
        logoutUrls: [...config.logoutUrls],
      },
      supportedIdentityProviders: [
        cognito.UserPoolClientIdentityProvider.COGNITO,
        ...this.enabledIdps.map((d) => cognito.UserPoolClientIdentityProvider.custom(d.cognitoProviderName)),
      ],
      preventUserExistenceErrors: true,
      enableTokenRevocation: true,
      accessTokenValidity: Duration.minutes(config.tokens.accessTokenMinutes),
      idTokenValidity: Duration.minutes(config.tokens.idTokenMinutes),
      refreshTokenValidity: Duration.days(config.tokens.refreshTokenDays),
      authSessionValidity: Duration.minutes(config.tokens.authSessionMinutes),
      readAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ email: true, emailVerified: true })
        .withCustomAttributes(IDP_EMAIL_VERIFIED_ATTR),
      // email + custom:idp_email_verified only: Cognito drops IdP-mapped values for attributes
      // the client can't write. email_verified is never client-writable (§3.3).
      writeAttributes: new cognito.ClientAttributes()
        .withStandardAttributes({ email: true })
        .withCustomAttributes(IDP_EMAIL_VERIFIED_ATTR),
    });
    (this.client.node.defaultChild as cognito.CfnUserPoolClient).overrideLogicalId(USER_POOL_CLIENT_LOGICAL_ID);
    for (const idp of this.identityProviders) this.client.node.addDependency(idp);
    bindings.setEnv('COGNITO_APP_CLIENT_IDS', this.client.userPoolClientId);

    // --- WAF (§3.9, REQ-OPS-2)
    if (config.waf) {
      const acl = new wafv2.CfnWebACL(this, 'WebAcl', {
        name: `ourlore-${config.stage}-userpool`,
        scope: 'REGIONAL',
        defaultAction: { allow: {} },
        visibilityConfig: {
          cloudWatchMetricsEnabled: true,
          metricName: `ourlore-${config.stage}-userpool`,
          sampledRequestsEnabled: true,
        },
        rules: [
          {
            name: 'ip-rate-limit',
            priority: 0,
            action: { block: {} },
            statement: {
              rateBasedStatement: { limit: 300, evaluationWindowSec: 300, aggregateKeyType: 'IP' },
            },
            visibilityConfig: {
              cloudWatchMetricsEnabled: true,
              metricName: `ourlore-${config.stage}-userpool-ip-rate`,
              sampledRequestsEnabled: true,
            },
          },
        ],
      });
      new wafv2.CfnWebACLAssociation(this, 'WebAclAssociation', {
        resourceArn: this.userPool.userPoolArn,
        webAclArn: acl.attrArn,
      });
    }
  }
}
