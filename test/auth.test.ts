/**
 * Identity (auth_design.md §3.2–§3.5, §3.9 WAF, §3.11).
 */
import { Match } from 'aws-cdk-lib/assertions';
import { IDENTITY_PROVIDERS, IdpDefinition, renderIdpRegistry, validateRegistry } from '../lib/config/identity-providers';
import { STAGES } from '../lib/config/stages';
import { CONTRACT, CfnResource, FIXTURE_SECRET_NAMES, SES_TEST_CONTEXT, functionByHandler, policiesOfRole, resourcesOfType, roleOf, synth, withIdps } from './helpers';

const TRIGGER_HANDLER = CONTRACT.cognito_triggers.pre_sign_up.handler;
const POST_CONFIRMATION_HANDLER = CONTRACT.cognito_triggers.post_confirmation.handler;

describe('user pool (§3.2)', () => {
  const { template, json } = synth();

  test('sign-in, verification, attributes, and plan', () => {
    template.resourceCountIs('AWS::Cognito::UserPool', 1);
    template.hasResourceProperties('AWS::Cognito::UserPool', {
      AdminCreateUserConfig: { AllowAdminCreateUserOnly: false },
      UsernameAttributes: ['email'],
      AliasAttributes: Match.absent(),
      UsernameConfiguration: { CaseSensitive: false },
      AutoVerifiedAttributes: ['email'],
      UserAttributeUpdateSettings: { AttributesRequireVerificationBeforeUpdate: ['email'] },
      UserPoolTier: 'ESSENTIALS',
      MfaConfiguration: 'OFF',
      DeviceConfiguration: Match.absent(),
      AccountRecoverySetting: { RecoveryMechanisms: [{ Name: 'verified_email', Priority: 1 }] },
      UserPoolTags: { 'ourlore:stage': 'dev' },
      VerificationMessageTemplate: Match.objectLike({
        DefaultEmailOption: 'CONFIRM_WITH_CODE',
        EmailSubject: Match.stringLikeRegexp('Ourlore'),
        EmailMessage: Match.stringLikeRegexp('\\{####\\}'),
      }),
      EmailConfiguration: { EmailSendingAccount: 'COGNITO_DEFAULT' },
    });
  });

  test('schema: required mutable email and one custom attribute (mutable, max 8)', () => {
    const pool = resourcesOfType(json, 'AWS::Cognito::UserPool')[0][1];
    expect(pool.Properties!.Schema).toEqual([
      { Name: 'email', Required: true, Mutable: true },
      { Name: 'idp_email_verified', AttributeDataType: 'String', Mutable: true, StringAttributeConstraints: { MaxLength: '8' } },
    ]);
  });

  test('password policy (REQ-PW-2)', () => {
    template.hasResourceProperties('AWS::Cognito::UserPool', {
      Policies: {
        PasswordPolicy: {
          MinimumLength: 8,
          RequireLowercase: true,
          RequireUppercase: true,
          RequireNumbers: true,
          RequireSymbols: true,
          TemporaryPasswordValidityDays: 3,
          PasswordHistorySize: 5,
        },
      },
    });
  });

  test('deletion protection and RETAIN (REQ-OPS-3)', () => {
    template.hasResource('AWS::Cognito::UserPool', {
      Properties: Match.objectLike({ DeletionProtection: 'ACTIVE' }),
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
    });
  });

  test('pre-sign-up and post-confirmation triggers are wired (and nothing else)', () => {
    const [fnId] = functionByHandler(json, TRIGGER_HANDLER);
    const [postId] = functionByHandler(json, POST_CONFIRMATION_HANDLER);
    const pool = resourcesOfType(json, 'AWS::Cognito::UserPool')[0][1];
    expect(pool.Properties!.LambdaConfig).toEqual({
      PreSignUp: { 'Fn::GetAtt': [fnId, 'Arn'] },
      PostConfirmation: { 'Fn::GetAtt': [postId, 'Arn'] },
    });
    expect(template).toBeTruthy();
  });

});

describe('email delivery (REQ-PW-7)', () => {
  /** SES identity ARN as CDK renders it: region/account/partition tokens, never literals. */
  const identityArn = (region: string | { Ref: string }) => ({
    'Fn::Join': [
      '',
      typeof region === 'string'
        ? ['arn:', { Ref: 'AWS::Partition' }, `:ses:${region}:`, { Ref: 'AWS::AccountId' }, ':identity/example.com']
        : ['arn:', { Ref: 'AWS::Partition' }, ':ses:', region, ':', { Ref: 'AWS::AccountId' }, ':identity/example.com'],
    ],
  });

  test('dev uses the Cognito default sender', () => {
    synth().template.hasResourceProperties('AWS::Cognito::UserPool', {
      EmailConfiguration: { EmailSendingAccount: 'COGNITO_DEFAULT' },
    });
  });

  test('dev ignores SES context', () => {
    synth(STAGES.dev, {}, SES_TEST_CONTEXT).template.hasResourceProperties('AWS::Cognito::UserPool', {
      EmailConfiguration: { EmailSendingAccount: 'COGNITO_DEFAULT' },
    });
  });

  test('prod without SES context fails synth with a clear error', () => {
    expect(() => synth(STAGES.prod)).toThrow(/Stage 'prod' must send Cognito email through SES \(REQ-PW-7\).*-c sesFromEmail=.*-c sesVerifiedDomain=/);
    expect(() => synth(STAGES.prod, {}, { sesFromEmail: 'no-reply@example.com' })).toThrow(/REQ-PW-7/);
    expect(() => synth(STAGES.prod, {}, { sesVerifiedDomain: 'example.com' })).toThrow(/REQ-PW-7/);
    expect(() => synth(STAGES.prod, {}, { sesFromEmail: ' ', sesVerifiedDomain: 'example.com' })).toThrow(/REQ-PW-7/);
  });

  test('prod with SES context: DEVELOPER account, From, and the identity SourceArn in the stack region', () => {
    const { template, json } = synth(STAGES.prod, {}, SES_TEST_CONTEXT);
    const [, pool] = resourcesOfType(json, 'AWS::Cognito::UserPool')[0];
    expect(pool.Properties!.EmailConfiguration).toEqual({
      EmailSendingAccount: 'DEVELOPER',
      From: 'Ourlore <no-reply@example.com>',
      SourceArn: identityArn({ Ref: 'AWS::Region' }),
    });
    template.resourceCountIs('AWS::Cognito::UserPool', 1);
  });

  test('prod with -c sesRegion uses that region in the SourceArn', () => {
    const { json } = synth(STAGES.prod, {}, { ...SES_TEST_CONTEXT, sesRegion: 'eu-west-1' });
    const [, pool] = resourcesOfType(json, 'AWS::Cognito::UserPool')[0];
    expect(pool.Properties!.EmailConfiguration).toEqual({
      EmailSendingAccount: 'DEVELOPER',
      From: 'Ourlore <no-reply@example.com>',
      SourceArn: identityArn('eu-west-1'),
    });
  });

  test.each([
    ['not an email', { sesFromEmail: 'no-reply', sesVerifiedDomain: 'example.com' }, /not a valid email address/],
    ['bad local part', { sesFromEmail: 'a b@example.com', sesVerifiedDomain: 'example.com' }, /not a valid email address/],
    ['bad domain', { sesFromEmail: 'no-reply@example.com', sesVerifiedDomain: 'example' }, /not a valid domain/],
    ['domain mismatch', { sesFromEmail: 'no-reply@example.org', sesVerifiedDomain: 'example.com' }, /must be on the verified domain/],
    ['look-alike suffix', { sesFromEmail: 'no-reply@evilexample.com', sesVerifiedDomain: 'example.com' }, /must be on the verified domain/],
    ['subdomain sender', { sesFromEmail: 'no-reply@mail.example.com', sesVerifiedDomain: 'example.com' }, /must be on the verified domain/],
    ['bad region', { ...SES_TEST_CONTEXT, sesRegion: 'mars-1' }, /not an AWS region name/],
  ])('prod rejects invalid SES context: %s', (_label, context, error) => {
    expect(() => synth(STAGES.prod, {}, context)).toThrow(error);
  });

  test('domain comparison is case-insensitive and normalized', () => {
    const { json } = synth(STAGES.prod, {}, { sesFromEmail: 'No-Reply@Example.COM', sesVerifiedDomain: 'EXAMPLE.com' });
    const [, pool] = resourcesOfType(json, 'AWS::Cognito::UserPool')[0];
    expect(pool.Properties!.EmailConfiguration.From).toBe('Ourlore <No-Reply@example.com>');
    expect(JSON.stringify(pool.Properties!.EmailConfiguration.SourceArn)).toContain(':identity/example.com');
  });
});

describe('domain and app client (§3.3)', () => {
  const { template } = synth();

  test('prefix domain, classic hosted UI', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolDomain', {
      Domain: 'ourlore-dev-auth',
      ManagedLoginVersion: 1,
      CustomDomainConfig: Match.absent(),
    });
  });

  test('public client with SRP only and refresh-token rotation (REQ-ID-5/6)', () => {
    template.resourceCountIs('AWS::Cognito::UserPoolClient', 1);
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      ClientName: 'ios',
      GenerateSecret: false,
      ExplicitAuthFlows: ['ALLOW_USER_SRP_AUTH'],
      RefreshTokenRotation: { Feature: 'ENABLED', RetryGracePeriodSeconds: 10 },
    });
  });

  test('OAuth: code grant only, scopes, redirect URLs', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      AllowedOAuthFlowsUserPoolClient: true,
      AllowedOAuthFlows: ['code'],
      AllowedOAuthScopes: ['openid', 'email', 'aws.cognito.signin.user.admin'],
      CallbackURLs: ['ourlore://auth/callback/'],
      LogoutURLs: ['ourlore://auth/signout/'],
    });
  });

  test('token validity values and units (REQ-ID-4)', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      AccessTokenValidity: 15,
      IdTokenValidity: 15,
      RefreshTokenValidity: 525_600, // 365 days in minutes
      TokenValidityUnits: { AccessToken: 'minutes', IdToken: 'minutes', RefreshToken: 'minutes' },
      AuthSessionValidity: 3,
    });
  });

  test('revocation and user-existence errors (REQ-ID-5/7)', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      EnableTokenRevocation: true,
      PreventUserExistenceErrors: 'ENABLED',
    });
  });

  test('attribute permissions: email_verified is readable but never writable', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      ReadAttributes: ['custom:idp_email_verified', 'email', 'email_verified'],
      WriteAttributes: ['custom:idp_email_verified', 'email'],
    });
  });
});

describe('identity providers (§3.4)', () => {
  test('registry: claim providers name their claim; Apple always, Google claim', () => {
    expect(() => validateRegistry(IDENTITY_PROVIDERS)).not.toThrow();
    expect(IDENTITY_PROVIDERS.apple.emailVerified).toBe('always');
    expect(IDENTITY_PROVIDERS.google.emailVerified).toBe('claim');
    for (const def of Object.values(IDENTITY_PROVIDERS)) {
      if (def.emailVerified === 'claim') expect(def.attributeMapping.emailVerifiedClaim).toBeTruthy();
    }
    const bad: IdpDefinition = { ...IDENTITY_PROVIDERS.google, attributeMapping: { email: 'email' } };
    expect(() => validateRegistry({ google: bad })).toThrow(/emailVerifiedClaim/);
  });

  test('disabled: no IdP resources, COGNITO only, empty registry', () => {
    const { template, json } = synth();
    template.resourceCountIs('AWS::Cognito::UserPoolIdentityProvider', 0);
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', { SupportedIdentityProviders: ['COGNITO'] });
    const [, fn] = functionByHandler(json, TRIGGER_HANDLER);
    expect(fn.Properties!.Environment.Variables.IDP_REGISTRY).toBe('{}');
    expect(json.Outputs.EnabledIdps.Value).toBe('[]');
  });

  describe('enabled (apple + google, fixture secrets)', () => {
    const { template, json } = synth(withIdps());
    const idps = resourcesOfType(json, 'AWS::Cognito::UserPoolIdentityProvider');
    const byName: Record<string, { id: string; r: CfnResource }> = Object.fromEntries(idps.map(([id, r]) => [r.Properties!.ProviderName, { id, r }]));

    test('both providers exist with the right types, scopes, and mappings', () => {
      expect(Object.keys(byName).sort()).toEqual(['Google', 'SignInWithApple']);
      const apple = byName.SignInWithApple.r.Properties!;
      const google = byName.Google.r.Properties!;
      expect(apple.ProviderType).toBe('SignInWithApple');
      expect(apple.AttributeMapping).toEqual({ email: 'email' });
      expect(apple.ProviderDetails.authorize_scopes).toBe('email');
      expect(google.ProviderType).toBe('Google');
      expect(google.AttributeMapping).toEqual({ email: 'email', 'custom:idp_email_verified': 'email_verified' });
      expect(google.ProviderDetails.authorize_scopes).toBe('openid email');
    });

    test('every credential is a Secrets Manager dynamic reference', () => {
      const apple = byName.SignInWithApple.r.Properties!.ProviderDetails;
      const google = byName.Google.r.Properties!.ProviderDetails;
      const ref = (name: string, field: string): string => `{{resolve:secretsmanager:${name}:SecretString:${field}::}}`;
      expect(apple.client_id).toBe(ref(FIXTURE_SECRET_NAMES.apple, 'servicesId'));
      expect(apple.team_id).toBe(ref(FIXTURE_SECRET_NAMES.apple, 'teamId'));
      expect(apple.key_id).toBe(ref(FIXTURE_SECRET_NAMES.apple, 'keyId'));
      expect(apple.private_key).toBe(ref(FIXTURE_SECRET_NAMES.apple, 'privateKey'));
      expect(google.client_id).toBe(ref(FIXTURE_SECRET_NAMES.google, 'clientId'));
      expect(google.client_secret).toBe(ref(FIXTURE_SECRET_NAMES.google, 'clientSecret'));
    });

    test('no plaintext secret anywhere in the template (REQ-FED-8)', () => {
      const text = JSON.stringify(json);
      for (const s of ['BEGIN PRIVATE KEY', 'fixture-private-key', 'fixture-client-secret', 'GOCSPX-']) {
        expect(text).not.toContain(s);
      }
      // Every occurrence of a fixture secret name is a dynamic reference or a secret ARN.
      const hits = [...text.matchAll(/(.{0,26})fixture\/idp\/(apple|google)([^"]*)/g)];
      expect(hits.length).toBeGreaterThan(0);
      for (const [, before, , after] of hits) {
        const isRef = before.endsWith('{{resolve:secretsmanager:') && /^:SecretString:[A-Za-z]+::\}\}$/.test(after);
        const isArn = before.endsWith(':secret:') && (after === '' || after === '-??????');
        expect({ before, after, ok: isRef || isArn }).toMatchObject({ ok: true });
      }
    });

    test('client supports the providers and depends on them', () => {
      template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
        SupportedIdentityProviders: ['COGNITO', 'SignInWithApple', 'Google'],
      });
      const [, client] = resourcesOfType(json, 'AWS::Cognito::UserPoolClient')[0];
      for (const { id } of Object.values(byName)) expect(client.DependsOn).toContain(id);
    });

    test('IDP_REGISTRY env and EnabledIdps output', () => {
      const expected = renderIdpRegistry([IDENTITY_PROVIDERS.apple, IDENTITY_PROVIDERS.google]);
      expect(JSON.parse(expected)).toEqual({
        google: { id: 'google', emailVerified: 'claim' },
        signinwithapple: { id: 'apple', emailVerified: 'always' },
      });
      for (const f of ['pre_sign_up']) {
        const [, fn] = functionByHandler(json, CONTRACT.cognito_triggers[f].handler);
        expect(fn.Properties!.Environment.Variables.IDP_REGISTRY).toBe(expected);
      }
      for (const g of ['users', 'account']) {
        const [, fn] = functionByHandler(json, CONTRACT.resource_groups[g].handler);
        expect(fn.Properties!.Environment.Variables.IDP_REGISTRY).toBe(expected);
      }
      expect(json.Outputs.EnabledIdps.Value).toBe('["apple","google"]');
    });
  });

  test('unknown IdP id fails synth', () => {
    const cfg = { ...STAGES.dev, enabledIdps: ['facebook' as never] };
    expect(() => synth(cfg)).toThrow(/unknown IdP 'facebook'/);
  });
});

describe('pre-sign-up trigger (§3.5)', () => {
  const { json } = synth();
  const [fnId, fn] = functionByHandler(json, TRIGGER_HANDLER);
  const roleId = roleOf(fn);
  const policies = policiesOfRole(json, roleId);
  const standalone = policies.filter(([, p]) =>
    JSON.stringify(p.Properties!.PolicyDocument).includes('cognito-idp:'),
  );

  test('runtime settings and env: no COGNITO_USER_POOL_ID', () => {
    expect(fn.Properties!.Timeout).toBe(5);
    expect(fn.Properties!.MemorySize).toBe(256);
    expect(Object.keys(fn.Properties!.Environment.Variables).sort()).toEqual([...CONTRACT.cognito_triggers.pre_sign_up.env].sort());
    expect(fn.Properties!.Environment.Variables.COGNITO_USER_POOL_ID).toBeUndefined();
  });

  test('standalone policy grants ListUsers on the exact pool ARN only', () => {
    expect(standalone).toHaveLength(1);
    const [, policy] = standalone[0];
    expect(policy.Properties!.PolicyDocument.Statement).toEqual([
      { Action: 'cognito-idp:ListUsers', Effect: 'Allow', Resource: { 'Fn::GetAtt': ['UserPool', 'Arn'] } },
    ]);
  });

  test('the function does not depend on the standalone policy (no cycle)', () => {
    const [policyId] = standalone[0];
    expect(fn.DependsOn ?? []).not.toContain(policyId);
    // And the default policy (which the function does depend on) never references the pool.
    for (const dep of fn.DependsOn ?? []) {
      const r = json.Resources[dep];
      if (r.Type === 'AWS::IAM::Policy') expect(JSON.stringify(r)).not.toContain('UserPool');
    }
    expect(fnId).toBeTruthy();
  });

  test('Cognito may invoke the trigger', () => {
    const perms = resourcesOfType(json, 'AWS::Lambda::Permission').filter(
      ([, p]) =>
        p.Properties!.Principal === 'cognito-idp.amazonaws.com' &&
        JSON.stringify(p.Properties!.FunctionName) === JSON.stringify({ 'Fn::GetAtt': [fnId, 'Arn'] }),
    );
    expect(perms).toHaveLength(1);
    expect(perms[0][1].Properties!.SourceArn).toEqual({ 'Fn::GetAtt': ['UserPool', 'Arn'] });
  });
});

describe('post-confirmation trigger (security finding F-1)', () => {
  const { json, stack } = synth();
  const [fnId, fn] = functionByHandler(json, POST_CONFIRMATION_HANDLER);
  const policies = policiesOfRole(json, roleOf(fn));
  const standalone = policies.filter(([, p]) =>
    JSON.stringify(p.Properties!.PolicyDocument).includes('cognito-idp:'),
  );

  test('runtime settings, X-Ray, log group with retention; env is Powertools only', () => {
    expect(fn.Properties!.Timeout).toBe(5);
    expect(fn.Properties!.MemorySize).toBe(256);
    expect(fn.Properties!.TracingConfig).toEqual({ Mode: 'Active' });
    expect(Object.keys(fn.Properties!.Environment.Variables).sort()).toEqual(
      ['POWERTOOLS_LOG_LEVEL', 'POWERTOOLS_SERVICE_NAME'],
    );
    expect(fn.Properties!.Environment.Variables.POWERTOOLS_SERVICE_NAME).toBe('ourlore-post-confirmation');
    const logGroupId = fn.Properties!.LoggingConfig.LogGroup.Ref;
    expect(json.Resources[logGroupId].Type).toBe('AWS::Logs::LogGroup');
    expect(json.Resources[logGroupId].Properties!.RetentionInDays).toEqual(expect.any(Number));
  });

  test('standalone policy grants exactly AdminUserGlobalSignOut on the exact pool ARN', () => {
    expect(standalone).toHaveLength(1);
    const [, policy] = standalone[0];
    expect(policy.Properties!.PolicyDocument.Statement).toEqual([
      { Action: 'cognito-idp:AdminUserGlobalSignOut', Effect: 'Allow', Resource: { 'Fn::GetAtt': ['UserPool', 'Arn'] } },
    ]);
  });

  test('the policy is constructed outside the function and role subtrees', () => {
    const post = stack.auth.postConfirmation;
    const policy = post.standalonePolicy!;
    expect(policy).toBeDefined();
    expect(policy.node.scope).toBe(stack.auth);
    expect(policy.node.path.startsWith(`${post.role.node.path}/`)).toBe(false);
    expect(policy.node.path.startsWith(`${post.function.node.path}/`)).toBe(false);
    expect(policy.node.path.startsWith(`${post.node.path}/`)).toBe(false);
  });

  test('the function does not depend on the standalone policy (no cycle)', () => {
    const [policyId] = standalone[0];
    expect(fn.DependsOn ?? []).not.toContain(policyId);
    for (const dep of fn.DependsOn ?? []) {
      const r = json.Resources[dep];
      if (r.Type === 'AWS::IAM::Policy') expect(JSON.stringify(r)).not.toContain('UserPool');
    }
  });

  test('Cognito may invoke it, from this pool only', () => {
    const perms = resourcesOfType(json, 'AWS::Lambda::Permission').filter(
      ([, p]) =>
        p.Properties!.Principal === 'cognito-idp.amazonaws.com' &&
        JSON.stringify(p.Properties!.FunctionName) === JSON.stringify({ 'Fn::GetAtt': [fnId, 'Arn'] }),
    );
    expect(perms).toHaveLength(1);
    expect(perms[0][1].Properties!.SourceArn).toEqual({ 'Fn::GetAtt': ['UserPool', 'Arn'] });
  });

  test('output names the function for the E2E wiring check', () => {
    expect(json.Outputs.PostConfirmationFunctionArn.Value).toEqual({ 'Fn::GetAtt': [fnId, 'Arn'] });
  });
});

describe('WAF (§3.9, REQ-OPS-2)', () => {
  test('off in dev', () => {
    const { template } = synth();
    template.resourceCountIs('AWS::WAFv2::WebACL', 0);
    template.resourceCountIs('AWS::WAFv2::WebACLAssociation', 0);
  });

  test('prod: regional ACL with a 300/5 min IP rate rule on the user pool', () => {
    const { template, json } = synth(STAGES.prod, {}, SES_TEST_CONTEXT);
    template.hasResourceProperties('AWS::WAFv2::WebACL', {
      Scope: 'REGIONAL',
      DefaultAction: { Allow: {} },
      Rules: [
        Match.objectLike({
          Action: { Block: {} },
          Statement: { RateBasedStatement: { Limit: 300, EvaluationWindowSec: 300, AggregateKeyType: 'IP' } },
        }),
      ],
    });
    const [aclId] = resourcesOfType(json, 'AWS::WAFv2::WebACL')[0];
    template.hasResourceProperties('AWS::WAFv2::WebACLAssociation', {
      ResourceArn: { 'Fn::GetAtt': ['UserPool', 'Arn'] },
      WebACLArn: { 'Fn::GetAtt': [aclId, 'Arn'] },
    });
  });
});
