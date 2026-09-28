/**
 * Data (auth_design.md §3.6, api_interface.md §12.2) and pinned stateful logical ids (D-8).
 */
import { Match } from 'aws-cdk-lib/assertions';
import { STAGES } from '../lib/config/stages';
import {
  CURSOR_KEY_PARAMETER_LOGICAL_ID,
  FREE_TIER_RCU,
  FREE_TIER_WCU,
  TABLE_SPECS,
  cursorKeyParameterName,
  tableLogicalId,
} from '../lib/constructs/data';
import { CONTRACT, SES_TEST_CONTEXT, resourcesOfType, synth } from './helpers';

/** Provisioned throughput as `[RCU, WCU]`. */
type Cap = [number, number];

/** Expected keys, GSIs, and capacity, written out independently of the implementation. */
const EXPECTED: Record<
  string,
  { keys: [string, string?]; cap: Cap; gsis: Record<string, { keys: [string, string]; projection: string; include?: string[]; cap: Cap }>; ttl?: string }
> = {
  Users: {
    keys: ['userId'],
    cap: [2, 2],
    gsis: { UsersByUsername: { keys: ['dirShard', 'usernameKey'], projection: 'INCLUDE', include: ['username', 'fullname', 'avatarKey'], cap: [1, 1] } },
  },
  Usernames: { keys: ['usernameLower'], cap: [1, 1], gsis: {} },
  Follows: { keys: ['followerId', 'followeeId'], cap: [1, 1], gsis: { FollowsByFollowee: { keys: ['followeeId', 'followerId'], projection: 'KEYS_ONLY', cap: [1, 1] } } },
  FollowRequests: {
    keys: ['targetId', 'requesterId'],
    cap: [1, 1],
    gsis: { FollowRequestsByRequester: { keys: ['requesterId', 'targetId'], projection: 'KEYS_ONLY', cap: [1, 1] } },
  },
  SignificantOtherRequests: {
    keys: ['targetId', 'requesterId'],
    cap: [1, 1],
    gsis: { SORequestsByRequester: { keys: ['requesterId', 'targetId'], projection: 'KEYS_ONLY', cap: [1, 1] } },
  },
  Posts: { keys: ['postId'], cap: [2, 1], gsis: { PostsByOwnerDate: { keys: ['ownerId', 'dateKey'], projection: 'ALL', cap: [1, 1] } } },
  Likes: { keys: ['postId', 'userId'], cap: [1, 1], gsis: { LikesByUser: { keys: ['userId', 'postId'], projection: 'KEYS_ONLY', cap: [1, 1] } } },
  Wishes: { keys: ['wishId'], cap: [1, 1], gsis: { WishesByOwnerTitle: { keys: ['ownerId', 'titleKey'], projection: 'ALL', cap: [1, 1] } } },
  Idempotency: { keys: ['idemKey'], cap: [1, 1], gsis: {}, ttl: 'expiresAtEpoch' },
  DeletionJobs: {
    keys: ['userId'],
    cap: [1, 1],
    gsis: {
      PendingDeletionJobs: { keys: ['pendingShard', 'requestedAt'], projection: 'INCLUDE', include: ['phase', 'updatedAt', 'leaseUntil'], cap: [1, 1] },
    },
    ttl: 'expiresAtEpoch',
  },
};

/** CloudFormation `ProvisionedThroughput` for a `[RCU, WCU]` pair. */
const throughput = ([read, write]: Cap) => ({ ReadCapacityUnits: read, WriteCapacityUnits: write });

describe('tables', () => {
  const { json, template } = synth();
  const entities = Object.values(CONTRACT.tables).map((t) => t.entity);

  test('one table per contract entity, each with a key schema, and nothing else', () => {
    expect(entities.sort()).toEqual(Object.keys(EXPECTED).sort());
    expect(Object.keys(TABLE_SPECS).sort()).toEqual(Object.keys(EXPECTED).sort());
    template.resourceCountIs('AWS::DynamoDB::Table', entities.length);
  });

  test.each(Object.keys(EXPECTED))('%s: name, pinned id, keys, GSIs, capacity, PITR, retain, no streams, TTL', (entity) => {
    const exp = EXPECTED[entity];
    const r = json.Resources[tableLogicalId(entity)];
    expect(r).toBeDefined();
    expect(r.Type).toBe('AWS::DynamoDB::Table');
    expect(r.DeletionPolicy).toBe('Retain');
    expect(r.UpdateReplacePolicy).toBe('Retain');
    const p = r.Properties!;
    expect(p.TableName).toBe(`ourlore-dev-${entity}`);
    // Provisioned billing: CloudFormation defaults to PROVISIONED, so CDK omits BillingMode
    // and instead emits ProvisionedThroughput (on-demand would set PAY_PER_REQUEST and no throughput).
    expect(p.BillingMode).toBeUndefined();
    expect(p.ProvisionedThroughput).toEqual(throughput(exp.cap));
    // PITR is prod-only (not free-tier eligible), so dev has it disabled.
    expect(p.PointInTimeRecoverySpecification).toEqual({ PointInTimeRecoveryEnabled: false });
    expect(p.StreamSpecification).toBeUndefined();
    expect(p.DeletionProtectionEnabled).toBe(false);
    const keySchema = [{ AttributeName: exp.keys[0], KeyType: 'HASH' }];
    if (exp.keys[1]) keySchema.push({ AttributeName: exp.keys[1], KeyType: 'RANGE' });
    expect(p.KeySchema).toEqual(keySchema);
    const gsis = Object.fromEntries((p.GlobalSecondaryIndexes ?? []).map((g: any) => [g.IndexName, g]));
    expect(Object.keys(gsis).sort()).toEqual(Object.keys(exp.gsis).sort());
    for (const [name, g] of Object.entries(exp.gsis)) {
      expect(gsis[name].KeySchema).toEqual([
        { AttributeName: g.keys[0], KeyType: 'HASH' },
        { AttributeName: g.keys[1], KeyType: 'RANGE' },
      ]);
      expect(gsis[name].Projection.ProjectionType).toBe(g.projection);
      if (g.include) expect([...gsis[name].Projection.NonKeyAttributes].sort()).toEqual([...g.include].sort());
      // Each GSI has its own provisioned slice, drawn from the same free-tier pool.
      expect(gsis[name].ProvisionedThroughput).toEqual(throughput(g.cap));
    }
    for (const a of p.AttributeDefinitions) expect(a.AttributeType).toBe('S');
    if (exp.ttl) expect(p.TimeToLiveSpecification).toEqual({ AttributeName: exp.ttl, Enabled: true });
    else expect(p.TimeToLiveSpecification).toBeUndefined();
  });

  test('prod tables have deletion protection and PITR', () => {
    const prod = synth(STAGES.prod, {}, SES_TEST_CONTEXT).json;
    for (const [, t] of resourcesOfType(prod, 'AWS::DynamoDB::Table')) {
      expect(t.Properties!.DeletionProtectionEnabled).toBe(true);
      expect(t.Properties!.TableName).toMatch(/^ourlore-prod-/);
      expect(t.Properties!.BillingMode).toBeUndefined();
      expect(t.Properties!.ProvisionedThroughput).toBeDefined();
      expect(t.Properties!.PointInTimeRecoverySpecification).toEqual({ PointInTimeRecoveryEnabled: true });
    }
  });

  test.each([
    ['dev', STAGES.dev, {}],
    ['prod', STAGES.prod, SES_TEST_CONTEXT],
  ])('%s: total provisioned capacity (tables + GSIs) fits the DynamoDB free tier', (_l, cfg, ctx) => {
    let rcu = 0;
    let wcu = 0;
    for (const [, t] of resourcesOfType(synth(cfg, {}, ctx).json, 'AWS::DynamoDB::Table')) {
      const p = t.Properties!;
      // On-demand anywhere would bill per request, so it must not appear.
      expect(p.BillingMode).toBeUndefined();
      for (const pt of [p.ProvisionedThroughput, ...(p.GlobalSecondaryIndexes ?? []).map((g: any) => g.ProvisionedThroughput)]) {
        rcu += pt.ReadCapacityUnits;
        wcu += pt.WriteCapacityUnits;
      }
    }
    expect([rcu, wcu]).toEqual([20, 19]);
    expect(rcu).toBeLessThanOrEqual(FREE_TIER_RCU);
    expect(wcu).toBeLessThanOrEqual(FREE_TIER_WCU);
  });
});

describe('media bucket', () => {
  const { json, template } = synth();

  test('private, SSE-S3, no versioning, lifecycle, RETAIN, pinned id', () => {
    const r = json.Resources.MediaBucket;
    expect(r.Type).toBe('AWS::S3::Bucket');
    expect(r.DeletionPolicy).toBe('Retain');
    const p = r.Properties!;
    expect(p.BucketName).toBeUndefined();
    expect(p.PublicAccessBlockConfiguration).toEqual({
      BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true,
    });
    expect(p.BucketEncryption).toEqual({ ServerSideEncryptionConfiguration: [{ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] });
    expect(p.VersioningConfiguration).toBeUndefined();
    expect(p.OwnershipControls).toEqual({ Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] });
    expect(p.LifecycleConfiguration.Rules).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ Prefix: 'pending/', ExpirationInDays: 1, Status: 'Enabled' }),
        expect.objectContaining({ AbortIncompleteMultipartUpload: { DaysAfterInitiation: 1 }, Status: 'Enabled' }),
      ]),
    );
  });

  test('enforces TLS', () => {
    template.hasResourceProperties('AWS::S3::BucketPolicy', {
      Bucket: { Ref: 'MediaBucket' },
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({ Effect: 'Deny', Condition: { Bool: { 'aws:SecureTransport': 'false' } } }),
        ]),
      },
    });
  });
});

describe('cursor-signing key (operator-created SSM SecureString)', () => {
  test.each([
    ['dev', STAGES.dev, {}],
    ['prod', STAGES.prod, SES_TEST_CONTEXT],
  ])('%s: deploy-time existence check pinned to the stage name', (stage, cfg, ctx) => {
    const { json } = synth(cfg, {}, ctx);
    const name = `/ourlore/${stage}/cursor-key`;
    expect(cursorKeyParameterName(stage)).toBe(name);
    expect(json.Parameters?.[CURSOR_KEY_PARAMETER_LOGICAL_ID]).toMatchObject({
      Type: 'AWS::SSM::Parameter::Name',
      Default: name,
      AllowedValues: [name],
    });
  });

  test('is referenced only: the stack creates no parameter, secret, or key material', () => {
    const { json } = synth();
    for (const type of ['AWS::SSM::Parameter', 'AWS::SecretsManager::Secret', 'AWS::KMS::Key']) {
      expect(resourcesOfType(json, type)).toHaveLength(0);
    }
    // The only way the key reaches a function is the parameter name in CURSOR_KEY_PARAM.
    expect(JSON.stringify(json)).not.toMatch(/ssm-secure|GenerateSecretString/);
  });

  test('every paginating function receives the checked name', () => {
    const { json } = synth();
    const holders = resourcesOfType(json, 'AWS::Lambda::Function')
      .filter(([, f]) => f.Properties!.Environment.Variables.CURSOR_KEY_PARAM !== undefined)
      .map(([, f]) => f.Properties!.Environment.Variables.CURSOR_KEY_PARAM);
    expect(holders).toHaveLength(4);
    for (const v of holders) expect(v).toEqual({ Ref: CURSOR_KEY_PARAMETER_LOGICAL_ID });
  });
});

describe('pinned stateful logical ids (D-8)', () => {
  test.each([
    ['UserPool', 'AWS::Cognito::UserPool'],
    ['UserPoolClientIos', 'AWS::Cognito::UserPoolClient'],
    ['UserPoolDomain', 'AWS::Cognito::UserPoolDomain'],
    ['MediaBucket', 'AWS::S3::Bucket'],
    ['AccountPurgeQueue', 'AWS::SQS::Queue'],
    ['AccountPurgeDlq', 'AWS::SQS::Queue'],
    ...Object.keys(EXPECTED).map((e) => [`Table${e}`, 'AWS::DynamoDB::Table']),
  ])('%s is a %s', (id, type) => {
    const { json } = synth();
    expect(json.Resources[id]?.Type).toBe(type);
  });
});
