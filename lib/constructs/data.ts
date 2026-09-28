/**
 * Stateful data resources (auth_design.md §3.6, api_interface.md §12.2).
 *
 * - One DynamoDB table per entity, named `ourlore-<stage>-<Entity>`: provisioned capacity,
 *   `RETAIN`, deletion protection in prod, no streams (enabled when a consumer ships).
 * - Private media bucket (versioning off, D-10) with the `pending/` and multipart lifecycle.
 * - A reference to the operator-created cursor-signing key (below).
 *
 * Free tier: DynamoDB's always-free allowance is 25 provisioned RCU + 25 provisioned WCU and
 * 25 GB storage per region per account — and it applies to *provisioned* capacity only
 * (on-demand bills per request from the first one). That 25/25 is a single pool shared by
 * every table *and every GSI* in the region, so each entity gets a hand-tuned slice in
 * `TABLE_SPECS` below; tests assert one stage's total fits. Because the pool is per region,
 * only one stage fits: deploying dev and prod to the same account and region exceeds it.
 * No autoscaling: a fixed ceiling cannot scale past the free tier. Raise a slice (or move a
 * table to on-demand) when real traffic warrants, mindful of the shared pool.
 *
 * PITR is not free-tier eligible, so it is enabled only in prod.
 *
 * Cursor-signing key: an SSM Parameter Store `SecureString` at `/ourlore/<stage>/cursor-key`
 * (standard tier, AWS-managed `aws/ssm` key: free; Secrets Manager would be $0.40/month).
 * CloudFormation cannot create `SecureString`s, so the operator creates it once per stage:
 *
 *     aws ssm put-parameter --name /ourlore/<stage>/cursor-key --type SecureString \
 *       --value "$(openssl rand -base64 48)"
 *
 * The stack only references it. A template parameter of type `AWS::SSM::Parameter::Name`
 * makes CloudFormation reject the deploy if the parameter does not exist, instead of cursor
 * routes failing at runtime. Its value is pinned to the stage's name. The key never enters
 * the template; functions read it at runtime (`app.lib.cursor_key`).
 *
 * Logical ids of every stateful resource are pinned (D-8) so refactors of the construct tree
 * never replace data. Tests assert them.
 */
import { CfnParameter, Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import type { Contract } from '../contract';
import type { StageConfig } from '../config/stages';

/** A key attribute; every key in this model is a string. */
type Key = string;

/** Provisioned throughput slice (free tier is a shared 25 RCU / 25 WCU pool per region). */
export interface Capacity {
  readonly read: number;
  readonly write: number;
}

interface GsiSpec {
  readonly name: string;
  readonly pk: Key;
  readonly sk?: Key;
  readonly projection: dynamodb.ProjectionType;
  readonly include?: readonly string[];
  readonly capacity: Capacity;
}

interface TableSpec {
  readonly pk: Key;
  readonly sk?: Key;
  readonly capacity: Capacity;
  readonly gsis: readonly GsiSpec[];
  readonly ttl?: string;
}

/** Smallest provisioned slice; most tables and GSIs need no more at beta traffic. */
const MIN: Capacity = { read: 1, write: 1 };

/**
 * Key schema and provisioned throughput per contract entity (api_interface.md §12.2 plus the
 * auth_design.md §3.6 additions).
 *
 * Capacity is deliberately tiny for the beta. The sum across every table and GSI must stay
 * within the free-tier pool (`FREE_TIER_*`); `data.test.ts` asserts it. The hottest read paths
 * (Users on nearly every request, Posts timelines) get one extra RCU, and Users one extra WCU
 * for the counter updates in most social transactions.
 */
export const TABLE_SPECS: Readonly<Record<string, TableSpec>> = {
  Users: {
    pk: 'userId',
    capacity: { read: 2, write: 2 },
    gsis: [
      {
        name: 'UsersByUsername',
        pk: 'dirShard',
        sk: 'usernameKey',
        projection: dynamodb.ProjectionType.INCLUDE,
        include: ['username', 'fullname', 'avatarKey'],
        capacity: MIN,
      },
    ],
  },
  Usernames: { pk: 'usernameLower', capacity: MIN, gsis: [] },
  Follows: {
    pk: 'followerId',
    sk: 'followeeId',
    capacity: MIN,
    gsis: [
      { name: 'FollowsByFollowee', pk: 'followeeId', sk: 'followerId', projection: dynamodb.ProjectionType.KEYS_ONLY, capacity: MIN },
    ],
  },
  FollowRequests: {
    pk: 'targetId',
    sk: 'requesterId',
    capacity: MIN,
    gsis: [
      { name: 'FollowRequestsByRequester', pk: 'requesterId', sk: 'targetId', projection: dynamodb.ProjectionType.KEYS_ONLY, capacity: MIN },
    ],
  },
  SignificantOtherRequests: {
    pk: 'targetId',
    sk: 'requesterId',
    capacity: MIN,
    gsis: [
      { name: 'SORequestsByRequester', pk: 'requesterId', sk: 'targetId', projection: dynamodb.ProjectionType.KEYS_ONLY, capacity: MIN },
    ],
  },
  Posts: {
    pk: 'postId',
    capacity: { read: 2, write: 1 },
    gsis: [{ name: 'PostsByOwnerDate', pk: 'ownerId', sk: 'dateKey', projection: dynamodb.ProjectionType.ALL, capacity: MIN }],
  },
  Likes: {
    pk: 'postId',
    sk: 'userId',
    capacity: MIN,
    gsis: [{ name: 'LikesByUser', pk: 'userId', sk: 'postId', projection: dynamodb.ProjectionType.KEYS_ONLY, capacity: MIN }],
  },
  Wishes: {
    pk: 'wishId',
    capacity: MIN,
    gsis: [{ name: 'WishesByOwnerTitle', pk: 'ownerId', sk: 'titleKey', projection: dynamodb.ProjectionType.ALL, capacity: MIN }],
  },
  Idempotency: { pk: 'idemKey', capacity: MIN, gsis: [], ttl: 'expiresAtEpoch' },
  DeletionJobs: {
    pk: 'userId',
    capacity: MIN,
    gsis: [
      {
        // Sparse: `pendingShard` exists only until the job completes.
        name: 'PendingDeletionJobs',
        pk: 'pendingShard',
        sk: 'requestedAt',
        projection: dynamodb.ProjectionType.INCLUDE,
        include: ['phase', 'updatedAt', 'leaseUntil'],
        capacity: MIN,
      },
    ],
    ttl: 'expiresAtEpoch',
  },
};

/** DynamoDB always-free provisioned allowance, per region per payer account. */
export const FREE_TIER_RCU = 25;
export const FREE_TIER_WCU = 25;

/** Pinned logical id of an entity's table. */
export function tableLogicalId(entity: string): string {
  return `Table${entity}`;
}

export const MEDIA_BUCKET_LOGICAL_ID = 'MediaBucket';
/** Logical id of the template parameter that checks the cursor key exists at deploy time. */
export const CURSOR_KEY_PARAMETER_LOGICAL_ID = 'CursorKeyParameterName';

/** SSM name of a stage's operator-created cursor-signing key. */
export function cursorKeyParameterName(stage: string): string {
  return `/ourlore/${stage}/cursor-key`;
}

export interface DataProps {
  readonly config: StageConfig;
  readonly contract: Contract;
}

/** Tables, media bucket, and the cursor-signing key reference. */
export class Data extends Construct {
  /** Tables by contract logical name (e.g. `deletion_jobs`). */
  readonly tables: Readonly<Record<string, dynamodb.Table>>;
  readonly mediaBucket: s3.Bucket;
  /** The operator-created cursor-signing key (referenced, never created or read at deploy). */
  readonly cursorKey: ssm.IStringParameter;

  constructor(scope: Construct, id: string, props: DataProps) {
    super(scope, id);
    const { config, contract } = props;
    const prod = config.stage === 'prod';

    const tables: Record<string, dynamodb.Table> = {};
    for (const [logical, entry] of Object.entries(contract.tables)) {
      const spec = TABLE_SPECS[entry.entity];
      if (!spec) throw new Error(`No key schema for contract table '${logical}' (entity ${entry.entity}).`);
      const table = new dynamodb.Table(this, entry.entity, {
        tableName: `ourlore-${config.stage}-${entry.entity}`,
        partitionKey: { name: spec.pk, type: dynamodb.AttributeType.STRING },
        sortKey: spec.sk ? { name: spec.sk, type: dynamodb.AttributeType.STRING } : undefined,
        billingMode: dynamodb.BillingMode.PROVISIONED,
        readCapacity: spec.capacity.read,
        writeCapacity: spec.capacity.write,
        // PITR is not free-tier eligible; enable it only in prod.
        pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: prod },
        removalPolicy: RemovalPolicy.RETAIN,
        deletionProtection: prod,
        timeToLiveAttribute: spec.ttl,
      });
      for (const g of spec.gsis) {
        table.addGlobalSecondaryIndex({
          indexName: g.name,
          partitionKey: { name: g.pk, type: dynamodb.AttributeType.STRING },
          sortKey: g.sk ? { name: g.sk, type: dynamodb.AttributeType.STRING } : undefined,
          projectionType: g.projection,
          nonKeyAttributes: g.include ? [...g.include] : undefined,
          readCapacity: g.capacity.read,
          writeCapacity: g.capacity.write,
        });
      }
      (table.node.defaultChild as dynamodb.CfnTable).overrideLogicalId(tableLogicalId(entry.entity));
      tables[logical] = table;
    }
    this.tables = tables;

    this.mediaBucket = new s3.Bucket(this, 'MediaBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      versioned: false,
      removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [
        { id: 'expire-pending-uploads', prefix: 'pending/', expiration: Duration.days(1) },
        { id: 'abort-incomplete-multipart', abortIncompleteMultipartUploadAfter: Duration.days(1) },
      ],
    });
    (this.mediaBucket.node.defaultChild as s3.CfnBucket).overrideLogicalId(MEDIA_BUCKET_LOGICAL_ID);

    const name = cursorKeyParameterName(config.stage);
    const existenceCheck = new CfnParameter(this, 'CursorKeyParameterName', {
      type: 'AWS::SSM::Parameter::Name',
      default: name,
      allowedValues: [name],
      description:
        'Cursor-signing key (operator-created SecureString). The deploy fails if it does not ' +
        'exist; create it with: aws ssm put-parameter --type SecureString --name <this> ' +
        '--value "$(openssl rand -base64 48)"',
    });
    existenceCheck.overrideLogicalId(CURSOR_KEY_PARAMETER_LOGICAL_ID);
    this.cursorKey = ssm.StringParameter.fromSecureStringParameterAttributes(this, 'CursorKey', {
      // Using the template parameter ties every reference to the name that was checked.
      parameterName: existenceCheck.valueAsString,
      simpleName: false, // the name starts with '/'
    });
  }
}
