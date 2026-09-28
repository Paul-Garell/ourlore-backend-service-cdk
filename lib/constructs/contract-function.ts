/**
 * One Lambda function built from a contract `FunctionSpec` (auth_design.md §3.7).
 *
 * Every group, trigger, and worker is built here so they all follow the same rules:
 * - runtime, architecture, memory, timeout, and handler from the contract
 * - X-Ray active; an explicit log group with retention
 * - env is exactly the function's declared `env`; a missing value fails synth unless the
 *   name is deferred (supplied as "") or optional (may be "")
 * - a dedicated role with no managed policies; IAM is derived only from the declared
 *   scopes (plus writing to its own log group and X-Ray, which CDK adds for tracing)
 */
import { Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';
import type { BucketAccess, Contract, FunctionSpec, QueueAccess, TableAccess } from '../contract';

/** IAM actions per table access level (`/index/*` is always included). */
export const TABLE_ACTIONS: Readonly<Record<TableAccess, readonly string[]>> = {
  read: [
    'dynamodb:BatchGetItem',
    'dynamodb:ConditionCheckItem',
    'dynamodb:DescribeTable',
    'dynamodb:GetItem',
    'dynamodb:Query',
    'dynamodb:Scan',
  ],
  read_write: [
    'dynamodb:BatchGetItem',
    'dynamodb:BatchWriteItem',
    'dynamodb:ConditionCheckItem',
    'dynamodb:DeleteItem',
    'dynamodb:DescribeTable',
    'dynamodb:GetItem',
    'dynamodb:PutItem',
    'dynamodb:Query',
    'dynamodb:Scan',
    'dynamodb:UpdateItem',
  ],
};

/** IAM actions per bucket access level: object-level and bucket-level. */
export const BUCKET_ACTIONS: Readonly<Record<BucketAccess, { objects: readonly string[]; bucket: readonly string[] }>> = {
  put: { objects: ['s3:PutObject'], bucket: [] },
  read: { objects: ['s3:GetObject'], bucket: ['s3:ListBucket'] },
  read_write: { objects: ['s3:GetObject', 's3:PutObject'], bucket: ['s3:ListBucket'] },
  read_write_delete: { objects: ['s3:DeleteObject', 's3:GetObject', 's3:PutObject'], bucket: ['s3:ListBucket'] },
};

/** IAM actions per queue access level. */
export const QUEUE_ACTIONS: Readonly<Record<QueueAccess, readonly string[]>> = {
  send: ['sqs:SendMessage'],
  receive_delete: [
    'sqs:ChangeMessageVisibility',
    'sqs:DeleteMessage',
    'sqs:GetQueueAttributes',
    'sqs:ReceiveMessage',
  ],
};

export const SECRET_READ_ACTIONS: readonly string[] = ['secretsmanager:GetSecretValue'];

/**
 * IAM actions for reading one SSM parameter. `SecureString`s use the AWS-managed `aws/ssm`
 * key, whose key policy lets principals in the account decrypt through SSM, so no `kms:`
 * grant is needed. A customer-managed key would need `kms:Decrypt` here.
 */
export const PARAMETER_READ_ACTIONS: readonly string[] = ['ssm:GetParameter'];

const RUNTIMES: Readonly<Record<string, lambda.Runtime>> = {
  'python3.12': lambda.Runtime.PYTHON_3_12,
};
const ARCHITECTURES: Readonly<Record<string, lambda.Architecture>> = {
  arm64: lambda.Architecture.ARM_64,
  x86_64: lambda.Architecture.X86_64,
};

/**
 * Registry of the concrete resources and env values the contract's logical names refer to.
 *
 * Filled in by the stack as constructs are created; lookups fail synth with a clear message
 * when something the contract references was never provided.
 */
export class ContractBindings {
  private readonly tables = new Map<string, dynamodb.ITable>();
  private readonly buckets = new Map<string, s3.IBucket>();
  private readonly queues = new Map<string, sqs.IQueue>();
  /** `null` = optional secret that is disabled in this stage. */
  private readonly secrets = new Map<string, secretsmanager.ISecret | null>();
  private readonly parameters = new Map<string, ssm.IParameter>();
  private readonly env = new Map<string, string>();
  private poolArn?: string;

  constructor(readonly contract: Contract) {}

  /** Register a table under its contract logical name; also sets its env var. */
  addTable(logical: string, table: dynamodb.ITable): void {
    this.tables.set(logical, table);
    this.setEnv(this.catalogEntry('tables', logical).env_var, table.tableName);
  }

  addBucket(logical: string, bucket: s3.IBucket): void {
    this.buckets.set(logical, bucket);
    this.setEnv(this.catalogEntry('buckets', logical).env_var, bucket.bucketName);
  }

  addQueue(logical: string, queue: sqs.IQueue): void {
    this.queues.set(logical, queue);
    this.setEnv(this.catalogEntry('queues', logical).env_var, queue.queueUrl);
  }

  /**
   * Register a secret. `null` marks an optional secret as disabled: its env var becomes ""
   * and it gets no grant. Only secrets whose env var is in `optional_env_vars` may be null.
   */
  addSecret(logical: string, secret: secretsmanager.ISecret | null): void {
    const envVar = this.catalogEntry('secrets', logical).env_var;
    if (secret === null && !this.contract.optional_env_vars.includes(envVar)) {
      throw new Error(`Secret '${logical}' is required (${envVar} is not optional).`);
    }
    this.secrets.set(logical, secret);
    this.setEnv(envVar, secret === null ? '' : secret.secretArn);
  }

  /** Register an SSM parameter; its env var carries the parameter *name*. */
  addParameter(logical: string, parameter: ssm.IParameter): void {
    this.parameters.set(logical, parameter);
    this.setEnv(this.catalogEntry('parameters', logical).env_var, parameter.parameterName);
  }

  setUserPoolArn(arn: string): void {
    this.poolArn = arn;
  }

  /** Set a scalar env value (e.g. client ids, registry JSON). */
  setEnv(name: string, value: string): void {
    if (!(name in this.contract.env_vars)) throw new Error(`Env var '${name}' is not in the contract catalog.`);
    this.env.set(name, value);
  }

  /**
   * Resolve exactly `names`. Deferred names are "", optional names may be "", and anything
   * else missing or empty fails synth.
   */
  resolveEnv(names: readonly string[], overrides: Readonly<Record<string, string>> = {}): Record<string, string> {
    const out: Record<string, string> = {};
    for (const name of names) {
      if (this.contract.deferred_env_vars.includes(name)) {
        out[name] = '';
        continue;
      }
      const value = overrides[name] ?? this.env.get(name);
      if (value === undefined) throw new Error(`No value for env var '${name}' (not deferred).`);
      if (value === '' && !this.contract.optional_env_vars.includes(name)) {
        throw new Error(`Env var '${name}' is empty but not optional.`);
      }
      out[name] = value;
    }
    return out;
  }

  table(logical: string): dynamodb.ITable {
    return required(this.tables.get(logical), `table '${logical}'`);
  }
  bucket(logical: string): s3.IBucket {
    return required(this.buckets.get(logical), `bucket '${logical}'`);
  }
  queue(logical: string): sqs.IQueue {
    return required(this.queues.get(logical), `queue '${logical}'`);
  }
  secret(logical: string): secretsmanager.ISecret | null {
    if (!this.secrets.has(logical)) throw new Error(`Secret '${logical}' was never bound.`);
    return this.secrets.get(logical) ?? null;
  }
  parameter(logical: string): ssm.IParameter {
    return required(this.parameters.get(logical), `parameter '${logical}'`);
  }
  userPoolArn(): string {
    return required(this.poolArn, 'user pool ARN');
  }

  /** Build the IAM statements a spec's scopes grant. */
  statementsFor(spec: FunctionSpec): iam.PolicyStatement[] {
    const out: iam.PolicyStatement[] = [];
    for (const [logical, level] of Object.entries(spec.tables)) {
      const arn = this.table(logical).tableArn;
      out.push(new iam.PolicyStatement({ actions: [...TABLE_ACTIONS[level]], resources: [arn, `${arn}/index/*`] }));
    }
    for (const [logical, level] of Object.entries(spec.buckets)) {
      const b = this.bucket(logical);
      const { objects, bucket } = BUCKET_ACTIONS[level];
      // Owner-first keys (D-10): objects only under the catalog's prefixes, and listing only
      // with an `s3:prefix` inside them.
      const prefixes = this.contract.buckets[logical].key_prefixes;
      out.push(
        new iam.PolicyStatement({ actions: [...objects], resources: prefixes.map((p) => b.arnForObjects(`${p}*`)) }),
      );
      if (bucket.length > 0) {
        out.push(
          new iam.PolicyStatement({
            actions: [...bucket],
            resources: [b.bucketArn],
            conditions: { StringLike: { 's3:prefix': prefixes.map((p) => `${p}*`) } },
          }),
        );
      }
    }
    for (const [logical, level] of Object.entries(spec.queues)) {
      out.push(new iam.PolicyStatement({ actions: [...QUEUE_ACTIONS[level]], resources: [this.queue(logical).queueArn] }));
    }
    for (const logical of Object.keys(spec.secrets)) {
      const s = this.secret(logical);
      if (s === null) continue; // optional and disabled in this stage: no grant
      // Name-imported secrets have a partial ARN; IAM needs the random-suffix wildcard.
      const arn = s.secretFullArn ?? `${s.secretArn}-??????`;
      out.push(new iam.PolicyStatement({ actions: [...SECRET_READ_ACTIONS], resources: [arn] }));
    }
    for (const logical of Object.keys(spec.parameters)) {
      out.push(
        new iam.PolicyStatement({ actions: [...PARAMETER_READ_ACTIONS], resources: [this.parameter(logical).parameterArn] }),
      );
    }
    if (spec.cognito_actions.length > 0) {
      out.push(
        new iam.PolicyStatement({
          actions: spec.cognito_actions.map((a) => `cognito-idp:${a}`),
          resources: [this.userPoolArn()],
        }),
      );
    }
    return out;
  }

  private catalogEntry(kind: 'tables' | 'buckets' | 'queues' | 'secrets' | 'parameters', logical: string): { env_var: string } {
    const entry = this.contract[kind][logical];
    if (!entry) throw new Error(`'${logical}' is not in the contract ${kind} catalog.`);
    return entry;
  }
}

function required<T>(v: T | undefined, what: string): T {
  if (v === undefined) throw new Error(`Contract references ${what}, which was never bound.`);
  return v;
}

export interface ContractFunctionProps {
  readonly spec: FunctionSpec;
  readonly bindings: ContractBindings;
  readonly code: lambda.Code;
  /** Powertools service name, e.g. `ourlore-users`. */
  readonly serviceName: string;
  readonly logLevel: string;
  readonly logRetentionDays: number;
  readonly logRemovalPolicy: RemovalPolicy;
  readonly description: string;
  /**
   * When set, the contract grants go into a standalone `iam.Policy` created in this scope
   * instead of the role's default policy. Used by the pre-sign-up trigger to avoid the
   * pool → function → policy → pool cycle (§3.5). The scope must be outside both the role's
   * and the function's construct subtrees.
   */
  readonly standalonePolicyScope?: Construct;
}

/** A contract-driven Lambda function with its own role and log group. */
export class ContractFunction extends Construct {
  readonly function: lambda.Function;
  readonly role: iam.Role;
  readonly logGroup: logs.LogGroup;
  /** The standalone grant policy, when `standalonePolicyScope` was given. */
  readonly standalonePolicy?: iam.Policy;

  constructor(scope: Construct, id: string, props: ContractFunctionProps) {
    super(scope, id);
    const { spec, bindings } = props;
    const rt = bindings.contract.runtime;
    const runtime = RUNTIMES[rt.runtime];
    const architecture = ARCHITECTURES[rt.architecture];
    if (!runtime) throw new Error(`Unsupported runtime '${rt.runtime}' in contract.`);
    if (!architecture) throw new Error(`Unsupported architecture '${rt.architecture}' in contract.`);

    this.logGroup = new logs.LogGroup(this, 'LogGroup', {
      retention: retentionFor(props.logRetentionDays),
      removalPolicy: props.logRemovalPolicy,
    });

    this.role = new iam.Role(this, 'Role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: `${props.serviceName} (${Stack.of(this).stackName})`,
    });
    this.logGroup.grantWrite(this.role);

    const environment = bindings.resolveEnv(spec.env, {
      POWERTOOLS_SERVICE_NAME: props.serviceName,
      POWERTOOLS_LOG_LEVEL: props.logLevel,
    });

    this.function = new lambda.Function(this, 'Function', {
      runtime,
      architecture,
      handler: spec.handler,
      code: props.code,
      memorySize: spec.memory_mb,
      timeout: Duration.seconds(spec.timeout_seconds),
      tracing: lambda.Tracing.ACTIVE,
      logGroup: this.logGroup,
      role: this.role,
      environment,
      description: props.description,
    });

    const statements = bindings.statementsFor(spec);
    if (props.standalonePolicyScope) {
      if (statements.length > 0) {
        this.standalonePolicy = new iam.Policy(props.standalonePolicyScope, `${id}Policy`, {
          statements,
          roles: [this.role],
        });
      }
    } else {
      for (const s of statements) this.role.addToPrincipalPolicy(s);
    }
  }
}

/** Map a day count to the nearest supported `RetentionDays` value (exact match required). */
export function retentionFor(days: number): logs.RetentionDays {
  const match = Object.values(logs.RetentionDays).find((v) => v === days);
  if (match === undefined) throw new Error(`Unsupported log retention of ${days} days.`);
  return match as logs.RetentionDays;
}
