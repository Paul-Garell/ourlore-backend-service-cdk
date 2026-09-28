/**
 * IAM least privilege (auth_design.md §3.7, §3.11, D-11).
 *
 * For every contract function, the union of its role's grants must equal exactly what the
 * contract declares (computed here independently from the contract), plus writing to its own
 * log group, X-Ray, and — for SQS-triggered workers — what the event source mapping needs.
 */
import { STAGES } from '../lib/config/stages';
import type { FunctionSpec, WorkerSpec } from '../lib/contract';
import {
  CONTRACT,
  FIXTURE_SECRET_NAMES,
  TemplateJson,
  contractFunctions,
  functionByHandler,
  grantsOfRole,
  policiesOfRole,
  resourceKey,
  resourcesOfType,
  roleOf,
  stageContext,
  synth,
  withIdps,
} from './helpers';

const TABLE_READ = ['BatchGetItem', 'ConditionCheckItem', 'DescribeTable', 'GetItem', 'Query', 'Scan'];
const TABLE_WRITE = ['BatchWriteItem', 'DeleteItem', 'PutItem', 'UpdateItem'];
const QUEUE_IDS: Record<string, string> = { account_purge: 'AccountPurgeQueue', account_purge_dlq: 'AccountPurgeDlq' };
const SQS_EVENT_SOURCE = ['ChangeMessageVisibility', 'DeleteMessage', 'GetQueueAttributes', 'GetQueueUrl', 'ReceiveMessage'];

/** Expected grants of one function, as `action resourceKey` strings (see helpers.resourceKey). */
function expectedGrants(spec: FunctionSpec, logGroupId: string, appleSecretName?: string): Set<string> {
  const out = new Set<string>();
  const add = (actions: string[], resource: string): void => actions.forEach((a) => out.add(`${a} ${resource}`));
  add(['logs:CreateLogStream', 'logs:PutLogEvents'], logGroupId);
  add(['xray:PutTelemetryRecords', 'xray:PutTraceSegments'], '*');
  for (const [logical, level] of Object.entries(spec.tables)) {
    const id = `Table${CONTRACT.tables[logical].entity}`;
    const actions = [...TABLE_READ, ...(level === 'read_write' ? TABLE_WRITE : [])].map((a) => `dynamodb:${a}`);
    add(actions, id);
    add(actions, `${id}/index/*`);
  }
  for (const [logical, level] of Object.entries(spec.buckets)) {
    const objects = { put: ['PutObject'], read: ['GetObject'], read_write: ['GetObject', 'PutObject'], read_write_delete: ['DeleteObject', 'GetObject', 'PutObject'] }[level];
    // Only under the owner prefixes (D-10), never `MediaBucket/*`.
    for (const p of CONTRACT.buckets[logical].key_prefixes) add(objects.map((a) => `s3:${a}`), `MediaBucket/${p}*`);
    if (level !== 'put') add(['s3:ListBucket'], 'MediaBucket');
  }
  for (const [logical, level] of Object.entries(spec.queues)) {
    const actions = level === 'send' ? ['SendMessage'] : ['ChangeMessageVisibility', 'DeleteMessage', 'GetQueueAttributes', 'ReceiveMessage'];
    add(actions.map((a) => `sqs:${a}`), QUEUE_IDS[logical]);
  }
  for (const logical of Object.keys(spec.secrets)) {
    if (logical === 'apple' && appleSecretName) add(['secretsmanager:GetSecretValue'], `secret:${appleSecretName}-??????`);
  }
  for (const logical of Object.keys(spec.parameters)) {
    // The ARN is built from the deploy-time-checked template parameter holding the name.
    if (logical === 'cursor_key') add(['ssm:GetParameter'], 'parameter:Ref:CursorKeyParameterName');
  }
  add(spec.cognito_actions.map((a) => `cognito-idp:${a}`), 'UserPool');
  const es = (spec as WorkerSpec).event_source;
  if (es?.type === 'sqs') add(SQS_EVENT_SOURCE.map((a) => `sqs:${a}`), QUEUE_IDS[es.queue]);
  return out;
}

function grantsOf(json: TemplateJson, handler: string): { grants: Set<string>; logGroupId: string; roleId: string } {
  const [, fn] = functionByHandler(json, handler);
  const roleId = roleOf(fn);
  return { grants: grantsOfRole(json, roleId), logGroupId: fn.Properties!.LoggingConfig.LogGroup.Ref, roleId };
}

describe.each([
  ['dev, no IdPs', STAGES.dev, undefined],
  ['dev, apple + google', withIdps(), FIXTURE_SECRET_NAMES.apple],
  ['prod, apple + google', withIdps('prod'), FIXTURE_SECRET_NAMES.apple],
])('least privilege (%s)', (_label, config, appleSecret) => {
  const { json } = synth(config, {}, stageContext(config));

  test.each(contractFunctions().map((f) => [f.name, f]))('%s grants exactly the contract scope', (_n, f) => {
    const { grants, logGroupId } = grantsOf(json, f.spec.handler);
    expect([...grants].sort()).toEqual([...expectedGrants(f.spec, logGroupId, appleSecret)].sort());
  });

  test('roles: lambda-only trust, no managed or inline policies', () => {
    for (const f of contractFunctions()) {
      const { roleId } = grantsOf(json, f.spec.handler);
      const role = json.Resources[roleId].Properties!;
      expect(role.ManagedPolicyArns).toBeUndefined();
      expect(role.Policies).toBeUndefined();
      expect(role.AssumeRolePolicyDocument.Statement).toEqual([
        { Action: 'sts:AssumeRole', Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' } },
      ]);
    }
  });

  test("no '*' resource except X-Ray, in any identity policy", () => {
    for (const [, p] of resourcesOfType(json, 'AWS::IAM::Policy')) {
      for (const s of p.Properties!.PolicyDocument.Statement) {
        const resources: unknown[] = [].concat(s.Resource);
        if (resources.includes('*')) {
          expect([].concat(s.Action).every((a: string) => a.startsWith('xray:'))).toBe(true);
        }
      }
    }
    expect(resourcesOfType(json, 'AWS::IAM::ManagedPolicy')).toHaveLength(0);
  });

  test('s3:ListBucket is always limited to the owner prefixes; no object grant on the whole bucket', () => {
    let listStatements = 0;
    for (const [, p] of resourcesOfType(json, 'AWS::IAM::Policy')) {
      for (const s of p.Properties!.PolicyDocument.Statement) {
        const actions: string[] = [].concat(s.Action);
        if (actions.includes('s3:ListBucket')) {
          listStatements += 1;
          expect(actions).toEqual(['s3:ListBucket']);
          expect(s.Condition).toEqual({ StringLike: { 's3:prefix': ['media/*', 'pending/*', 'thumb/*'] } });
        }
        if (actions.some((a) => a.startsWith('s3:') && a !== 's3:ListBucket')) {
          for (const r of [].concat(s.Resource)) {
            expect(resourceKey(r)).toMatch(/^MediaBucket\/(media|pending|thumb)\/\*$/);
          }
        }
      }
    }
    // users, posts, and the purge worker list; uploads only puts.
    expect(listStatements).toBe(3);
  });

  test('the purge worker may list, read, and delete media, and Scan every purged table', () => {
    const { grants } = grantsOf(json, CONTRACT.workers.account_purge.handler);
    for (const p of ['media', 'pending', 'thumb']) expect(grants).toContain(`s3:DeleteObject MediaBucket/${p}/*`);
    expect(grants).toContain('s3:ListBucket MediaBucket');
    for (const entity of ['Users', 'Usernames', 'Follows', 'FollowRequests', 'SignificantOtherRequests', 'Posts', 'Likes', 'Wishes']) {
      expect(grants).toContain(`dynamodb:Scan Table${entity}`);
    }
    expect([...grants].some((g) => g.includes('TableIdempotency'))).toBe(false);
  });

  test('users function: no Cognito admin actions, no Secrets Manager, and SSM only for the cursor key (§3.11)', () => {
    const { grants, roleId } = grantsOf(json, CONTRACT.resource_groups.users.handler);
    const list = [...grants];
    expect(list.filter((g) => g.startsWith('cognito-idp:'))).toEqual([]);
    expect(list.filter((g) => g.startsWith('secretsmanager:'))).toEqual([]);
    expect(list.filter((g) => g.startsWith('ssm:'))).toEqual(['ssm:GetParameter parameter:Ref:CursorKeyParameterName']);
    // No IdP secret, by name or by ARN, anywhere in its policies.
    const policyText = JSON.stringify(policiesOfRole(json, roleId).map(([, p]) => p.Properties!.PolicyDocument));
    expect(policyText).not.toContain('idp/');
    expect(policyText).not.toContain(FIXTURE_SECRET_NAMES.apple);
    expect(policyText).not.toContain(FIXTURE_SECRET_NAMES.google);
  });

  test('exactly the paginating groups may read the cursor key; nothing gets a KMS or wildcard SSM grant', () => {
    const readers = contractFunctions()
      .filter((f) => [...grantsOf(json, f.spec.handler).grants].some((g) => g.startsWith('ssm:')))
      .map((f) => f.name)
      .sort();
    expect(readers).toEqual(['posts', 'social', 'users', 'wishes']);
    for (const [, p] of resourcesOfType(json, 'AWS::IAM::Policy')) {
      for (const s of p.Properties!.PolicyDocument.Statement) {
        const actions: string[] = [].concat(s.Action);
        expect(actions.some((a) => a.startsWith('kms:'))).toBe(false);
        if (actions.some((a) => a.startsWith('ssm:'))) {
          expect(actions).toEqual(['ssm:GetParameter']);
          expect(JSON.stringify(s.Resource)).not.toContain('*');
        }
      }
    }
  });

  test('only purge and maintenance hold AdminDeleteUser (D-11)', () => {
    const holders = contractFunctions()
      .filter((f) => [...grantsOf(json, f.spec.handler).grants].some((g) => g.startsWith('cognito-idp:Admin')))
      .map((f) => f.name)
      .sort();
    expect(holders).toEqual(['account_purge', 'maintenance']);
  });

  test('only the account function may read the Apple secret, and only when Apple is enabled', () => {
    const readers = contractFunctions()
      .filter((f) => [...grantsOf(json, f.spec.handler).grants].some((g) => g.includes('idp/apple')))
      .map((f) => f.name);
    expect(readers).toEqual(appleSecret ? ['account'] : []);
    const [, account] = functionByHandler(json, CONTRACT.resource_groups.account.handler);
    const value = account.Properties!.Environment.Variables.APPLE_SECRET_ARN;
    if (appleSecret) expect(JSON.stringify(value)).toContain(`:secret:${appleSecret}`);
    else expect(value).toBe('');
  });
});

describe('Apple disabled', () => {
  test('APPLE_SECRET_ARN is "" and no Secrets Manager grant references an IdP secret', () => {
    const { json } = synth();
    const text = JSON.stringify(
      resourcesOfType(json, 'AWS::IAM::Policy').map(([, p]) => p.Properties!.PolicyDocument),
    );
    expect(text).not.toContain('idp/');
    const [, account] = functionByHandler(json, CONTRACT.resource_groups.account.handler);
    expect(account.Properties!.Environment.Variables.APPLE_SECRET_ARN).toBe('');
  });
});

describe('trigger policy is standalone', () => {
  test('the pre-sign-up role has a default policy (logs, X-Ray) and one standalone policy (ListUsers)', () => {
    const { json } = synth();
    const [, fn] = functionByHandler(json, CONTRACT.cognito_triggers.pre_sign_up.handler);
    const policies = policiesOfRole(json, roleOf(fn));
    expect(policies).toHaveLength(2);
    const paths = policies.map(([id]) => id);
    expect(paths.filter((id) => id.includes('RoleDefaultPolicy'))).toHaveLength(1);
  });
});
