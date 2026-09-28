/**
 * Contract loader/validation (lib/contract.ts) and env resolution (ContractBindings).
 */
import { ContractBindings } from '../lib/constructs/contract-function';
import { Contract, ContractError, allRoutes, loadContract, parseContract } from '../lib/contract';
import { CONTRACT } from './helpers';

/** Deep-copied, mutable contract for negative cases. */
function mutable(): any {
  return JSON.parse(JSON.stringify(CONTRACT));
}

describe('vendored contract.json', () => {
  test('loads as version 4 with 6 groups and 30 routes', () => {
    const c = loadContract();
    expect(c.version).toBe(4);
    expect(Object.keys(c.resource_groups).sort()).toEqual(['account', 'posts', 'social', 'uploads', 'users', 'wishes']);
    expect(allRoutes(c)).toHaveLength(30);
    expect(Object.keys(c.cognito_triggers)).toEqual(['pre_sign_up']);
    expect(Object.keys(c.workers).sort()).toEqual(['account_purge', 'maintenance']);
  });

  test('optional and deferred env vars', () => {
    expect(CONTRACT.optional_env_vars).toEqual(['APPLE_SECRET_ARN']);
    expect(CONTRACT.deferred_env_vars).toEqual(['MEDIA_CDN_DOMAIN']);
  });

  test('media bucket declares its owner key prefixes (D-10)', () => {
    expect(CONTRACT.buckets.media.key_prefixes).toEqual(['media/', 'pending/', 'thumb/']);
  });

  test('account group: 20 s timeout and PURGE_DELAY_SECONDS', () => {
    expect(CONTRACT.resource_groups.account.timeout_seconds).toBe(20);
    expect(CONTRACT.resource_groups.account.env).toContain('PURGE_DELAY_SECONDS');
  });

  test('missing file fails with a ContractError', () => {
    expect(() => loadContract('/nonexistent/contract.json')).toThrow(ContractError);
  });
});

describe('validation fails synth on', () => {
  test.each<[string, (c: any) => void, RegExp]>([
    ['wrong version', (c) => { c.version = 1; }, /version 1 is not supported/],
    ['unknown method', (c) => { c.resource_groups.users.routes[0].method = 'HEAD'; }, /unknown method 'HEAD'/],
    ['duplicate route', (c) => { c.resource_groups.social.routes.push({ ...c.resource_groups.users.routes[1] }); }, /duplicate route 'POST \/v1\/me'/],
    ['env name not in catalog', (c) => { c.resource_groups.users.env.push('NOPE'); }, /env 'NOPE' is not in env_vars/],
    ['duplicate env name', (c) => { c.workers.maintenance.env.push('TABLE_DELETION_JOBS'); }, /is duplicated/],
    ['optional name not in catalog', (c) => { c.optional_env_vars.push('NOPE'); }, /'NOPE' \(optional\/deferred\)/],
    ['unknown table in scope', (c) => { c.resource_groups.users.tables.nope = 'read'; }, /tables.nope is not in the tables catalog/],
    ['unknown access level', (c) => { c.resource_groups.users.tables.users = 'admin'; }, /unknown access 'admin'/],
    ['unknown bucket access', (c) => { c.resource_groups.users.buckets.media = 'delete'; }, /unknown access 'delete'/],
    ['auth route without scopes', (c) => { c.resource_groups.users.routes[1].scopes = []; }, /auth route without scopes/],
    ['public route with scopes', (c) => { c.resource_groups.users.routes[0].scopes = ['x']; }, /public route with scopes/],
    ['bad handler', (c) => { c.resource_groups.users.handler = 'os.system'; }, /handler 'os.system' is invalid/],
    ['unknown worker queue', (c) => { c.workers.account_purge.event_source.queue = 'nope'; }, /queue 'nope' is unknown/],
    ['bad schedule', (c) => { c.workers.maintenance.event_source.expression = 'every 5'; }, /expression 'every 5' is invalid/],
    ['unknown event source', (c) => { c.workers.maintenance.event_source = { type: 'kinesis' }; }, /type 'kinesis' is unknown/],
    ['catalog env var unknown', (c) => { c.tables.users.env_var = 'NOPE'; }, /tables.users.env_var 'NOPE'/],
    ['missing parameters catalog', (c) => { delete c.parameters; }, /'parameters' must be an object/],
    ['parameter env var unknown', (c) => { c.parameters.cursor_key.env_var = 'NOPE'; }, /parameters.cursor_key.env_var 'NOPE'/],
    ['optional parameter', (c) => { c.optional_env_vars.push('CURSOR_KEY_PARAM'); }, /must not be optional or deferred/],
    ['unknown parameter in scope', (c) => { c.resource_groups.users.parameters.nope = 'read'; }, /parameters.nope is not in the parameters catalog/],
    ['unknown parameter access', (c) => { c.resource_groups.users.parameters.cursor_key = 'write'; }, /unknown access 'write'/],
    ['function without parameters', (c) => { delete c.workers.maintenance.parameters; }, /workers.maintenance.parameters must be an object/],
    ['bucket without key prefixes', (c) => { delete c.buckets.media.key_prefixes; }, /buckets.media.key_prefixes must be a non-empty list/],
    ['empty key prefixes', (c) => { c.buckets.media.key_prefixes = []; }, /key_prefixes must be a non-empty list/],
    ['wildcard key prefix', (c) => { c.buckets.media.key_prefixes = ['*']; }, /key_prefixes '\*' is invalid/],
    ['key prefix without slash', (c) => { c.buckets.media.key_prefixes = ['media']; }, /key_prefixes 'media' is invalid/],
    ['duplicate key prefix', (c) => { c.buckets.media.key_prefixes = ['media/', 'media/']; }, /has duplicates/],
  ])('%s', (_label, mutate, message) => {
    const c = mutable();
    mutate(c);
    expect(() => parseContract(c)).toThrow(message);
  });
});

describe('env resolution (ContractBindings.resolveEnv)', () => {
  const fresh = (): ContractBindings => new ContractBindings(CONTRACT as Contract);

  test('deferred names resolve to "" without a value', () => {
    expect(fresh().resolveEnv(['MEDIA_CDN_DOMAIN'])).toEqual({ MEDIA_CDN_DOMAIN: '' });
  });

  test('a missing non-deferred value fails', () => {
    expect(() => fresh().resolveEnv(['TABLE_USERS'])).toThrow(/No value for env var 'TABLE_USERS'/);
  });

  test('optional names may be ""; others may not', () => {
    const b = fresh();
    b.setEnv('APPLE_SECRET_ARN', '');
    b.setEnv('IDP_REGISTRY', '');
    expect(b.resolveEnv(['APPLE_SECRET_ARN'])).toEqual({ APPLE_SECRET_ARN: '' });
    expect(() => b.resolveEnv(['IDP_REGISTRY'])).toThrow(/empty but not optional/);
  });

  test('only optional secrets may be disabled', () => {
    expect(() => fresh().addSecret('apple', null)).not.toThrow();
    expect(() => fresh().addSecret('cursor', null)).toThrow(/not in the contract secrets catalog/);
  });

  test('a parameter binds its name to its env var; unknown or unbound parameters fail', () => {
    const b = fresh();
    b.addParameter('cursor_key', { parameterName: '/ourlore/dev/cursor-key' } as any);
    expect(b.resolveEnv(['CURSOR_KEY_PARAM'])).toEqual({ CURSOR_KEY_PARAM: '/ourlore/dev/cursor-key' });
    expect(() => b.addParameter('nope', { parameterName: 'x' } as any)).toThrow(/not in the contract parameters catalog/);
    expect(() => fresh().parameter('cursor_key')).toThrow(/parameter 'cursor_key', which was never bound/);
  });

  test('setting a name outside the catalog fails', () => {
    expect(() => fresh().setEnv('NOPE', 'x')).toThrow(/not in the contract catalog/);
  });
});
