/**
 * Stack-level behavior: stages, outputs (§3.10), termination protection, public-repo hygiene,
 * bundling helpers (D-9), and cycle-free synthesis for every configuration.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { App } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { LAMBDA_LOCK_FILE, pipInstallArgs, readLambdaLock, sharedLambdaCode } from '../lib/bundling';
import { STAGES, StageConfig, minimumProdPurgeDelaySeconds, stageConfig, validateStageConfig } from '../lib/config/stages';
import { SES_TEST_CONTEXT, stageContext, synth, withIdps } from './helpers';

describe('stages', () => {
  test('dev and prod config per §3.1', () => {
    expect(STAGES.dev).toMatchObject({ enabledIdps: [], waf: false, terminationProtection: false, domainPrefix: 'ourlore-dev-auth' });
    expect(STAGES.prod).toMatchObject({ waf: true, terminationProtection: true, domainPrefix: 'ourlore-prod-auth' });
    expect(STAGES.prod.ses).toBeUndefined();
    for (const s of Object.values(STAGES)) {
      expect(s.callbackUrls).toEqual(['ourlore://auth/callback/']);
      expect(s.logoutUrls).toEqual(['ourlore://auth/signout/']);
      expect(s.tokens).toEqual({ accessTokenMinutes: 15, idTokenMinutes: 15, refreshTokenDays: 90, authSessionMinutes: 3, refreshRotationGraceSeconds: 10 });
    }
  });

  test('purge delay: dev 120 s, prod 960 s (§4.3, G-4)', () => {
    expect(STAGES.dev.purgeDelaySeconds).toBe(120);
    expect(STAGES.prod.purgeDelaySeconds).toBe(960);
    expect(minimumProdPurgeDelaySeconds(STAGES.prod)).toBe(960); // max(15 min + 60 s, 900 s + 60 s)
  });

  test('prod purge delay below UPL-1 POST expiry + 60 s fails synth', () => {
    const cfg: StageConfig = { ...STAGES.prod, purgeDelaySeconds: 959 };
    expect(() => validateStageConfig(cfg)).toThrow(/prod purgeDelaySeconds \(959\) must be >= 960/);
    expect(() => synth(cfg, {}, SES_TEST_CONTEXT)).toThrow(/must be >= 960/);
  });

  test('prod purge delay below access-token lifetime + 60 s fails synth', () => {
    const tokens = { ...STAGES.prod.tokens, accessTokenMinutes: 30 };
    expect(minimumProdPurgeDelaySeconds({ tokens })).toBe(1860);
    expect(() => validateStageConfig({ ...STAGES.prod, tokens, purgeDelaySeconds: 960 })).toThrow(/must be >= 1860/);
    expect(() => validateStageConfig({ ...STAGES.prod, tokens, purgeDelaySeconds: 1860 })).not.toThrow();
  });

  test('dev may use a short purge delay; invalid values fail in any stage', () => {
    expect(() => validateStageConfig({ ...STAGES.dev, purgeDelaySeconds: 0 })).not.toThrow();
    for (const bad of [-1, 1.5, Number.NaN, 86_401]) {
      expect(() => validateStageConfig({ ...STAGES.dev, purgeDelaySeconds: bad })).toThrow(/purgeDelaySeconds must be an integer/);
    }
  });

  test('unknown or missing stage fails', () => {
    expect(() => stageConfig('staging')).toThrow(/Unknown or missing stage/);
    expect(() => stageConfig(undefined)).toThrow(/Unknown or missing stage/);
    expect(stageConfig('prod').stage).toBe('prod');
  });

  test('termination protection only in prod', () => {
    expect(synth().stack.terminationProtection).toBe(false);
    expect(synth(STAGES.prod, {}, SES_TEST_CONTEXT).stack.terminationProtection).toBe(true);
  });

  test('no SES sender is committed; prod synth requires it from context (REQ-PW-7)', () => {
    expect(STAGES.prod.ses).toBeUndefined();
    expect(() => synth(STAGES.prod)).toThrow(/REQ-PW-7/);
    expect(() => synth(STAGES.prod, {}, SES_TEST_CONTEXT)).not.toThrow();
  });
});

describe('outputs (§3.10)', () => {
  test('all client-config outputs exist', () => {
    const { json } = synth();
    expect(Object.keys(json.Outputs).sort()).toEqual(
      ['ApiEndpoint', 'CallbackUrls', 'CognitoDomain', 'EnabledIdps', 'LogoutUrls', 'OAuthScopes', 'PreSignUpLogGroup', 'Region', 'UserPoolClientId', 'UserPoolId'].sort(),
    );
    expect(json.Outputs.UserPoolId.Value).toEqual({ Ref: 'UserPool' });
    expect(json.Outputs.UserPoolClientId.Value).toEqual({ Ref: 'UserPoolClientIos' });
    expect(json.Outputs.CallbackUrls.Value).toBe('["ourlore://auth/callback/"]');
    expect(json.Outputs.LogoutUrls.Value).toBe('["ourlore://auth/signout/"]');
    expect(json.Outputs.OAuthScopes.Value).toBe('["openid","email","aws.cognito.signin.user.admin"]');
    expect(json.Outputs.CognitoDomain.Value).toEqual({
      'Fn::Join': ['', ['ourlore-dev-auth.auth.', { Ref: 'AWS::Region' }, '.amazoncognito.com']],
    });
  });
});

describe('public-repo hygiene', () => {
  test.each([
    ['dev', STAGES.dev],
    ['prod', STAGES.prod],
    ['dev with IdPs', withIdps()],
  ])('%s template has no account ids or concrete ARNs', (_l, cfg) => {
    const text = JSON.stringify(synth(cfg, {}, stageContext(cfg)).json);
    expect(text).not.toMatch(/\b\d{12}\b/);
    expect(text).not.toMatch(/arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}/);
  });

  test('committed config files contain no account ids', () => {
    for (const f of ['lib/config/stages.ts', 'lib/config/identity-providers.ts', 'cdk.json', 'contract.json']) {
      expect(fs.readFileSync(path.join(__dirname, '..', f), 'utf8')).not.toMatch(/\b\d{12}\b/);
    }
  });
});

describe('synthesis has no circular dependency', () => {
  test.each([
    ['dev', STAGES.dev],
    ['prod', STAGES.prod],
    ['dev with IdPs', withIdps()],
    ['prod with IdPs', withIdps('prod')],
  ])('%s synthesizes', (_l, cfg) => {
    // Template.fromStack runs full synthesis, which throws on dependency cycles.
    expect(() => synth(cfg, {}, stageContext(cfg))).not.toThrow();
  });
});

describe('bundling (D-9)', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ourlore-bundling-'));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  const APP_REPO = path.join(__dirname, '..', '..', 'OurloreBackendService');
  const HASH = `sha256:${'a'.repeat(64)}`;

  test("reads the app's committed lock: exact pins, all hashed, runtime pins present", () => {
    const lock = readLambdaLock(path.join(APP_REPO, LAMBDA_LOCK_FILE));
    expect(lock.hashed).toBe(true);
    expect(lock.requirements.length).toBeGreaterThan(0);
    const names = lock.requirements.map((r) => r.name);
    for (const n of ['aws-lambda-powertools', 'aws-xray-sdk', 'pydantic', 'pydantic-core', 'boto3']) expect(names).toContain(n);
    for (const r of lock.requirements) expect(r.hashes.every((h) => /^sha256:[0-9a-f]{64}$/.test(h))).toBe(true);
  });

  test('parses continuation lines, comments, and normalizes names', () => {
    const f = path.join(dir, LAMBDA_LOCK_FILE);
    fs.writeFileSync(f, `# header\nFoo_Bar==1.0 \\\n    --hash=${HASH}\n\nbaz==2.0.post1 --hash=${HASH} # trailing\n`);
    expect(readLambdaLock(f)).toEqual({
      path: f,
      hashed: true,
      requirements: [
        { name: 'foo-bar', version: '1.0', hashes: [HASH] },
        { name: 'baz', version: '2.0.post1', hashes: [HASH] },
      ],
    });
  });

  test.each([
    ['unpinned', 'requests>=2\n', /not an exact pin/],
    ['extras (lock must be flat)', 'b[c]==2.0\n', /not an exact pin/],
    ['partial hashes', `a==1.0 --hash=${HASH}\nb==2.0\n`, /every entry or none/],
    ['unsupported option', 'a==1.0 --index-url=https://example.com\n', /unsupported option/],
    ['weak hash', 'a==1.0 --hash=md5:abc\n', /unsupported option/],
    ['duplicate', 'a==1.0\nA==1.0\n', /locked twice/],
    ['empty', '# nothing\n', /no requirements/],
  ])('rejects a bad lock: %s', (_label, body, error) => {
    const f = path.join(dir, LAMBDA_LOCK_FILE);
    fs.writeFileSync(f, body);
    expect(() => readLambdaLock(f)).toThrow(error);
  });

  test('a missing lock names the script that generates it', () => {
    expect(() => readLambdaLock(path.join(dir, LAMBDA_LOCK_FILE))).toThrow(/lock_lambda_deps\.sh/);
  });

  test('pip command: Lambda platform, --target, --no-deps, --require-hashes, -r <lock>', () => {
    const lock = { path: '/app/requirements-lambda.lock', hashed: true, requirements: [{ name: 'a', version: '1', hashes: [HASH] }] };
    expect(pipInstallArgs(lock, '/out')).toEqual([
      '-m', 'pip', 'install',
      '--platform', 'manylinux2014_aarch64',
      '--only-binary=:all:',
      '--python-version', '3.12',
      '--implementation', 'cp',
      '--target', '/out',
      '--no-deps',
      '--require-hashes',
      '--no-compile',
      '--disable-pip-version-check',
      '--no-warn-conflicts',
      '--quiet',
      '-r', '/app/requirements-lambda.lock',
    ]);
  });

  test('pip command omits --require-hashes only for an unhashed lock, and never installs by name', () => {
    const args = pipInstallArgs({ path: '/l', hashed: false, requirements: [{ name: 'a', version: '1', hashes: [] }] }, '/o');
    expect(args).not.toContain('--require-hashes');
    expect(args).toContain('--no-deps');
    expect(args.slice(-2)).toEqual(['-r', '/l']);
    expect(args).not.toContain('a==1');
  });

  test('an app path without a lock fails synth with a clear message', () => {
    fs.mkdirSync(path.join(dir, 'src', 'app'), { recursive: true });
    const app = new App({ context: { 'ourlore:appPath': dir } });
    expect(() => sharedLambdaCode(app)).toThrow(/requirements-lambda\.lock not found/);
  });

  test('skipBundling uses inline placeholder code and warns', () => {
    const app = new App({ context: { 'ourlore:skipBundling': 'true' } });
    const code = sharedLambdaCode(app);
    expect(code).toBeInstanceOf(lambda.InlineCode);
  });

  test('a missing app path fails with a clear message', () => {
    const app = new App({ context: { 'ourlore:appPath': path.join(dir, 'missing') } });
    expect(() => sharedLambdaCode(app)).toThrow(/App sources not found/);
  });

  test('every function shares one code asset', () => {
    const { json } = synth();
    const codes = new Set(
      Object.values(json.Resources)
        .filter((r) => r.Type === 'AWS::Lambda::Function')
        .map((r) => JSON.stringify(r.Properties!.Code)),
    );
    expect(codes.size).toBe(1);
  });
});
