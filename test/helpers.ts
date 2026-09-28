/**
 * Test helpers: synthesize `Ourlore-<stage>` with the repo's feature flags (cdk.json context)
 * and bundling skipped, plus template queries shared by the per-construct suites.
 */
import * as fs from 'fs';
import * as path from 'path';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { STAGES, StageConfig, StageName } from '../lib/config/stages';
import { Contract, loadContract } from '../lib/contract';
import { OurloreStack, OurloreStackProps } from '../lib/ourlore-stack';

/** Feature flags and other context from cdk.json, so tests match `cdk synth`. */
const CDK_CONTEXT: Record<string, unknown> = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'cdk.json'), 'utf8'),
).context;

export const CONTRACT: Contract = loadContract();

/** Fixture secret names (never real) for IdP-enabled synths. */
export const FIXTURE_SECRET_NAMES = {
  apple: 'fixture/idp/apple',
  google: 'fixture/idp/google',
} as const;

/**
 * SES context a prod synth must be given (REQ-PW-7). Fixture values only: `example.com` is
 * reserved (RFC 2606).
 */
export const SES_TEST_CONTEXT = {
  sesFromEmail: 'no-reply@example.com',
  sesVerifiedDomain: 'example.com',
} as const;

/** The context `cdk synth` needs for a stage: SES for prod, nothing for dev. */
export function stageContext(config: StageConfig): Record<string, unknown> {
  return config.stage === 'prod' ? { ...SES_TEST_CONTEXT } : {};
}

/** Stage config with both providers enabled against fixture secret names. */
export function withIdps(stage: StageName = 'dev'): StageConfig {
  return { ...STAGES[stage], enabledIdps: ['apple', 'google'], idpSecretNames: { ...FIXTURE_SECRET_NAMES } };
}

export interface Synth {
  readonly stack: OurloreStack;
  readonly template: Template;
  readonly json: TemplateJson;
}

export interface CfnResource {
  readonly Type: string;
  readonly Properties?: Record<string, any>;
  readonly DependsOn?: string[];
  readonly DeletionPolicy?: string;
  readonly UpdateReplacePolicy?: string;
}

export interface TemplateJson {
  readonly Resources: Record<string, CfnResource>;
  readonly Outputs: Record<string, { Value: unknown }>;
  readonly Parameters?: Record<string, Record<string, any>>;
}

const cache = new Map<string, Synth>();

/**
 * Synthesize a stack. Results are cached per (config, extra props) because synthesis is the
 * slow part and templates are immutable.
 */
export function synth(
  config: StageConfig = STAGES.dev,
  extra: Partial<OurloreStackProps> = {},
  context: Record<string, unknown> = {},
): Synth {
  const key = JSON.stringify({ config, extra, context });
  const hit = cache.get(key);
  if (hit) return hit;
  const app = new App({ context: { ...CDK_CONTEXT, 'ourlore:skipBundling': 'true', ...context } });
  const stack = new OurloreStack(app, `Ourlore-${config.stage}`, { config, ...extra });
  const template = Template.fromStack(stack);
  const result = { stack, template, json: template.toJSON() as TemplateJson };
  cache.set(key, result);
  return result;
}

/** Every resource of a type as [logicalId, resource]. */
export function resourcesOfType(t: TemplateJson, type: string): Array<[string, CfnResource]> {
  return Object.entries(t.Resources).filter(([, r]) => r.Type === type);
}

/** The Lambda function whose handler is `handler` (every contract function's is unique). */
export function functionByHandler(t: TemplateJson, handler: string): [string, CfnResource] {
  const matches = resourcesOfType(t, 'AWS::Lambda::Function').filter(([, r]) => r.Properties?.Handler === handler);
  if (matches.length !== 1) throw new Error(`Expected one function with handler ${handler}, found ${matches.length}`);
  return matches[0];
}

/** Every contract function as [name, spec, kind]. */
export function contractFunctions(c: Contract = CONTRACT): Array<{ name: string; kind: 'group' | 'trigger' | 'worker'; spec: Contract['resource_groups'][string] | Contract['workers'][string] | Contract['cognito_triggers'][string] }> {
  return [
    ...Object.entries(c.resource_groups).map(([name, spec]) => ({ name, kind: 'group' as const, spec })),
    ...Object.entries(c.cognito_triggers).map(([name, spec]) => ({ name, kind: 'trigger' as const, spec })),
    ...Object.entries(c.workers).map(([name, spec]) => ({ name, kind: 'worker' as const, spec })),
  ];
}

/** Role logical id of a function resource. */
export function roleOf(fn: CfnResource): string {
  return fn.Properties?.Role['Fn::GetAtt'][0];
}

/** Every IAM::Policy attached to a role, as [logicalId, resource]. */
export function policiesOfRole(t: TemplateJson, roleId: string): Array<[string, CfnResource]> {
  return resourcesOfType(t, 'AWS::IAM::Policy').filter(([, p]) =>
    (p.Properties?.Roles ?? []).some((r: any) => r.Ref === roleId),
  );
}

/**
 * Canonical key for a policy resource:
 * - `*`
 * - `<LogicalId>` for `Fn::GetAtt [X, Arn]`
 * - `<LogicalId>/index/*`, `<LogicalId>/*` for joins
 * - `secret:<name>-??????` for name-imported secrets
 * - `parameter:<name>` for SSM parameter ARNs (`<name>` may itself be a `Ref:` key)
 */
export function resourceKey(res: unknown): string {
  if (typeof res === 'string') return res;
  const r = res as Record<string, any>;
  if (r['Fn::GetAtt']) return r['Fn::GetAtt'][0];
  if (r.Ref) return `Ref:${r.Ref}`;
  if (r['Fn::Join']) {
    const joined = (r['Fn::Join'][1] as unknown[])
      .map((p) => (typeof p === 'string' ? p : resourceKey(p)))
      .join(r['Fn::Join'][0]);
    const i = joined.indexOf(':secret:');
    if (i >= 0) return `secret:${joined.slice(i + ':secret:'.length)}`;
    // SSM ARNs are `arn:<p>:ssm:<region>:<account>:parameter/<path>`; the path keeps its '/'.
    const j = joined.indexOf(':ssm:');
    const k = joined.indexOf(':parameter', j);
    return j >= 0 && k >= 0 ? `parameter:${joined.slice(k + ':parameter'.length)}` : joined;
  }
  return JSON.stringify(res);
}

/** Flattened (action, resourceKey) grants of a role across all its policies. */
export function grantsOfRole(t: TemplateJson, roleId: string): Set<string> {
  const out = new Set<string>();
  for (const [, p] of policiesOfRole(t, roleId)) {
    for (const s of p.Properties!.PolicyDocument.Statement) {
      expect(s.Effect).toBe('Allow');
      expect(s.NotAction).toBeUndefined();
      expect(s.NotResource).toBeUndefined();
      const actions: string[] = [].concat(s.Action);
      const resources: unknown[] = [].concat(s.Resource);
      for (const a of actions) for (const r of resources) out.add(`${a} ${resourceKey(r)}`);
    }
  }
  return out;
}
