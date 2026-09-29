/**
 * HTTP API, routes, authorizers, throttles, access logs, and group functions (auth_design.md
 * §3.7, REQ-ID-2, REQ-OPS-1/4, D-12, REQ-Q-1 route/authorizer contract test).
 */
import { ACC1_ROUTE_KEY, AUTH5_ROUTE_KEY, STAGES, USR3_ROUTE_KEY } from '../lib/config/stages';
import { allRoutes, routeKey } from '../lib/contract';
import { CONTRACT, CfnResource, SES_TEST_CONTEXT, contractFunctions, functionByHandler, resourcesOfType, synth } from './helpers';

describe('HTTP API', () => {
  const { json, template } = synth();
  const routes: Record<string, { id: string; r: CfnResource }> = Object.fromEntries(
    resourcesOfType(json, 'AWS::ApiGatewayV2::Route').map(([id, r]) => [r.Properties!.RouteKey, { id, r }]),
  );
  const [authorizerId, authorizer] = resourcesOfType(json, 'AWS::ApiGatewayV2::Authorizer')[0];

  test('one HTTP API without CORS', () => {
    template.resourceCountIs('AWS::ApiGatewayV2::Api', 1);
    template.hasResourceProperties('AWS::ApiGatewayV2::Api', { ProtocolType: 'HTTP' });
    const [, api] = resourcesOfType(json, 'AWS::ApiGatewayV2::Api')[0];
    expect(api.Properties!.CorsConfiguration).toBeUndefined();
  });

  test('JWT authorizer: this pool as issuer, the iOS client as audience', () => {
    template.resourceCountIs('AWS::ApiGatewayV2::Authorizer', 1);
    expect(authorizer.Properties).toMatchObject({
      AuthorizerType: 'JWT',
      IdentitySource: ['$request.header.Authorization'],
      JwtConfiguration: {
        Audience: [{ Ref: 'UserPoolClientIos' }],
        Issuer: { 'Fn::Join': ['', ['https://cognito-idp.', { Ref: 'AWS::Region' }, '.amazonaws.com/', { Ref: 'UserPool' }]] },
      },
    });
  });

  test('exactly the contract routes exist', () => {
    expect(Object.keys(routes).sort()).toEqual(allRoutes(CONTRACT).map(routeKey).sort());
  });

  test.each(allRoutes(CONTRACT).map((r) => [routeKey(r), r]))('%s: authorizer and scopes match the contract', (_k, r) => {
    const { r: route } = routes[routeKey(r)];
    if (r.auth) {
      expect(route.Properties!.AuthorizationType).toBe('JWT');
      expect(route.Properties!.AuthorizerId).toEqual({ Ref: authorizerId });
      expect(route.Properties!.AuthorizationScopes).toEqual(['aws.cognito.signin.user.admin']);
      expect(route.Properties!.AuthorizationScopes).toEqual(r.scopes);
    } else {
      expect(route.Properties!.AuthorizationType).toBe('NONE');
      expect(route.Properties!.AuthorizerId).toBeUndefined();
      expect(route.Properties!.AuthorizationScopes).toBeUndefined();
    }
  });

  test('AUTH-5 is the only NONE route', () => {
    const none = Object.entries(routes).filter(([, { r }]) => r.Properties!.AuthorizationType !== 'JWT').map(([k]) => k);
    expect(none).toEqual([AUTH5_ROUTE_KEY]);
  });

  test('each route targets its group integration, which targets its group function', () => {
    for (const r of allRoutes(CONTRACT)) {
      const { r: route } = routes[routeKey(r)];
      const integrationId = route.Properties!.Target['Fn::Join'][1][1].Ref;
      const integration = json.Resources[integrationId];
      expect(integration.Properties!.IntegrationType).toBe('AWS_PROXY');
      expect(integration.Properties!.PayloadFormatVersion).toBe('2.0');
      const [fnId] = functionByHandler(json, CONTRACT.resource_groups[r.group].handler);
      expect(integration.Properties!.IntegrationUri).toEqual({ 'Fn::GetAtt': [fnId, 'Arn'] });
    }
  });
});

describe('stage: throttles and access logs (REQ-OPS-1/4)', () => {
  const { json } = synth();
  const [, stage] = resourcesOfType(json, 'AWS::ApiGatewayV2::Stage')[0];

  test('$default with auto-deploy and the default throttle', () => {
    expect(resourcesOfType(json, 'AWS::ApiGatewayV2::Stage')).toHaveLength(1);
    expect(stage.Properties).toMatchObject({
      StageName: '$default',
      AutoDeploy: true,
      DefaultRouteSettings: { ThrottlingRateLimit: 50, ThrottlingBurstLimit: 100 },
    });
  });

  test('per-route throttles for AUTH-5, ACC-1, and USR-3, and the stage waits for those routes', () => {
    expect(stage.Properties!.RouteSettings).toEqual({
      [AUTH5_ROUTE_KEY]: { ThrottlingRateLimit: 10, ThrottlingBurstLimit: 20 },
      [ACC1_ROUTE_KEY]: { ThrottlingRateLimit: 2, ThrottlingBurstLimit: 5 },
      [USR3_ROUTE_KEY]: { ThrottlingRateLimit: 10, ThrottlingBurstLimit: 20 },
    });
    const throttled = [AUTH5_ROUTE_KEY, ACC1_ROUTE_KEY, USR3_ROUTE_KEY];
    const routeIds = resourcesOfType(json, 'AWS::ApiGatewayV2::Route')
      .filter(([, r]) => throttled.includes(r.Properties!.RouteKey))
      .map(([id]) => id);
    expect(routeIds).toHaveLength(throttled.length);
    for (const id of routeIds) expect(stage.DependsOn).toContain(id);
  });

  test('USR-3 (GET /v1/users) gets the AUTH-5 throttle in every stage (A-15)', () => {
    expect(USR3_ROUTE_KEY).toBe('GET /v1/users');
    for (const cfg of Object.values(STAGES)) {
      expect(cfg.throttle.routes[USR3_ROUTE_KEY]).toEqual({ rate: 10, burst: 20 });
      expect(cfg.throttle.routes[USR3_ROUTE_KEY]).toEqual(cfg.throttle.routes[AUTH5_ROUTE_KEY]);
    }
  });

  test('a throttle for a non-contract route fails synth', () => {
    const cfg = { ...STAGES.dev, throttle: { ...STAGES.dev.throttle, routes: { 'GET /nope': { rate: 1, burst: 1 } } } };
    expect(() => synth(cfg)).toThrow(/not a contract route/);
  });

  test('JSON access log with exactly the approved fields and no headers', () => {
    const format = JSON.parse(stage.Properties!.AccessLogSettings.Format);
    expect(format).toEqual({
      requestId: '$context.requestId',
      routeKey: '$context.routeKey',
      status: '$context.status',
      responseLatency: '$context.responseLatency',
      integrationError: '$context.integrationErrorMessage',
      sub: '$context.authorizer.claims.sub',
      sourceIp: '$context.identity.sourceIp',
    });
    expect(stage.Properties!.AccessLogSettings.Format).not.toMatch(/header|authorization/i);
    const logGroupId = stage.Properties!.AccessLogSettings.DestinationArn['Fn::GetAtt'][0];
    expect(json.Resources[logGroupId].Properties!.RetentionInDays).toBe(14);
  });
});

describe('functions (every group, trigger, worker)', () => {
  const { json } = synth();

  test.each(contractFunctions().map((f) => [f.name, f]))('%s: runtime, arch, memory, timeout, X-Ray, log group, env', (_n, f) => {
    const [, fn] = functionByHandler(json, f.spec.handler);
    const p = fn.Properties!;
    expect(p.Runtime).toBe(CONTRACT.runtime.runtime);
    expect(p.Architectures).toEqual([CONTRACT.runtime.architecture]);
    expect(p.MemorySize).toBe(f.spec.memory_mb);
    expect(p.Timeout).toBe(f.spec.timeout_seconds);
    expect(p.TracingConfig).toEqual({ Mode: 'Active' });
    const logGroupId = p.LoggingConfig.LogGroup.Ref;
    expect(json.Resources[logGroupId].Type).toBe('AWS::Logs::LogGroup');
    expect(json.Resources[logGroupId].Properties!.RetentionInDays).toBe(14);
    // env is exactly the declared names.
    expect(Object.keys(p.Environment.Variables).sort()).toEqual([...f.spec.env].sort());
    expect(p.Environment.Variables.POWERTOOLS_SERVICE_NAME).toBe(`ourlore-${f.name.replace(/_/g, '-')}`);
  });

  test('10 functions: 6 groups, 2 triggers, 2 workers', () => {
    expect(resourcesOfType(json, 'AWS::Lambda::Function')).toHaveLength(contractFunctions().length);
    expect(contractFunctions()).toHaveLength(10);
  });

  test('deferred env vars are exactly MEDIA_CDN_DOMAIN and are ""', () => {
    expect(CONTRACT.deferred_env_vars).toEqual(['MEDIA_CDN_DOMAIN']);
    for (const f of contractFunctions()) {
      const [, fn] = functionByHandler(json, f.spec.handler);
      for (const name of CONTRACT.deferred_env_vars) {
        if (f.spec.env.includes(name)) expect(fn.Properties!.Environment.Variables[name]).toBe('');
      }
    }
  });

  test('COGNITO_USER_POOL_ID only on purge and maintenance', () => {
    const holders = contractFunctions()
      .filter((f) => 'COGNITO_USER_POOL_ID' in functionByHandler(json, f.spec.handler)[1].Properties!.Environment.Variables)
      .map((f) => f.name)
      .sort();
    expect(holders).toEqual(['account_purge', 'maintenance']);
  });

  test('account function: 20 s timeout and the stage purge delay (§4.3)', () => {
    const [, dev] = functionByHandler(json, CONTRACT.resource_groups.account.handler);
    expect(dev.Properties!.Timeout).toBe(20);
    expect(dev.Properties!.Environment.Variables.PURGE_DELAY_SECONDS).toBe('120');
    const prod = synth(STAGES.prod, {}, SES_TEST_CONTEXT).json;
    const [, prodFn] = functionByHandler(prod, CONTRACT.resource_groups.account.handler);
    expect(prodFn.Properties!.Environment.Variables.PURGE_DELAY_SECONDS).toBe('960');
  });

  test('PURGE_DELAY_SECONDS reaches only the account function', () => {
    const holders = contractFunctions()
      .filter((f) => 'PURGE_DELAY_SECONDS' in functionByHandler(json, f.spec.handler)[1].Properties!.Environment.Variables)
      .map((f) => f.name);
    expect(holders).toEqual(['account']);
  });

  test('prod log retention is 90 days', () => {
    const prod = synth(STAGES.prod, {}, SES_TEST_CONTEXT).json;
    for (const [, lg] of resourcesOfType(prod, 'AWS::Logs::LogGroup')) expect(lg.Properties!.RetentionInDays).toBe(90);
  });
});
