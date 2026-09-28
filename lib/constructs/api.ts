/**
 * HTTP API (auth_design.md §3.7, REQ-ID-2, REQ-OPS-1/4, D-12).
 *
 * - No CORS: native clients only.
 * - JWT authorizer (issuer = this pool, audience = the iOS client). Every `auth: true` route
 *   also requires the route's `authorizationScopes` (`aws.cognito.signin.user.admin`), which
 *   ID tokens lack, so they get 403 at the edge.
 * - `auth: false` routes (AUTH-5 only) get an explicit `HttpNoneAuthorizer`.
 * - One Lambda per resource group, from the contract.
 * - `$default` stage with auto-deploy, a default throttle, per-route throttles, and JSON
 *   access logs without headers.
 */
import { RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigateway';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpJwtAuthorizer } from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import { Contract, HttpMethodName, allRoutes, routeKey } from '../contract';
import type { StageConfig } from '../config/stages';
import { pascal } from './account-lifecycle';
import { ContractBindings, ContractFunction, retentionFor } from './contract-function';

const METHODS: Readonly<Record<HttpMethodName, apigwv2.HttpMethod>> = {
  GET: apigwv2.HttpMethod.GET,
  POST: apigwv2.HttpMethod.POST,
  PUT: apigwv2.HttpMethod.PUT,
  PATCH: apigwv2.HttpMethod.PATCH,
  DELETE: apigwv2.HttpMethod.DELETE,
};

/**
 * Access-log fields (REQ-OPS-4). Deliberately no headers, so `Authorization` is never logged.
 */
export const ACCESS_LOG_FORMAT: Readonly<Record<string, string>> = {
  requestId: '$context.requestId',
  routeKey: '$context.routeKey',
  status: '$context.status',
  responseLatency: '$context.responseLatency',
  integrationError: '$context.integrationErrorMessage',
  sub: '$context.authorizer.claims.sub',
  sourceIp: '$context.identity.sourceIp',
};

export interface ApiProps {
  readonly config: StageConfig;
  readonly contract: Contract;
  readonly bindings: ContractBindings;
  readonly code: lambda.Code;
  readonly userPool: cognito.IUserPool;
  readonly client: cognito.IUserPoolClient;
}

/** HTTP API, authorizer, routes, and the per-group functions. */
export class Api extends Construct {
  readonly httpApi: apigwv2.HttpApi;
  readonly stage: apigwv2.HttpStage;
  readonly accessLogs: logs.LogGroup;
  /** Group functions by contract group name. */
  readonly functions: Readonly<Record<string, ContractFunction>>;

  constructor(scope: Construct, id: string, props: ApiProps) {
    super(scope, id);
    const { config, contract, bindings } = props;
    const prod = config.stage === 'prod';
    const removal = prod ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;

    this.httpApi = new apigwv2.HttpApi(this, 'HttpApi', {
      apiName: `ourlore-${config.stage}`,
      description: `Ourlore API (${config.stage})`,
      createDefaultStage: false,
      // No corsPreflight: native clients only.
    });

    this.accessLogs = new logs.LogGroup(this, 'AccessLogs', {
      retention: retentionFor(config.logRetentionDays),
      removalPolicy: removal,
    });

    this.stage = new apigwv2.HttpStage(this, 'DefaultStage', {
      httpApi: this.httpApi,
      stageName: '$default',
      autoDeploy: true,
      throttle: { rateLimit: config.throttle.default.rate, burstLimit: config.throttle.default.burst },
      accessLogSettings: {
        destination: new apigwv2.LogGroupLogDestination(this.accessLogs),
        format: apigw.AccessLogFormat.custom(JSON.stringify(ACCESS_LOG_FORMAT)),
      },
    });

    const issuer = `https://cognito-idp.${Stack.of(this).region}.amazonaws.com/${props.userPool.userPoolId}`;
    const jwt = new HttpJwtAuthorizer('CognitoJwt', issuer, {
      authorizerName: 'cognito-jwt',
      jwtAudience: [props.client.userPoolClientId],
      identitySource: ['$request.header.Authorization'],
    });
    const none = new apigwv2.HttpNoneAuthorizer();

    // One function + integration per resource group.
    const functions: Record<string, ContractFunction> = {};
    const integrations: Record<string, HttpLambdaIntegration> = {};
    for (const [group, spec] of Object.entries(contract.resource_groups)) {
      const fn = new ContractFunction(this, `${pascal(group)}Group`, {
        spec,
        bindings,
        code: props.code,
        serviceName: `ourlore-${group}`,
        logLevel: config.logLevel,
        logRetentionDays: config.logRetentionDays,
        logRemovalPolicy: removal,
        description: `Ourlore API resource group: ${group}`,
      });
      functions[group] = fn;
      integrations[group] = new HttpLambdaIntegration(`${pascal(group)}Integration`, fn.function);
    }
    this.functions = functions;

    // Routes (validated by the contract loader: known methods, no duplicates).
    const routesByKey = new Map<string, apigwv2.HttpRoute>();
    for (const r of allRoutes(contract)) {
      const [route] = this.httpApi.addRoutes({
        path: r.path,
        methods: [METHODS[r.method]],
        integration: integrations[r.group],
        authorizer: r.auth ? jwt : none,
        authorizationScopes: r.auth ? [...r.scopes] : undefined,
      });
      routesByKey.set(routeKey(r), route);
    }

    // Per-route throttles (REQ-OPS-1). The stage must be created after these routes exist,
    // or API Gateway rejects the RouteSettings.
    const cfnStage = this.stage.node.defaultChild as apigwv2.CfnStage;
    // `RouteSettings` is a JSON-typed map in CloudFormation, so CDK does not rename keys:
    // they must be written in CloudFormation's PascalCase.
    const routeSettings: Record<string, { ThrottlingRateLimit: number; ThrottlingBurstLimit: number }> = {};
    for (const [key, t] of Object.entries(config.throttle.routes)) {
      const route = routesByKey.get(key);
      if (!route) throw new Error(`Throttle configured for '${key}', which is not a contract route.`);
      routeSettings[key] = { ThrottlingRateLimit: t.rate, ThrottlingBurstLimit: t.burst };
      this.stage.node.addDependency(route);
    }
    cfnStage.routeSettings = routeSettings;
  }
}
