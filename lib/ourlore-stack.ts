/**
 * `Ourlore-<stage>`: the whole backend for one stage (auth_design.md D-8, §3).
 *
 * One stack with a construct per concern. Stateful resources use `RETAIN` and pinned logical
 * ids, so the stack can be split later without replacing data.
 */
import { CfnOutput, Stack, StackProps, Tags } from 'aws-cdk-lib';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { Contract, loadContract } from './contract';
import { sharedLambdaCode } from './bundling';
import { sesConfigFromContext, validateSesConfig } from './config/ses';
import { IdpDefinition, defaultIdpSecretName } from './config/identity-providers';
import { StageConfig, validateStageConfig } from './config/stages';
import { AccountLifecycleQueues, AccountLifecycleWorkers } from './constructs/account-lifecycle';
import { Alarms } from './constructs/alarms';
import { Api } from './constructs/api';
import { Auth, OAUTH_SCOPES } from './constructs/auth';
import { ContractBindings } from './constructs/contract-function';
import { Data } from './constructs/data';

export interface OurloreStackProps extends StackProps {
  readonly config: StageConfig;
  /** Defaults to the vendored `contract.json`. */
  readonly contract?: Contract;
  /** Defaults to the committed IdP registry. Tests may inject one. */
  readonly registry?: Readonly<Record<string, IdpDefinition>>;
  /** Alarm email from context; never committed. */
  readonly alarmEmail?: string;
}

/** The Ourlore backend stack. */
export class OurloreStack extends Stack {
  readonly data: Data;
  readonly auth: Auth;
  readonly queues: AccountLifecycleQueues;
  readonly workers: AccountLifecycleWorkers;
  readonly api: Api;
  readonly alarms: Alarms;

  constructor(scope: Construct, id: string, props: OurloreStackProps) {
    super(scope, id, { ...props, terminationProtection: props.config.terminationProtection });
    // SES sender (REQ-PW-7): an explicit config wins (tests); otherwise prod reads it from
    // context and fails synth without it. dev uses the Cognito default sender.
    const ses = props.config.ses
      ? validateSesConfig(props.config.ses)
      : sesConfigFromContext(props.config.stage, (key) => this.node.tryGetContext(key));
    const config: StageConfig = validateStageConfig({ ...props.config, ses });
    const contract = props.contract ?? loadContract();
    Tags.of(this).add('ourlore:stage', config.stage);

    const bindings = new ContractBindings(contract);
    // ACC-1: purgeNotBefore = requestedAt + PURGE_DELAY_SECONDS (auth_design.md §4.3).
    bindings.setEnv('PURGE_DELAY_SECONDS', String(config.purgeDelaySeconds));
    const code = sharedLambdaCode(this);

    // Data
    this.data = new Data(this, 'Data', { config, contract });
    for (const [logical, table] of Object.entries(this.data.tables)) bindings.addTable(logical, table);
    bindings.addBucket('media', this.data.mediaBucket);
    bindings.addParameter('cursor_key', this.data.cursorKey);

    // Apple credentials: operator-created; bound only when Apple is enabled, otherwise
    // APPLE_SECRET_ARN is "" and no grant is made (§2).
    const appleName = config.idpSecretNames?.apple ?? defaultIdpSecretName(config.stage, 'apple');
    bindings.addSecret(
      'apple',
      config.enabledIdps.includes('apple')
        ? secretsmanager.Secret.fromSecretNameV2(this, 'AppleIdpSecret', appleName)
        : null,
    );

    // Identity
    this.auth = new Auth(this, 'Auth', { config, contract, bindings, code, registry: props.registry });

    // Account lifecycle: queues before the API (ACC-1 sends to it), workers after identity.
    this.queues = new AccountLifecycleQueues(this, 'AccountLifecycle', { config, bindings });
    this.workers = new AccountLifecycleWorkers(this, 'AccountLifecycleWorkers', { config, contract, bindings, code });

    // API
    this.api = new Api(this, 'Api', {
      config,
      contract,
      bindings,
      code,
      userPool: this.auth.userPool,
      client: this.auth.client,
    });

    // Alarms
    this.alarms = new Alarms(this, 'Alarms', {
      config,
      alarmEmail: props.alarmEmail,
      dlq: this.queues.dlq,
      httpApi: this.api.httpApi,
      errorFunctions: {
        account: this.api.functions.account.function,
        users: this.api.functions.users.function,
        'account-purge': this.workers.functions.account_purge.function,
        maintenance: this.workers.functions.maintenance.function,
      },
      postConfirmationFunction: this.auth.postConfirmation.function,
    });

    // Outputs (§3.10). List values are JSON arrays so scripts can parse them unambiguously.
    const out = (id: string, value: string, description: string): void => {
      new CfnOutput(this, id, { value, description });
    };
    out('Region', this.region, 'AWS region');
    out('UserPoolId', this.auth.userPool.userPoolId, 'Cognito user pool id');
    out('UserPoolClientId', this.auth.client.userPoolClientId, 'iOS app client id');
    out('CognitoDomain', this.auth.domainHost, 'Cognito OAuth domain host');
    out('ApiEndpoint', this.api.httpApi.apiEndpoint, 'HTTP API endpoint');
    out('EnabledIdps', JSON.stringify(this.auth.enabledIdps.map((d) => d.id)), 'Enabled IdP ids (JSON)');
    out('CallbackUrls', JSON.stringify(config.callbackUrls), 'OAuth callback URLs (JSON)');
    out('LogoutUrls', JSON.stringify(config.logoutUrls), 'OAuth sign-out URLs (JSON)');
    out('OAuthScopes', JSON.stringify(OAUTH_SCOPES.map((s) => s.scopeName)), 'OAuth scopes of the iOS client (JSON)');
    out('PreSignUpLogGroup', this.auth.preSignUp.logGroup.logGroupName, 'Pre-sign-up log group (E2E step 11)');
    out(
      'PostConfirmationFunctionArn',
      this.auth.postConfirmation.function.functionArn,
      'Post-confirmation trigger function (E2E step 12 checks the pool is wired to it)',
    );
  }
}
