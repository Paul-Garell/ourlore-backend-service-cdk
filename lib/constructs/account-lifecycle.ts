/**
 * Account lifecycle (auth_design.md §3.8, REQ-DEL-4/6/10): purge queue + DLQ, the purge
 * worker, and the scheduled maintenance function.
 *
 * Only these two functions hold Cognito admin actions (D-11). Both are defined by the
 * contract's `workers` section, including their event sources.
 */
import { Duration, RemovalPolicy } from 'aws-cdk-lib';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import type { Contract, WorkerSpec } from '../contract';
import type { StageConfig } from '../config/stages';
import { ContractBindings, ContractFunction } from './contract-function';

export const PURGE_QUEUE_LOGICAL_ID = 'AccountPurgeQueue';
export const PURGE_DLQ_LOGICAL_ID = 'AccountPurgeDlq';

/** Contract logical names of the queues this construct owns. */
export const PURGE_QUEUE = 'account_purge';
export const PURGE_DLQ = 'account_purge_dlq';

export interface AccountLifecycleQueuesProps {
  readonly config: StageConfig;
  readonly bindings: ContractBindings;
}

/** The purge queue and its DLQ. Created before the API so ACC-1 can send to it. */
export class AccountLifecycleQueues extends Construct {
  readonly queue: sqs.Queue;
  readonly dlq: sqs.Queue;

  constructor(scope: Construct, id: string, props: AccountLifecycleQueuesProps) {
    super(scope, id);
    const { config, bindings } = props;

    this.dlq = new sqs.Queue(this, 'Dlq', {
      queueName: `ourlore-${config.stage}-account-purge-dlq`,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
    });
    (this.dlq.node.defaultChild as sqs.CfnQueue).overrideLogicalId(PURGE_DLQ_LOGICAL_ID);

    this.queue = new sqs.Queue(this, 'Queue', {
      queueName: `ourlore-${config.stage}-account-purge`,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      // Must exceed the worker timeout (300 s) with margin for retries.
      visibilityTimeout: Duration.seconds(1800),
      retentionPeriod: Duration.days(14),
      deadLetterQueue: { queue: this.dlq, maxReceiveCount: 5 },
    });
    (this.queue.node.defaultChild as sqs.CfnQueue).overrideLogicalId(PURGE_QUEUE_LOGICAL_ID);

    bindings.addQueue(PURGE_QUEUE, this.queue);
    bindings.addQueue(PURGE_DLQ, this.dlq);
  }
}

export interface AccountLifecycleWorkersProps {
  readonly config: StageConfig;
  readonly contract: Contract;
  readonly bindings: ContractBindings;
  readonly code: lambda.Code;
}

/** Purge worker (SQS) and maintenance (EventBridge schedule), from `contract.workers`. */
export class AccountLifecycleWorkers extends Construct {
  /** Worker functions by contract name (`account_purge`, `maintenance`). */
  readonly functions: Readonly<Record<string, ContractFunction>>;

  constructor(scope: Construct, id: string, props: AccountLifecycleWorkersProps) {
    super(scope, id);
    const { config, contract, bindings } = props;
    const prod = config.stage === 'prod';
    const functions: Record<string, ContractFunction> = {};

    for (const [name, spec] of Object.entries(contract.workers) as Array<[string, WorkerSpec]>) {
      const fn = new ContractFunction(this, pascal(name), {
        spec,
        bindings,
        code: props.code,
        serviceName: `ourlore-${name.replace(/_/g, '-')}`,
        logLevel: config.logLevel,
        logRetentionDays: config.logRetentionDays,
        logRemovalPolicy: prod ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY,
        description: `Ourlore worker: ${name}`,
      });
      const es = spec.event_source;
      if (es.type === 'sqs') {
        // Grants the receive/delete actions the event source mapping itself needs.
        fn.function.addEventSource(
          new sources.SqsEventSource(bindings.queue(es.queue), {
            batchSize: es.batch_size,
            reportBatchItemFailures: es.report_batch_item_failures,
          }),
        );
      } else {
        new events.Rule(this, `${pascal(name)}Schedule`, {
          description: `Ourlore ${name} schedule`,
          schedule: events.Schedule.expression(es.expression),
          targets: [new targets.LambdaFunction(fn.function, { retryAttempts: 2 })],
        });
      }
      functions[name] = fn;
    }
    this.functions = functions;
  }
}

/** `account_purge` → `AccountPurge`. */
export function pascal(name: string): string {
  return name
    .split(/[_-]/)
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join('');
}
