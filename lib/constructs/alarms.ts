/**
 * Alarms (auth_design.md §3.9, REQ-OPS-5, REQ-DEL-10).
 *
 * Custom metrics (`Ourlore/*`) are emitted by the backend as dimensionless EMF, so the alarms
 * here use no dimensions. One AWS account per stage keeps them unambiguous.
 */
import { Duration } from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { Construct } from 'constructs';
import type { StageConfig } from '../config/stages';

export const METRIC_NAMESPACE = 'Ourlore';

export interface AlarmsProps {
  readonly config: StageConfig;
  /** From `-c alarmEmail=...`; never committed. */
  readonly alarmEmail?: string;
  readonly dlq: sqs.IQueue;
  readonly httpApi: apigwv2.IHttpApi;
  /** Functions with an `Errors` alarm, keyed by kebab-case name (used in the alarm name). */
  readonly errorFunctions: Readonly<Record<string, lambda.IFunction>>;
}

/** SNS topic plus every alarm. */
export class Alarms extends Construct {
  readonly topic: sns.Topic;

  constructor(scope: Construct, id: string, props: AlarmsProps) {
    super(scope, id);
    const { config } = props;
    const prefix = `ourlore-${config.stage}`;

    this.topic = new sns.Topic(this, 'Topic', {
      topicName: `${prefix}-alarms`,
      displayName: `Ourlore ${config.stage} alarms`,
      enforceSSL: true,
    });
    if (props.alarmEmail) {
      this.topic.addSubscription(new subs.EmailSubscription(props.alarmEmail));
    }
    const action = new actions.SnsAction(this.topic);
    const add = (alarm: cloudwatch.Alarm): void => {
      alarm.addAlarmAction(action);
    };
    const fiveMin = Duration.minutes(5);

    add(
      new cloudwatch.Alarm(this, 'PurgeDlqNotEmpty', {
        alarmName: `${prefix}-account-purge-dlq-not-empty`,
        alarmDescription: 'Account purge jobs exhausted their retries (REQ-DEL-10).',
        metric: props.dlq.metricApproximateNumberOfMessagesVisible({ period: fiveMin, statistic: 'Maximum' }),
        threshold: 0,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    );

    for (const [name, fn] of Object.entries(props.errorFunctions)) {
      add(
        new cloudwatch.Alarm(this, `${name.replace(/(^|-)(.)/g, (_m, _d, c: string) => c.toUpperCase())}Errors`, {
          alarmName: `${prefix}-${name}-errors`,
          alarmDescription: `Lambda errors on ${name}.`,
          metric: fn.metricErrors({ period: fiveMin, statistic: 'Sum' }),
          threshold: 3,
          comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
          evaluationPeriods: 1,
          treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
        }),
      );
    }

    add(
      new cloudwatch.Alarm(this, 'Api5xx', {
        alarmName: `${prefix}-api-5xx`,
        alarmDescription: 'HTTP API 5xx responses.',
        metric: props.httpApi.metricServerError({ period: fiveMin, statistic: 'Sum' }),
        threshold: 10,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    );

    add(
      new cloudwatch.Alarm(this, 'OldestPendingDeletion', {
        alarmName: `${prefix}-oldest-pending-deletion`,
        alarmDescription: 'A deletion job is older than 6 hours (REQ-DEL-10).',
        metric: new cloudwatch.Metric({
          namespace: METRIC_NAMESPACE,
          metricName: 'OldestPendingDeletionAgeSeconds',
          period: fiveMin,
          statistic: 'Maximum',
        }),
        threshold: 21600,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    );

    add(
      new cloudwatch.Alarm(this, 'PreSignUpCheckSkipped', {
        alarmName: `${prefix}-pre-sign-up-check-skipped`,
        alarmDescription:
          'WARNING (not an outage): the pre-sign-up duplicate-email check failed open >= 5 times in 1 hour.',
        metric: new cloudwatch.Metric({
          namespace: METRIC_NAMESPACE,
          metricName: 'PreSignUpCheckSkipped',
          period: Duration.hours(1),
          statistic: 'Sum',
        }),
        threshold: 5,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    );
  }
}
