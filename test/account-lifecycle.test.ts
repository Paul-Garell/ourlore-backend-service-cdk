/**
 * Account lifecycle (auth_design.md §3.8) and alarms (§3.9).
 */
import { Match } from 'aws-cdk-lib/assertions';
import { CONTRACT, functionByHandler, resourcesOfType, synth } from './helpers';

describe('purge queue and DLQ', () => {
  const { json, template } = synth();

  test('queue: SSE-SQS, 1800 s visibility, 14 d retention, redrive 5 to the DLQ', () => {
    expect(json.Resources.AccountPurgeQueue.Properties).toMatchObject({
      QueueName: 'ourlore-dev-account-purge',
      SqsManagedSseEnabled: true,
      VisibilityTimeout: 1800,
      MessageRetentionPeriod: 14 * 24 * 3600,
      RedrivePolicy: { deadLetterTargetArn: { 'Fn::GetAtt': ['AccountPurgeDlq', 'Arn'] }, maxReceiveCount: 5 },
    });
    expect(json.Resources.AccountPurgeDlq.Properties).toMatchObject({
      QueueName: 'ourlore-dev-account-purge-dlq',
      SqsManagedSseEnabled: true,
      MessageRetentionPeriod: 14 * 24 * 3600,
    });
  });

  test.each(['AccountPurgeQueue', 'AccountPurgeDlq'])('%s enforces TLS', (id) => {
    template.hasResourceProperties('AWS::SQS::QueuePolicy', {
      Queues: [{ Ref: id }],
      PolicyDocument: {
        Statement: Match.arrayWith([
          Match.objectLike({ Effect: 'Deny', Condition: { Bool: { 'aws:SecureTransport': 'false' } } }),
        ]),
      },
    });
  });
});

describe('workers', () => {
  const { json } = synth();

  test('purge worker: SQS event source, batch 1, partial batch failures', () => {
    const [fnId] = functionByHandler(json, CONTRACT.workers.account_purge.handler);
    const esm = resourcesOfType(json, 'AWS::Lambda::EventSourceMapping');
    expect(esm).toHaveLength(1);
    expect(esm[0][1].Properties).toMatchObject({
      EventSourceArn: { 'Fn::GetAtt': ['AccountPurgeQueue', 'Arn'] },
      FunctionName: { Ref: fnId },
      BatchSize: 1,
      FunctionResponseTypes: ['ReportBatchItemFailures'],
    });
  });

  test('maintenance: EventBridge rate(5 minutes)', () => {
    const [fnId] = functionByHandler(json, CONTRACT.workers.maintenance.handler);
    const rules = resourcesOfType(json, 'AWS::Events::Rule');
    expect(rules).toHaveLength(1);
    expect(rules[0][1].Properties).toMatchObject({
      ScheduleExpression: 'rate(5 minutes)',
      State: 'ENABLED',
      Targets: [expect.objectContaining({ Arn: { 'Fn::GetAtt': [fnId, 'Arn'] } })],
    });
  });
});

describe('alarms', () => {
  const { json, template } = synth();
  const alarms: Record<string, Record<string, any>> = Object.fromEntries(
    resourcesOfType(json, 'AWS::CloudWatch::Alarm').map(([, a]) => [a.Properties!.AlarmName, a.Properties!]),
  );
  const [topicId] = resourcesOfType(json, 'AWS::SNS::Topic')[0];

  test('SNS topic ourlore-<stage>-alarms; no subscription without alarmEmail', () => {
    template.hasResourceProperties('AWS::SNS::Topic', { TopicName: 'ourlore-dev-alarms' });
    template.resourceCountIs('AWS::SNS::Subscription', 0);
  });

  test('email subscription when alarmEmail is set', () => {
    synth(undefined, { alarmEmail: 'ops@example.com' }).template.hasResourceProperties('AWS::SNS::Subscription', {
      Protocol: 'email',
      Endpoint: 'ops@example.com',
    });
  });

  test('every alarm notifies the topic', () => {
    expect(Object.keys(alarms)).toHaveLength(9);
    for (const a of Object.values(alarms)) expect(a.AlarmActions).toEqual([{ Ref: topicId }]);
  });

  test('DLQ depth > 0', () => {
    expect(alarms['ourlore-dev-account-purge-dlq-not-empty']).toMatchObject({
      Namespace: 'AWS/SQS',
      MetricName: 'ApproximateNumberOfMessagesVisible',
      Dimensions: [{ Name: 'QueueName', Value: { 'Fn::GetAtt': ['AccountPurgeDlq', 'QueueName'] } }],
      Threshold: 0,
      ComparisonOperator: 'GreaterThanThreshold',
    });
  });

  test.each([
    ['account', CONTRACT.resource_groups.account.handler],
    ['users', CONTRACT.resource_groups.users.handler],
    ['account-purge', CONTRACT.workers.account_purge.handler],
    ['maintenance', CONTRACT.workers.maintenance.handler],
  ])('%s Errors >= 3 over 5 min', (name, handler) => {
    const [fnId] = functionByHandler(json, handler);
    expect(alarms[`ourlore-dev-${name}-errors`]).toMatchObject({
      Namespace: 'AWS/Lambda',
      MetricName: 'Errors',
      Dimensions: [{ Name: 'FunctionName', Value: { Ref: fnId } }],
      Statistic: 'Sum',
      Period: 300,
      Threshold: 3,
      ComparisonOperator: 'GreaterThanOrEqualToThreshold',
    });
  });

  test('API 5xx >= 10 over 5 min', () => {
    expect(alarms['ourlore-dev-api-5xx']).toMatchObject({
      Namespace: 'AWS/ApiGateway',
      MetricName: '5xx',
      Statistic: 'Sum',
      Period: 300,
      Threshold: 10,
      ComparisonOperator: 'GreaterThanOrEqualToThreshold',
    });
  });

  test('custom metrics are dimensionless; missing data is not breaching', () => {
    expect(alarms['ourlore-dev-oldest-pending-deletion']).toMatchObject({
      Namespace: 'Ourlore',
      MetricName: 'OldestPendingDeletionAgeSeconds',
      Threshold: 21600,
      ComparisonOperator: 'GreaterThanThreshold',
      TreatMissingData: 'notBreaching',
    });
    expect(alarms['ourlore-dev-pre-sign-up-check-skipped']).toMatchObject({
      Namespace: 'Ourlore',
      MetricName: 'PreSignUpCheckSkipped',
      Statistic: 'Sum',
      Period: 3600,
      Threshold: 5,
      ComparisonOperator: 'GreaterThanOrEqualToThreshold',
      TreatMissingData: 'notBreaching',
    });
    expect(alarms['ourlore-dev-purge-throttled']).toMatchObject({
      Namespace: 'Ourlore',
      MetricName: 'PurgeThrottled',
      Statistic: 'Sum',
      Period: 3600,
      Threshold: 20,
      ComparisonOperator: 'GreaterThanOrEqualToThreshold',
      TreatMissingData: 'notBreaching',
    });
    expect(alarms['ourlore-dev-purge-throttled'].AlarmDescription).toMatch(/^WARNING/);
    expect(alarms['ourlore-dev-oldest-pending-deletion'].Dimensions).toBeUndefined();
    expect(alarms['ourlore-dev-pre-sign-up-check-skipped'].Dimensions).toBeUndefined();
    expect(alarms['ourlore-dev-purge-throttled'].Dimensions).toBeUndefined();
  });
});
