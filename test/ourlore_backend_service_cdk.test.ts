import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { OurloreBackendServiceCdkStack } from '../lib/ourlore_backend_service_cdk-stack';

describe('OurloreBackendServiceCdkStack', () => {
  test('synthesizes a valid CloudFormation template', () => {
    const app = new cdk.App();
    const stack = new OurloreBackendServiceCdkStack(app, 'TestStack');

    // Template.fromStack throws if the stack fails to synthesize.
    const template = Template.fromStack(stack);

    expect(template.toJSON()).toBeDefined();
  });
});
