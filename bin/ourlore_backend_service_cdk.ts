#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { OurloreBackendServiceCdkStack } from '../lib/ourlore_backend_service_cdk-stack';

const app = new cdk.App();
new OurloreBackendServiceCdkStack(app, 'OurloreBackendServiceCdkStack', {
  /* Account and region are resolved at synth time from the active AWS CLI
   * profile (e.g. `--profile adminsafe`). Never hardcode an account ID here —
   * this repo is public. */
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
});