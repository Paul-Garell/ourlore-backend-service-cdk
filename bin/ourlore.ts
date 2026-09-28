#!/usr/bin/env node
/**
 * CDK app entrypoint: `npx cdk <cmd> -c stage=dev|prod [--profile <p>]` builds `Ourlore-<stage>`.
 *
 * Account and region come from the active AWS CLI profile at synth time
 * (`CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION`). Without credentials the stack synthesizes
 * environment-agnostic. Never hardcode an account id here: this repo is public.
 *
 * Context:
 * - `stage` (required): `dev` or `prod`
 * - `alarmEmail` (optional): SNS email subscription for alarms
 * - `sesFromEmail`, `sesVerifiedDomain` (required for prod), `sesRegion` (optional): SES
 *   sender for Cognito email; see lib/config/ses.ts
 * - `ourlore:appPath`, `ourlore:skipBundling`: see lib/bundling.ts
 */
import { App } from 'aws-cdk-lib';
import { stageConfig } from '../lib/config/stages';
import { OurloreStack } from '../lib/ourlore-stack';

const app = new App();
const config = stageConfig(app.node.tryGetContext('stage') as string | undefined);
const alarmEmail = app.node.tryGetContext('alarmEmail') as string | undefined;

new OurloreStack(app, `Ourlore-${config.stage}`, {
  config,
  alarmEmail: alarmEmail && alarmEmail.length > 0 ? alarmEmail : undefined,
  description: `Ourlore backend (${config.stage})`,
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },
});
