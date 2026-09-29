# Ourlore Backend Service CDK

AWS CDK (TypeScript) infrastructure for the Ourlore backend: one stack per stage
(`Ourlore-dev`, `Ourlore-prod`) with Cognito, the HTTP API, the per-group Lambdas,
DynamoDB, the media bucket, the account-deletion pipeline, and alarms. The design is
`../OurloreBackendService/docs/auth_design.md` §3; this README covers operating it.

## Prerequisites

- [Node.js 24 LTS](https://nodejs.org/) (see `.nvmrc`)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) with a configured profile (IAM Identity Center/SSO recommended)
- `python3` with `pip` on `PATH` (Lambda bundling, below)
- The app repo checked out next to this one (`../OurloreBackendService`), or `-c ourlore:appPath=<path>`
- [gitleaks](https://github.com/gitleaks/gitleaks), required by the pre-commit hook (`brew install gitleaks`)

## Getting started

```bash
npm install          # also installs the git hooks via husky
npm run build
npm test             # bundling is skipped in tests
npx cdk synth -c stage=dev -c ourlore:skipBundling=true -q   # fast synth, placeholder code
npx cdk synth -c stage=dev -q                                  # real bundling
```

Pinned toolchain: `aws-cdk-lib` 2.271.0, `aws-cdk` 2.1143.0, `constructs` 10.8.1.

## Layout

| Path | Purpose |
|---|---|
| `bin/ourlore.ts` | Entrypoint: `-c stage=dev\|prod` builds `Ourlore-<stage>` |
| `lib/config/stages.ts` | Per-stage, non-secret config (domain prefix, redirect URLs, enabled IdPs, throttles, WAF, termination protection, log retention, purge delay) and its synth-time validation |
| `lib/config/ses.ts` | Prod SES sender from context (`-c sesFromEmail`, `-c sesVerifiedDomain`, `-c sesRegion`), validated |
| `lib/config/identity-providers.ts` | IdP registry (Apple, Google) |
| `lib/contract.ts` | Typed loader + validation of `contract.json` |
| `lib/constructs/auth.ts` | User pool, domain, iOS client, IdPs, pre-sign-up and post-confirmation triggers, WAF |
| `lib/constructs/data.ts` | Tables, media bucket, cursor-key reference |
| `lib/constructs/api.ts` | HTTP API, JWT authorizer, routes, group Lambdas, access logs |
| `lib/constructs/account-lifecycle.ts` | Purge queue + DLQ, purge worker, maintenance schedule |
| `lib/constructs/alarms.ts` | SNS topic and alarms (DLQ depth, Lambda errors, API 5xx, oldest pending deletion, post-confirmation errors; warnings: pre-sign-up check skipped, post-confirmation sign-out failed, purge throttled) |
| `lib/constructs/contract-function.ts` | One Lambda (role, log group, env, IAM) from a contract function spec |
| `lib/bundling.ts` | Local Python bundling (no Docker) |
| `contract.json` | App/infra contract, vendored from the app repo by `../sync-contract.sh` |

Routes, env vars, runtime, and IAM scope all come from `contract.json` (version 5). S3 grants
are scoped to the bucket's `key_prefixes` (`media/`, `pending/`, `thumb/`): object actions on
`<prefix>*` only, and `s3:ListBucket` only with an `s3:prefix` condition inside them. Change them in the
app repo (`src/app/contract.py`), then run `../sync-contract.sh`. A malformed contract (an
unknown method, a duplicate route, an env name outside the catalog, or a missing value that
isn't deferred or optional) fails synth.

## Stages

| | `dev` | `prod` |
|---|---|---|
| Stack | `Ourlore-dev` | `Ourlore-prod` |
| Cognito domain prefix | `ourlore-dev-auth` | `ourlore-prod-auth` |
| Enabled IdPs | none until the secrets exist | none until the secrets exist |
| WAF on the user pool | off | on (300 requests / 5 min per IP) |
| Termination protection | off | on |
| Table deletion protection | off | on |
| Log retention | 14 days | 90 days |
| Cognito email | Cognito default sender | SES, from `-c sesFromEmail=... -c sesVerifiedDomain=...` (synth fails without them) |
| Account-purge delay (`purgeDelaySeconds`) | 120 s | 960 s (synth fails below 960) |

`purgeDelaySeconds` is passed to the `account` function as `PURGE_DELAY_SECONDS`: the purge
of a deleted account's data starts no earlier than `requestedAt + purgeDelaySeconds`, so work
already in flight when the tombstone committed (access tokens, presigned upload POSTs) has
expired (auth_design.md §4.3). A `prod` value below the access-token lifetime + 60 s or the
UPL-1 POST expiry (900 s) + 60 s fails synth. `dev` uses 120 s so the deletion E2E finishes
in minutes; raise it to 960 s once to rehearse prod timing.

Stateful resources (user pool, tables, media bucket) are `RETAIN` and have pinned logical
ids, so they survive stack deletion and construct refactors.

DynamoDB uses fixed provisioned capacity sized to the always-free tier (every table and GSI
together within 25 RCU / 25 WCU). That allowance is per region, so only one stage fits per
account and region. PITR is prod-only.

## Deploying

Account and region come from the AWS CLI profile at deploy time; nothing account-specific
is committed. Without credentials, synth produces an environment-agnostic template.

Before the first deploy of a stage, create its cursor-signing key (below).

```bash
aws sso login --profile <your-profile>
npx cdk bootstrap --profile <your-profile>                          # once per account/region
npx cdk diff   -c stage=dev --profile <your-profile>
npx cdk deploy -c stage=dev --profile <your-profile> -c alarmEmail=<you@example.com>
```

Use one AWS account per stage: the custom alarm metrics (`Ourlore/*`) are dimensionless.

### Cursor-signing key (required, once per stage)

Pagination cursors are HMAC-signed with a key kept in SSM Parameter Store as a standard-tier
`SecureString` encrypted with the AWS-managed `aws/ssm` key, which is free. CloudFormation
can't create `SecureString`s, so create it yourself, in the stage's account and region:

```bash
aws ssm put-parameter --profile <your-profile> --type SecureString \
  --name /ourlore/<stage>/cursor-key --value "$(openssl rand -base64 48)"
```

The value must be standard base64 of at least 32 random bytes. The stack takes the name as a
template parameter of type `AWS::SSM::Parameter::Name`, so `cdk deploy` fails with a
validation error if the parameter is missing. The stack never reads, outputs, or deletes the
key, and only the `users`, `social`, `posts`, and `wishes` functions may read it.

To rotate, overwrite it (`put-parameter ... --overwrite`). Functions pick up the new key
within 15 minutes, without a redeploy. Existing cursors become invalid, and clients restart
from page one (`400 invalid_cursor`). Don't delete the parameter while the stage is live:
cursor routes return `500` once a container's cached key expires.

### Prod: SES sender (required)

`prod` sends Cognito email (verification codes, password reset) through SES (REQ-PW-7). The
sender is operator-specific, so it's passed as context and never committed:

```bash
npx cdk diff   -c stage=prod --profile <prod-profile> \
  -c sesFromEmail=no-reply@<your-domain> -c sesVerifiedDomain=<your-domain>
npx cdk deploy -c stage=prod --profile <prod-profile> \
  -c sesFromEmail=no-reply@<your-domain> -c sesVerifiedDomain=<your-domain> \
  -c alarmEmail=<you@example.com>
```

- `sesFromEmail` must be a valid address whose domain equals `sesVerifiedDomain`
  (case-insensitive). Subdomain senders aren't accepted: the SES identity ARN is derived
  from `sesVerifiedDomain`.
- `sesRegion` (optional) is the region of the SES identity. It defaults to the stack's
  region.
- A `prod` synth, diff, or deploy without `sesFromEmail` and `sesVerifiedDomain` fails with
  an error naming the missing context. `dev` always uses the Cognito default sender and
  ignores these keys.
- Before the first prod deploy, verify the domain identity in SES in that region (DKIM) and
  move the account out of the SES sandbox; otherwise Cognito can't send to arbitrary
  addresses.

`-c alarmEmail=...` (optional) subscribes an email address to `ourlore-<stage>-alarms`. It
is read from context only and is never committed. Confirm the subscription email that AWS
sends.

Never deploy a synth made with `-c ourlore:skipBundling=true`: its functions are placeholders.

### Lambda bundling

All functions share one asset, built locally without Docker:

1. `python3 -m pip install --platform manylinux2014_aarch64 --only-binary=:all:
   --python-version 3.12 --implementation cp --target <asset> --no-deps --require-hashes
   -r <appPath>/requirements-lambda.lock`. The lock is the app's fully resolved,
   hash-pinned runtime dependency set, generated by the app's `scripts/lock_lambda_deps.sh`
   from its `pyproject.toml` pins. An unpinned, partially hashed, or missing lock fails
   synth.
2. copy `<appPath>/src/app` into the asset

Context: `ourlore:appPath` (default `../OurloreBackendService`); `ourlore:skipBundling=true`
skips bundling (tests do this). `OURLORE_PYTHON` overrides the interpreter. pip needs network
access to PyPI. The asset is cached in `cdk.out` by a hash of the sources and the lock.

## Federated sign-in: operator setup

Each provider needs a Secrets Manager secret named `ourlore/<stage>/idp/<id>`, created out
of band (never in this repo), before it's enabled. Enabling a provider without its secret
fails the deploy.

The Cognito redirect URI for both providers is:

```
https://<domainPrefix>.auth.<region>.amazoncognito.com/oauth2/idpresponse
```

### Sign in with Apple (`ourlore/<stage>/idp/apple`)

1. In the Apple Developer portal, enable Sign in with Apple on the app's primary App ID (the
   bundle id).
2. Create a Services ID, grouped under that primary App ID. Add the Cognito domain
   (`<domainPrefix>.auth.<region>.amazoncognito.com`) and the redirect URI above as its
   return URL.
3. Create a key with Sign in with Apple enabled for the primary App ID; download the `.p8`.
4. Create the secret (JSON):

   ```json
   { "servicesId": "<services id>", "teamId": "<team id>", "keyId": "<key id>",
     "privateKey": "<contents of the .p8>", "bundleId": "<app bundle id>" }
   ```

   `bundleId` is used by the backend for account-deletion token revocation.

### Google (`ourlore/<stage>/idp/google`)

1. In Google Cloud, create an OAuth client of type Web application.
2. Add the redirect URI above as an authorized redirect URI.
3. Create the secret (JSON): `{ "clientId": "<client id>", "clientSecret": "<client secret>" }`

### Enabling

Add the id to `enabledIdps` for the stage in `lib/config/stages.ts` and redeploy. The
template only holds `{{resolve:secretsmanager:...}}` references. The Apple secret is also
granted to the `account` function (ACC-1 revocation); while Apple is disabled,
`APPLE_SECRET_ARN` is empty and no grant exists.

## iOS client config

After a deploy, from the workspace root:

```bash
./export-ios-config.sh dev <your-profile>
```

It reads the stack outputs (`describe-stacks`, read-only) and writes the git-ignored
`Ourlore/Ourlore/Config/OurloreBackend.json` (Amplify outputs format: `auth`, including
`oauth.identity_providers`, plus `custom.ourlore_api_endpoint`). A placeholder,
`OurloreBackend.example.json`, is committed next to it.

Stack outputs: `Region`, `UserPoolId`, `UserPoolClientId`, `CognitoDomain`, `ApiEndpoint`,
`EnabledIdps`, `CallbackUrls`, `LogoutUrls`, `OAuthScopes`, `PreSignUpLogGroup`,
`PostConfirmationFunctionArn` (E2E step 12). List-valued
outputs are JSON arrays.

## Commands

| Command | Description |
|---|---|
| `npm run build` | Compile TypeScript |
| `npm run watch` | Compile on change |
| `npm test` | Run the Jest assertion tests |
| `npx cdk synth -c stage=<s>` | Emit the synthesized CloudFormation |
| `npx cdk diff -c stage=<s> --profile <p>` | Compare the deployed stack with local |
| `npx cdk deploy -c stage=<s> --profile <p>` | Deploy the stack |

## Secret scanning

A husky pre-commit hook runs `gitleaks` against staged changes and blocks the
commit if a secret is detected. Commits are refused if gitleaks is not installed.

`cdk.out/` and `cdk.context.json` are git-ignored because they contain
account-specific identifiers.

## License

[MIT](LICENSE)
