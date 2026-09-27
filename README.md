# Ourlore Backend Service CDK

AWS CDK (TypeScript) infrastructure for the Ourlore backend service.

## Prerequisites

- [Node.js 24 LTS](https://nodejs.org/) (see `.nvmrc`)
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) with a configured profile (IAM Identity Center/SSO recommended)
- [gitleaks](https://github.com/gitleaks/gitleaks) — required by the pre-commit hook (`brew install gitleaks`)

## Getting started

```bash
npm install          # also installs the git hooks via husky
npm run build
npm test
```

## Deploying

The target account and region are resolved at synth time from the active AWS CLI
profile (`CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION`); nothing account-specific is
committed to this repository.

```bash
aws sso login --profile <your-profile>
npx cdk bootstrap --profile <your-profile>   # once per account/region
npx cdk diff      --profile <your-profile>
npx cdk deploy    --profile <your-profile>
```

## Commands

| Command          | Description                               |
| ---------------- | ----------------------------------------- |
| `npm run build`  | Compile TypeScript                        |
| `npm run watch`  | Compile on change                         |
| `npm test`       | Run Jest unit tests                       |
| `npx cdk synth`  | Emit the synthesized CloudFormation       |
| `npx cdk diff`   | Compare the deployed stack with local     |
| `npx cdk deploy` | Deploy the stack                          |

## Secret scanning

A husky pre-commit hook runs `gitleaks` against staged changes and blocks the
commit if a secret is detected. Commits are refused if gitleaks is not installed.

`cdk.out/` and `cdk.context.json` are git-ignored because they contain
account-specific identifiers.

## License

[MIT](LICENSE)
