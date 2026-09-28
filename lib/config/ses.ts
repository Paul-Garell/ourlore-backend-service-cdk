/**
 * SES sender for Cognito email (REQ-PW-7, auth_design.md §3.2).
 *
 * The sender address and verified domain are operator-specific, and this repo is public, so
 * they come from CDK context at synth time instead of `stages.ts`:
 *
 *   -c sesFromEmail=no-reply@<domain> -c sesVerifiedDomain=<domain> [-c sesRegion=<region>]
 *
 * `prod` requires them (synth fails without them). `dev` always uses the Cognito default
 * sender and ignores the context.
 */
import type { SesConfig, StageName } from './stages';

/** Context keys. */
export const SES_CONTEXT = {
  fromEmail: 'sesFromEmail',
  verifiedDomain: 'sesVerifiedDomain',
  region: 'sesRegion',
} as const;

/** One DNS label: letters, digits, inner hyphens, at most 63 characters. */
const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
/** A fully qualified domain with an alphabetic TLD. */
const DOMAIN_RE = new RegExp(`^(?:${LABEL}\\.)+[A-Za-z]{2,63}$`);
/** Dot-atom local part (RFC 5322 without quoted strings). */
const LOCAL_RE = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
/** AWS region name, for example `us-east-1` or `ap-southeast-2`. */
const REGION_RE = /^[a-z]{2}(?:-[a-z]+)+-\d+$/;

const USAGE =
  `-c ${SES_CONTEXT.fromEmail}=<no-reply@your-domain> -c ${SES_CONTEXT.verifiedDomain}=<your-domain> ` +
  `[-c ${SES_CONTEXT.region}=<region of the SES identity; defaults to the stack region>]`;

/** Read an optional string context value; non-strings and blanks are treated as absent. */
function str(get: (key: string) => unknown, key: string): string | undefined {
  const v = get(key);
  if (v === undefined || v === null) return undefined;
  if (typeof v !== 'string') throw new Error(`Context '${key}' must be a string.`);
  const t = v.trim();
  return t.length > 0 ? t : undefined;
}

/**
 * Validate an SES sender.
 *
 * The address's domain must equal `sesVerifiedDomain` (case-insensitively): the identity ARN
 * Cognito sends through is derived from that domain, and CDK's `UserPoolEmail.withSES`
 * rejects any other domain.
 */
export function validateSesConfig(ses: SesConfig): SesConfig {
  const fromEmail = ses.fromEmail.trim();
  const at = fromEmail.lastIndexOf('@');
  const local = at > 0 ? fromEmail.slice(0, at) : '';
  const emailDomain = at > 0 ? fromEmail.slice(at + 1) : '';
  if (!LOCAL_RE.test(local) || local.length > 64 || !DOMAIN_RE.test(emailDomain)) {
    throw new Error(`SES from address '${fromEmail}' is not a valid email address (${SES_CONTEXT.fromEmail}).`);
  }
  const verifiedDomain = ses.sesVerifiedDomain.trim().toLowerCase();
  if (!DOMAIN_RE.test(verifiedDomain) || verifiedDomain.length > 253) {
    throw new Error(`SES verified domain '${ses.sesVerifiedDomain}' is not a valid domain (${SES_CONTEXT.verifiedDomain}).`);
  }
  if (emailDomain.toLowerCase() !== verifiedDomain) {
    throw new Error(
      `SES from address '${fromEmail}' must be on the verified domain '${verifiedDomain}' ` +
        `(${SES_CONTEXT.fromEmail} must end with '@${verifiedDomain}').`,
    );
  }
  if (ses.sesRegion !== undefined && !REGION_RE.test(ses.sesRegion)) {
    throw new Error(`SES region '${ses.sesRegion}' is not an AWS region name (${SES_CONTEXT.region}).`);
  }
  return {
    fromEmail: `${local}@${verifiedDomain}`,
    sesVerifiedDomain: verifiedDomain,
    ...(ses.sesRegion !== undefined ? { sesRegion: ses.sesRegion } : {}),
  };
}

/**
 * Resolve the SES sender for a stage from context.
 *
 * @param stage the stage being synthesized
 * @param get context getter (`node.tryGetContext`)
 * @returns the validated sender for `prod`; `undefined` for `dev` (Cognito default sender)
 * @throws for `prod` when the context is missing or invalid
 */
export function sesConfigFromContext(stage: StageName, get: (key: string) => unknown): SesConfig | undefined {
  if (stage !== 'prod') return undefined;
  const fromEmail = str(get, SES_CONTEXT.fromEmail);
  const sesVerifiedDomain = str(get, SES_CONTEXT.verifiedDomain);
  const sesRegion = str(get, SES_CONTEXT.region);
  if (!fromEmail || !sesVerifiedDomain) {
    throw new Error(
      `Stage 'prod' must send Cognito email through SES (REQ-PW-7); the Cognito default sender is dev-only. ` +
        `Pass ${USAGE}.`,
    );
  }
  return validateSesConfig({ fromEmail, sesVerifiedDomain, sesRegion });
}
