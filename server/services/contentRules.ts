import { extractEmailAddress, getDomainFromEmail } from "./domains";

const URGENCY_PATTERNS = [
  /urgent/i,
  /immediately/i,
  /within\s+\d+\s+(hours?|days?)/i,
  /action required/i,
  /verify now/i,
  /right now/i,
  /asap/i,
  /as soon as possible/i,
  /quick request/i,
  /today\b/i,
  /before end of day/i,
  /account will be (closed|suspended|disabled)/i,
  /final warning/i,
];

const EMOTIONAL_PATTERNS = [
  /won a prize/i,
  /account has been compromised/i,
  /overdue bill/i,
  /security alert/i,
  /unusual login/i,
  /password reset/i,
];

const SENSITIVE_REQUEST_PATTERNS = [
  /password/i,
  /mfa code/i,
  /verification code/i,
  /bank account/i,
  /credit card/i,
  /social security/i,
  /login credentials/i,
  /routing number/i,
  /payroll details/i,
  /direct deposit/i,
  /ssn/i,
  /tax\s*(id|number|return)/i,
];

const PLATFORM_ABUSE_PATTERNS = [
  /forms\.gle/i,
  /docs\.google\.com\/forms/i,
  /sites\.google\.com/i,
  /notion\.site/i,
  /dropbox\.com/i,
  /onedrive/i,
  /sharepoint/i,
  /sway\.office\.com/i,
  /docs\.google\.com\/document/i,
];

const BEC_FINANCIAL_REQUEST_PATTERNS = [
  /\bgift cards?\b/i,
  /\bpurchase\b.{0,40}\bgift cards?\b/i,
  /\bbuy\b.{0,40}\bgift cards?\b/i,
  /\bsend me the codes?\b/i,
  /\bwire transfer\b/i,
  /\bbank transfer\b/i,
  /\bchange (?:our )?payment details\b/i,
  /\bupdate (?:our )?bank details\b/i,
  /\bpay this invoice\b/i,
];

const BEC_CONVERSATION_HOOK_PATTERNS = [
  /\bare you available(?: right now)?\b/i,
  /\bavailable right now\b/i,
  /\bquick request\b/i,
  /\bneed you to\b/i,
  /\bcan you handle this\b/i,
  /\btext me back\b/i,
  /\bkeep this between us\b/i,
  /\bdiscreet(?:ly)?\b/i,
  /\bconfidential\b/i,
  /\bclient meeting\b/i,
];

const EXECUTIVE_IDENTITY_PATTERNS = [
  /\bceo\b/i,
  /\bcfo\b/i,
  /\bcoo\b/i,
  /\bcto\b/i,
  /\bpresident\b/i,
  /\bfounder\b/i,
  /\bowner\b/i,
  /\bmanaging director\b/i,
  /\bvice president\b/i,
  /\bvp\b/i,
  /\bfinance director\b/i,
];

const GENERIC_SUPPORT_DOMAIN_PATTERNS = [
  /support/i,
  /help/i,
  /service/i,
  /secure/i,
  /verify/i,
  /notification/i,
  /alert/i,
  /mail/i,
  /portal/i,
  /account/i,
];

function extractDisplayName(sender: string): string {
  if (!sender) return "";

  const angleIndex = sender.indexOf("<");
  if (angleIndex <= 0) return "";

  return sender.slice(0, angleIndex).replace(/["']/g, "").trim().toLowerCase();
}

function isRoleMailbox(localPart: string): boolean {
  return /^(ceo|cfo|coo|cto|president|founder|owner|director|finance|accounts(?:payable)?|payroll)$/i.test(localPart);
}

export function analyzeContent(
  bodyText = "",
  subject = "",
  links: Array<{ href: string }> = [],
  sender = "",
) {
  const text = `${subject} ${bodyText}`;
  const linkUrls = links.map((l) => l.href || "").join(" ");
  const combinedText = `${text} ${linkUrls}`;
  const senderAddress = extractEmailAddress(sender);
  const senderDomain = getDomainFromEmail(senderAddress);
  const senderLocalPart = senderAddress.split("@")[0] || "";
  const senderIdentity = `${extractDisplayName(sender)} ${senderLocalPart}`;
  const presentsAsExecutive = EXECUTIVE_IDENTITY_PATTERNS.some((r) => r.test(senderIdentity)) || isRoleMailbox(senderLocalPart);
  const hasFinancialRequest = BEC_FINANCIAL_REQUEST_PATTERNS.some((r) => r.test(text));
  const hasConversationHook = BEC_CONVERSATION_HOOK_PATTERNS.some((r) => r.test(text));
  const hasSupportThemedDomain = !!senderDomain && GENERIC_SUPPORT_DOMAIN_PATTERNS.some((r) => r.test(senderDomain));
  const findings: string[] = [];
  let score = 0;

  if (URGENCY_PATTERNS.some((r) => r.test(text))) {
    findings.push("This message uses urgent language to pressure quick action.");
    score += 10;
  }

  if (EMOTIONAL_PATTERNS.some((r) => r.test(text))) {
    findings.push("This message uses emotional pressure such as fear, security concerns, or reward language.");
    score += 8;
  }

  if (SENSITIVE_REQUEST_PATTERNS.some((r) => r.test(text))) {
    findings.push("This email asks for sensitive information or tries to push you toward credential entry.");
    score += 12;
  }

  if (PLATFORM_ABUSE_PATTERNS.some((r) => r.test(combinedText))) {
    findings.push("This email links to a legitimate platform that attackers commonly abuse to evade detection (e.g., Google Forms, Google Sites, SharePoint).");
    score += 8;
  }

  if (hasFinancialRequest) {
    findings.push("This email makes a financial or procurement request commonly seen in business email compromise, such as gift cards or payment changes.");
    score += 14;
  }

  if (presentsAsExecutive && hasFinancialRequest && hasConversationHook) {
    findings.push("This message shows CEO-fraud / business email compromise behavior by pairing an executive-style identity with a pressured request for off-book action.");
    score += 12;
  }

  if (presentsAsExecutive && hasSupportThemedDomain) {
    findings.push(`The sender uses an executive-style identity from a generic external domain (${senderDomain}), which is suspicious for an internal leadership request.`);
    score += 10;
  }

  return { score, findings };
}
