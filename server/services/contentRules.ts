const URGENCY_PATTERNS = [
  /urgent/i,
  /immediately/i,
  /within\s+\d+\s+(hours?|days?)/i,
  /action required/i,
  /verify now/i,
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

export function analyzeContent(bodyText = "", subject = "", links: Array<{ href: string }> = []) {
  const text = `${subject} ${bodyText}`;
  const linkUrls = links.map((l) => l.href || "").join(" ");
  const combinedText = `${text} ${linkUrls}`;
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

  return { score, findings };
}
