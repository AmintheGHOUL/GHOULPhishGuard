import { isIP } from "node:net";
import { extractEmailAddress, getBaseDomain, getDomainFromEmail } from "./domains";

export interface ParsedHeaders {
  fromRaw: string;
  from: string;
  replyTo: string;
  returnPath: string;
  subject: string;
  date: string;
  messageId: string;
  spf: AuthResult;
  dkim: AuthResult;
  dmarc: AuthResult;
  spfMailFrom: string;
  dkimDomain: string;
  dkimSelector: string;
  dmarcHeaderFrom: string;
  receivedChain: ReceivedHop[];
  sourceIp: string;
  sourceHost: string;
  xMailer: string;
  contentType: string;
  listUnsubscribe: string;
}

export interface AuthResult {
  status: "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | "unknown";
  detail: string;
}

export interface ReceivedHop {
  from: string;
  by: string;
  protocol: string;
  timestamp: string;
  ip: string;
  raw: string;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function unfoldHeaderValue(value: string): string {
  return value.replace(/\r?\n[ \t]+/g, " ").trim();
}

function extractHeaderValue(raw: string, headerName: string): string {
  const regex = new RegExp(
    `^${escapeRegex(headerName)}:\\s*([^\\r\\n]*(?:\\r?\\n[ \\t].*)*)`,
    "im",
  );
  const match = raw.match(regex);
  return match ? unfoldHeaderValue(match[1]) : "";
}

function extractAllHeaderValues(raw: string, headerName: string): string[] {
  const results: string[] = [];
  const regex = new RegExp(
    `^${escapeRegex(headerName)}:\\s*([^\\r\\n]*(?:\\r?\\n[ \\t].*)*)`,
    "gim",
  );
  let match: RegExpExecArray | null;
  while ((match = regex.exec(raw)) !== null) {
    results.push(unfoldHeaderValue(match[1]));
  }
  return results;
}

function extractTokenProperty(value: string, property: string): string {
  if (!value) return "";

  const propertyPattern = new RegExp(`\\b${escapeRegex(property)}=([^\\s;]+)`, "i");
  const match = value.match(propertyPattern);
  return match ? match[1].trim().replace(/^<|>$/g, "") : "";
}

function extractAuthProperty(value: string, mechanism: string, property: string): string {
  if (!value) return "";

  const mechanismPattern = new RegExp(
    `${escapeRegex(mechanism)}=\\w+[^;]*?\\b${escapeRegex(property)}=([^\\s;]+)`,
    "i",
  );
  const mechanismMatch = value.match(mechanismPattern);
  if (mechanismMatch) {
    return mechanismMatch[1].trim().replace(/^<|>$/g, "");
  }

  return extractTokenProperty(value, property);
}

function parseAuthStatus(value: string, mechanism: string): AuthResult {
  if (!value) return { status: "unknown", detail: "Header not found" };

  const pattern = new RegExp(`${escapeRegex(mechanism)}=(\\w+)`, "i");
  const match = value.match(pattern);
  if (!match) return { status: "unknown", detail: `No ${mechanism} result found in header` };

  const status = match[1].toLowerCase();
  const validStatuses = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"];
  const normalized = validStatuses.includes(status) ? status : "unknown";

  let detail = "";
  const detailPattern = new RegExp(`${escapeRegex(mechanism)}=\\w+\\s*(?:\\(([^)]+)\\))?`, "i");
  const detailMatch = value.match(detailPattern);
  if (detailMatch && detailMatch[1]) {
    detail = detailMatch[1].trim();
  }

  const reasonPattern = new RegExp(`${escapeRegex(mechanism)}=\\w+[^;]*`, "i");
  const reasonMatch = value.match(reasonPattern);
  if (!detail && reasonMatch) {
    detail = reasonMatch[0].replace(new RegExp(`${escapeRegex(mechanism)}=\\w+\\s*`, "i"), "").trim();
  }

  return {
    status: normalized as AuthResult["status"],
    detail: detail || `${mechanism}=${status}`,
  };
}

function parseSPFFromReceivedSPF(value: string): AuthResult {
  if (!value) return { status: "unknown", detail: "No Received-SPF header" };

  const statusMatch = value.match(/^(\w+)/);
  if (!statusMatch) return { status: "unknown", detail: value };

  const status = statusMatch[1].toLowerCase();
  const validStatuses = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"];
  const normalized = validStatuses.includes(status) ? status : "unknown";

  return {
    status: normalized as AuthResult["status"],
    detail: value.slice(0, 200),
  };
}

function extractIpCandidate(value: string): string {
  if (!value) return "";

  const candidates = [
    ...Array.from(value.matchAll(/\[([^\]]+)\]/g), (match) => match[1].trim()),
    ...(value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []),
    ...(value.match(/\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]{1,4}\b/gi) || []),
  ];

  for (const candidate of candidates) {
    if (isIP(candidate)) {
      return candidate;
    }
  }

  return "";
}

function parseReceivedHeaders(raw: string): ReceivedHop[] {
  const receivedValues = extractAllHeaderValues(raw, "Received");
  return receivedValues.map((val) => {
    const fromMatch = val.match(/from\s+([^\s(]+)/i);
    const byMatch = val.match(/by\s+([^\s(;]+)/i);
    const withMatch = val.match(/with\s+([^\s;]+)/i);
    const dateMatch = val.match(/;\s*(.+)$/);

    return {
      from: fromMatch ? fromMatch[1].replace(/\.$/, "") : "",
      by: byMatch ? byMatch[1].replace(/\.$/, "") : "",
      protocol: withMatch ? withMatch[1] : "",
      timestamp: dateMatch ? dateMatch[1].trim() : "",
      ip: extractIpCandidate(val),
      raw: val.slice(0, 300),
    };
  });
}

function extractEmail(headerValue: string): string {
  return extractEmailAddress(headerValue);
}

function normalizeDomainValue(value: string): string {
  if (!value) return "";

  const extracted = extractEmailAddress(value);
  if (extracted.includes("@")) {
    return getDomainFromEmail(extracted);
  }

  return value.trim().replace(/^<|>$/g, "").toLowerCase();
}

function selectSourceHop(receivedChain: ReceivedHop[]): ReceivedHop | null {
  for (let i = receivedChain.length - 1; i >= 0; i -= 1) {
    if (receivedChain[i].ip || receivedChain[i].from) {
      return receivedChain[i];
    }
  }

  return receivedChain.at(-1) ?? null;
}

export function parseEmailHeaders(rawHeaders: string): ParsedHeaders {
  const authResults = extractAllHeaderValues(rawHeaders, "Authentication-Results");
  const combinedAuth = authResults.join(" ; ");
  const receivedSPF = extractHeaderValue(rawHeaders, "Received-SPF");
  const receivedChain = parseReceivedHeaders(rawHeaders);
  const sourceHop = selectSourceHop(receivedChain);

  let spf = parseAuthStatus(combinedAuth, "spf");
  if (spf.status === "unknown" && receivedSPF) {
    spf = parseSPFFromReceivedSPF(receivedSPF);
  }

  const dkim = parseAuthStatus(combinedAuth, "dkim");
  const dmarc = parseAuthStatus(combinedAuth, "dmarc");

  const spfMailFrom = normalizeDomainValue(
    extractAuthProperty(combinedAuth, "spf", "smtp.mailfrom")
      || extractTokenProperty(receivedSPF, "envelope-from")
      || extractTokenProperty(receivedSPF, "smtp.mailfrom"),
  );
  const dkimDomain = normalizeDomainValue(extractAuthProperty(combinedAuth, "dkim", "header.d"));
  const dkimSelector = extractAuthProperty(combinedAuth, "dkim", "header.s").toLowerCase();
  const dmarcHeaderFrom = normalizeDomainValue(extractAuthProperty(combinedAuth, "dmarc", "header.from"));

  const fromRaw = extractHeaderValue(rawHeaders, "From");
  const replyToRaw = extractHeaderValue(rawHeaders, "Reply-To");
  const returnPathRaw = extractHeaderValue(rawHeaders, "Return-Path");
  const clientIp = extractTokenProperty(receivedSPF, "client-ip");
  const sourceIp = isIP(clientIp) ? clientIp : sourceHop?.ip || "";

  return {
    fromRaw,
    from: extractEmail(fromRaw),
    replyTo: extractEmail(replyToRaw),
    returnPath: extractEmail(returnPathRaw),
    subject: extractHeaderValue(rawHeaders, "Subject"),
    date: extractHeaderValue(rawHeaders, "Date"),
    messageId: extractHeaderValue(rawHeaders, "Message-ID") || extractHeaderValue(rawHeaders, "Message-Id"),
    spf,
    dkim,
    dmarc,
    spfMailFrom,
    dkimDomain,
    dkimSelector,
    dmarcHeaderFrom,
    receivedChain,
    sourceIp,
    sourceHost: sourceHop?.from || "",
    xMailer: extractHeaderValue(rawHeaders, "X-Mailer"),
    contentType: extractHeaderValue(rawHeaders, "Content-Type"),
    listUnsubscribe: extractHeaderValue(rawHeaders, "List-Unsubscribe"),
  };
}

export function hasRealAuthHeaders(rawHeaders: string): boolean {
  return /Authentication-Results:/im.test(rawHeaders) || /Received-SPF:/im.test(rawHeaders);
}

export function headerAuthFindings(parsed: ParsedHeaders): { score: number; findings: string[] } {
  let score = 0;
  const findings: string[] = [];

  const fromDomain = getBaseDomain(getDomainFromEmail(parsed.from));
  const spfMailFromDomain = getBaseDomain(parsed.spfMailFrom);
  const dkimSigningDomain = getBaseDomain(parsed.dkimDomain);
  const dmarcDomain = getBaseDomain(parsed.dmarcHeaderFrom);

  if (parsed.spf.status === "fail") {
    score += 20;
    findings.push(`SPF check failed: the sender's server is not authorized to send email for this domain. ${parsed.spf.detail}`);
  } else if (parsed.spf.status === "softfail") {
    score += 10;
    findings.push(`SPF check returned softfail: the sender's server may not be authorized. ${parsed.spf.detail}`);
  } else if (parsed.spf.status === "none") {
    score += 5;
    findings.push("No SPF record was found for the sender's domain.");
  } else if (parsed.spf.status === "pass") {
    findings.push("SPF check passed: the sending server is authorized for this domain.");
    if (
      parsed.spfMailFrom
      && fromDomain
      && spfMailFromDomain
      && spfMailFromDomain !== fromDomain
      && parsed.dmarc.status !== "pass"
    ) {
      score += 6;
      findings.push(
        `SPF passed for ${parsed.spfMailFrom}, but that envelope domain does not align with the visible sender domain ${fromDomain}.`,
      );
    }
  }

  if (parsed.dkim.status === "fail") {
    score += 15;
    findings.push(`DKIM signature verification failed: the email may have been altered in transit. ${parsed.dkim.detail}`);
  } else if (parsed.dkim.status === "pass") {
    findings.push("DKIM signature verified: the email has not been tampered with.");
    if (
      parsed.dkimDomain
      && fromDomain
      && dkimSigningDomain
      && dkimSigningDomain !== fromDomain
      && parsed.dmarc.status !== "pass"
    ) {
      score += 6;
      findings.push(
        `DKIM passed, but the signing domain ${parsed.dkimDomain} does not align with the visible sender domain ${fromDomain}.`,
      );
    }
  }

  if (parsed.dmarc.status === "fail") {
    score += 20;
    findings.push(`DMARC check failed: the email does not align with the domain's authentication policy. ${parsed.dmarc.detail}`);
  } else if (parsed.dmarc.status === "pass") {
    findings.push("DMARC check passed: the email aligns with the domain's authentication policy.");
    if (
      parsed.dmarcHeaderFrom
      && fromDomain
      && dmarcDomain
      && dmarcDomain !== fromDomain
    ) {
      score += 6;
      findings.push(
        `DMARC passed for ${parsed.dmarcHeaderFrom}, but the visible From domain is ${fromDomain}.`,
      );
    }
  }

  if (parsed.receivedChain.length > 6) {
    score += 5;
    findings.push(`The email passed through ${parsed.receivedChain.length} servers, which is unusually high and could indicate relaying.`);
  }

  return { score, findings };
}
