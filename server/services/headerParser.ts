export interface ParsedHeaders {
  from: string;
  replyTo: string;
  returnPath: string;
  subject: string;
  date: string;
  messageId: string;
  spf: AuthResult;
  dkim: AuthResult;
  dmarc: AuthResult;
  receivedChain: ReceivedHop[];
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
  raw: string;
}

function extractHeaderValue(raw: string, headerName: string): string {
  const regex = new RegExp(`^${headerName}:\\s*(.+?)(?=\\n[^\\s]|$)`, "ims");
  const match = raw.match(regex);
  return match ? match[1].replace(/\s+/g, " ").trim() : "";
}

function extractAllHeaderValues(raw: string, headerName: string): string[] {
  const results: string[] = [];
  const regex = new RegExp(`^${headerName}:\\s*(.+?)(?=\\n[^\\s]|$)`, "gims");
  let match;
  while ((match = regex.exec(raw)) !== null) {
    results.push(match[1].replace(/\s+/g, " ").trim());
  }
  return results;
}

function parseAuthStatus(value: string, mechanism: string): AuthResult {
  if (!value) return { status: "unknown", detail: "Header not found" };

  const pattern = new RegExp(`${mechanism}=(\\w+)`, "i");
  const match = value.match(pattern);
  if (!match) return { status: "unknown", detail: `No ${mechanism} result found in header` };

  const status = match[1].toLowerCase();
  const validStatuses = ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"];
  const normalized = validStatuses.includes(status) ? status : "unknown";

  let detail = "";
  const detailPattern = new RegExp(`${mechanism}=\\w+\\s*(?:\\(([^)]+)\\))?`, "i");
  const detailMatch = value.match(detailPattern);
  if (detailMatch && detailMatch[1]) {
    detail = detailMatch[1].trim();
  }

  const reasonPattern = new RegExp(`${mechanism}=\\w+[^;]*`, "i");
  const reasonMatch = value.match(reasonPattern);
  if (!detail && reasonMatch) {
    detail = reasonMatch[0].replace(new RegExp(`${mechanism}=\\w+\\s*`, "i"), "").trim();
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

function parseReceivedHeaders(raw: string): ReceivedHop[] {
  const receivedValues = extractAllHeaderValues(raw, "Received");
  return receivedValues.map((val) => {
    const fromMatch = val.match(/from\s+(\S+)/i);
    const byMatch = val.match(/by\s+(\S+)/i);
    const withMatch = val.match(/with\s+(\S+)/i);
    const dateMatch = val.match(/;\s*(.+)$/);

    return {
      from: fromMatch ? fromMatch[1] : "",
      by: byMatch ? byMatch[1] : "",
      protocol: withMatch ? withMatch[1] : "",
      timestamp: dateMatch ? dateMatch[1].trim() : "",
      raw: val.slice(0, 300),
    };
  });
}

function extractEmail(headerValue: string): string {
  const angleMatch = headerValue.match(/<([^>]+)>/);
  if (angleMatch) return angleMatch[1].trim();
  const atMatch = headerValue.match(/[\w.+-]+@[\w.-]+/);
  return atMatch ? atMatch[0] : headerValue.trim();
}

export function parseEmailHeaders(rawHeaders: string): ParsedHeaders {
  const authResults = extractAllHeaderValues(rawHeaders, "Authentication-Results");
  const combinedAuth = authResults.join(" ; ");

  const receivedSPF = extractHeaderValue(rawHeaders, "Received-SPF");

  let spf = parseAuthStatus(combinedAuth, "spf");
  if (spf.status === "unknown" && receivedSPF) {
    spf = parseSPFFromReceivedSPF(receivedSPF);
  }

  const dkim = parseAuthStatus(combinedAuth, "dkim");
  const dmarc = parseAuthStatus(combinedAuth, "dmarc");

  const fromRaw = extractHeaderValue(rawHeaders, "From");
  const replyToRaw = extractHeaderValue(rawHeaders, "Reply-To");
  const returnPathRaw = extractHeaderValue(rawHeaders, "Return-Path");

  return {
    from: extractEmail(fromRaw),
    replyTo: extractEmail(replyToRaw),
    returnPath: extractEmail(returnPathRaw),
    subject: extractHeaderValue(rawHeaders, "Subject"),
    date: extractHeaderValue(rawHeaders, "Date"),
    messageId: extractHeaderValue(rawHeaders, "Message-ID") || extractHeaderValue(rawHeaders, "Message-Id"),
    spf,
    dkim,
    dmarc,
    receivedChain: parseReceivedHeaders(rawHeaders),
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
  }

  if (parsed.dkim.status === "fail") {
    score += 15;
    findings.push(`DKIM signature verification failed: the email may have been altered in transit. ${parsed.dkim.detail}`);
  } else if (parsed.dkim.status === "pass") {
    findings.push("DKIM signature verified: the email has not been tampered with.");
  }

  if (parsed.dmarc.status === "fail") {
    score += 20;
    findings.push(`DMARC check failed: the email does not align with the domain's authentication policy. ${parsed.dmarc.detail}`);
  } else if (parsed.dmarc.status === "pass") {
    findings.push("DMARC check passed: the email aligns with the domain's authentication policy.");
  }

  if (parsed.receivedChain.length > 6) {
    score += 5;
    findings.push(`The email passed through ${parsed.receivedChain.length} servers, which is unusually high and could indicate relaying.`);
  }

  return { score, findings };
}
