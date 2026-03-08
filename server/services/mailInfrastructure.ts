import { isIP } from "node:net";
import { getBaseDomain } from "./domains";

interface ProviderDefinition {
  name: string;
  domains: string[];
  hostPatterns: RegExp[];
  ipv4Cidrs: string[];
}

export interface MailInfrastructureInput {
  sourceIp: string;
  sourceHost: string;
  fromDomain: string;
  dkimDomain: string;
  spfMailFrom: string;
  dmarcHeaderFrom: string;
  spfStatus: string;
  dkimStatus: string;
  dmarcStatus: string;
}

export interface MailInfrastructureResult {
  score: number;
  findings: string[];
  sourceIp: string | null;
  sourceHost: string | null;
  detectedProvider: string;
  expectedProvider: string | null;
  alignment: "aligned" | "mismatch" | "unknown";
  matchedRange: string | null;
  ipType: string;
}

const PROVIDERS: ProviderDefinition[] = [
  {
    name: "Microsoft 365",
    domains: ["microsoft.com", "outlook.com", "office365.com", "live.com", "hotmail.com", "onmicrosoft.com"],
    hostPatterns: [
      /\.outbound\.protection\.outlook\.com$/i,
      /\.mail\.protection\.outlook\.com$/i,
      /\.protection\.outlook\.com$/i,
    ],
    ipv4Cidrs: [
      "40.92.0.0/14",
      "40.107.0.0/16",
      "52.96.0.0/14",
      "52.100.0.0/14",
      "52.102.0.0/15",
      "52.103.0.0/16",
      "104.47.0.0/17",
    ],
  },
  {
    name: "Google Workspace",
    domains: ["google.com", "gmail.com", "googlemail.com"],
    hostPatterns: [
      /\.google\.com$/i,
      /\.googlemail\.com$/i,
    ],
    ipv4Cidrs: [
      "64.233.160.0/19",
      "66.102.0.0/20",
      "66.249.80.0/20",
      "72.14.192.0/18",
      "74.125.0.0/16",
      "108.177.8.0/21",
      "142.250.0.0/15",
      "172.217.0.0/16",
      "173.194.0.0/16",
      "209.85.128.0/17",
    ],
  },
  {
    name: "Amazon SES",
    domains: ["amazonses.com", "amazonaws.com"],
    hostPatterns: [
      /\.amazonses\.com$/i,
      /\.amazonaws\.com$/i,
    ],
    ipv4Cidrs: [
      "54.239.0.0/17",
      "54.240.0.0/18",
      "76.223.176.0/20",
    ],
  },
  {
    name: "SendGrid",
    domains: ["sendgrid.net"],
    hostPatterns: [
      /\.sendgrid\.net$/i,
      /\.outbound-mail\.sendgrid\.net$/i,
    ],
    ipv4Cidrs: [
      "149.72.0.0/16",
      "167.89.0.0/17",
      "168.245.0.0/17",
    ],
  },
  {
    name: "Mailchimp",
    domains: ["mailchimp.com", "mailchimpapp.net", "mcsv.net"],
    hostPatterns: [
      /\.mailchimp(?:app)?\.net$/i,
      /\.mcsv\.net$/i,
    ],
    ipv4Cidrs: [
      "198.2.128.0/18",
      "205.201.128.0/20",
    ],
  },
];

function ipv4ToInt(ip: string): number | null {
  if (isIP(ip) !== 4) return null;

  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }

  return parts.reduce((acc, part) => ((acc << 8) >>> 0) + part, 0) >>> 0;
}

function isInCidr(ip: string, cidr: string): boolean {
  const [baseIp, prefixText] = cidr.split("/");
  const ipValue = ipv4ToInt(ip);
  const baseValue = ipv4ToInt(baseIp);
  const prefix = Number(prefixText);

  if (ipValue === null || baseValue === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }

  if (prefix === 0) return true;

  const mask = prefix === 32 ? 0xffffffff : ((0xffffffff << (32 - prefix)) >>> 0);
  return (ipValue & mask) === (baseValue & mask);
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

function classifyIpType(ip: string | null): string {
  if (!ip) return "missing";

  const version = isIP(ip);
  if (!version) return "invalid";
  if (version === 6) return "ipv6";

  if (isInCidr(ip, "10.0.0.0/8") || isInCidr(ip, "172.16.0.0/12") || isInCidr(ip, "192.168.0.0/16")) {
    return "private";
  }
  if (isInCidr(ip, "127.0.0.0/8")) {
    return "loopback";
  }
  if (isInCidr(ip, "169.254.0.0/16")) {
    return "link-local";
  }
  if (isInCidr(ip, "100.64.0.0/10")) {
    return "carrier-nat";
  }
  if (isInCidr(ip, "192.0.2.0/24") || isInCidr(ip, "198.51.100.0/24") || isInCidr(ip, "203.0.113.0/24")) {
    return "documentation";
  }
  if (isInCidr(ip, "224.0.0.0/4")) {
    return "multicast";
  }
  if (
    isInCidr(ip, "0.0.0.0/8")
    || isInCidr(ip, "198.18.0.0/15")
    || isInCidr(ip, "240.0.0.0/4")
  ) {
    return "reserved";
  }

  return "public";
}

function matchProviderByInfrastructure(sourceHost: string | null, sourceIp: string | null): {
  provider: string;
  matchedRange: string | null;
} {
  const normalizedHost = sourceHost ? normalizeHost(sourceHost) : "";
  const hostMatch = PROVIDERS.find((provider) => normalizedHost && provider.hostPatterns.some((pattern) => pattern.test(normalizedHost)));
  let rangeMatch: { provider: string; matchedRange: string } | null = null;

  if (sourceIp && isIP(sourceIp) === 4) {
    for (const provider of PROVIDERS) {
      const matchedRange = provider.ipv4Cidrs.find((cidr) => isInCidr(sourceIp, cidr));
      if (matchedRange) {
        rangeMatch = { provider: provider.name, matchedRange };
        break;
      }
    }
  }

  if (hostMatch && rangeMatch && hostMatch.name === rangeMatch.provider) {
    return { provider: hostMatch.name, matchedRange: rangeMatch.matchedRange };
  }
  if (hostMatch) {
    return { provider: hostMatch.name, matchedRange: null };
  }
  if (rangeMatch) {
    return rangeMatch;
  }

  return { provider: "Unknown", matchedRange: null };
}

function inferExpectedProvider(domains: string[]): string | null {
  for (const domain of domains) {
    const normalized = getBaseDomain(domain);
    if (!normalized) continue;

    const provider = PROVIDERS.find((entry) => entry.domains.includes(normalized));
    if (provider) {
      return provider.name;
    }
  }

  return null;
}

function humanizeIpType(ipType: string): string {
  return ipType === "carrier-nat" ? "carrier-grade NAT" : ipType.replace(/-/g, " ");
}

export function analyzeMailInfrastructure(input: MailInfrastructureInput): MailInfrastructureResult {
  const sourceIp = input.sourceIp || null;
  const sourceHost = input.sourceHost ? normalizeHost(input.sourceHost) : null;
  const ipType = classifyIpType(sourceIp);
  const providerMatch = matchProviderByInfrastructure(sourceHost, sourceIp);

  const providerCandidates = [
    input.dkimStatus === "pass" ? input.dkimDomain : "",
    input.spfStatus === "pass" ? input.spfMailFrom : "",
    input.dmarcStatus === "pass" ? input.dmarcHeaderFrom : "",
    input.fromDomain,
  ].filter(Boolean);

  const expectedProvider = inferExpectedProvider(providerCandidates);
  const alignment: MailInfrastructureResult["alignment"] = expectedProvider && providerMatch.provider !== "Unknown"
    ? (expectedProvider === providerMatch.provider ? "aligned" : "mismatch")
    : "unknown";

  let score = 0;
  const findings: string[] = [];

  if (sourceIp) {
    if (ipType === "documentation") {
      findings.push(
        `Source IP ${sourceIp} is in a documentation/test network, which suggests the raw headers may be sanitized or synthetic.`,
      );
    } else if (["private", "loopback", "link-local", "carrier-nat", "multicast", "reserved", "invalid"].includes(ipType)) {
      score += 8;
      findings.push(
        `Source IP ${sourceIp} is ${humanizeIpType(ipType)} and is unusual for the earliest external mail hop.`,
      );
    }
  }

  if (providerMatch.provider !== "Unknown" && sourceIp && providerMatch.matchedRange) {
    findings.push(
      `Source IP ${sourceIp} falls within a known ${providerMatch.provider} outbound mail range (${providerMatch.matchedRange}).`,
    );
  } else if (providerMatch.provider !== "Unknown" && sourceHost) {
    findings.push(
      `Source host ${sourceHost} matches ${providerMatch.provider} mail infrastructure.`,
    );
  }

  if (alignment === "aligned" && expectedProvider) {
    findings.push(`The earliest sending infrastructure matches the expected ${expectedProvider} provider.`);
  } else if (alignment === "mismatch" && expectedProvider) {
    score += 10;
    findings.push(
      `The message claims a ${expectedProvider} sender or signing domain, but the earliest sending infrastructure looks like ${providerMatch.provider}.`,
    );
  }

  return {
    score,
    findings,
    sourceIp,
    sourceHost,
    detectedProvider: providerMatch.provider,
    expectedProvider,
    alignment,
    matchedRange: providerMatch.matchedRange,
    ipType,
  };
}
