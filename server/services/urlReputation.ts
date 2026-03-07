import { getBaseDomain } from "./domains";

export interface UrlReputationResult {
  domainAge: number | null;
  domainCreationDate: string | null;
  ageRiskScore: number;
  tldRiskScore: number;
  hostingRiskScore: number;
  totalScore: number;
  findings: string[];
  technical: Record<string, string>;
}

const SUSPICIOUS_TLDS = new Set([
  ".tk", ".ml", ".ga", ".cf", ".gq",
  ".xyz", ".top", ".buzz", ".club", ".work",
  ".icu", ".cam", ".rest", ".surf", ".monster",
  ".loan", ".click", ".link", ".website", ".space",
  ".site", ".online", ".win", ".racing", ".accountant",
  ".bid", ".stream", ".download", ".gdn", ".men",
  ".review", ".science", ".party", ".date", ".faith",
  ".cricket", ".trade",
]);

const FREE_HOSTING_PATTERNS = [
  "000webhostapp.com",
  "weebly.com",
  "wixsite.com",
  "blogspot.com",
  "wordpress.com",
  "sites.google.com",
  "firebaseapp.com",
  "web.app",
  "netlify.app",
  "vercel.app",
  "herokuapp.com",
  "glitch.me",
  "replit.dev",
  "github.io",
  "pages.dev",
  "surge.sh",
  "ngrok.io",
  "ngrok-free.app",
  "serveo.net",
  "loca.lt",
  "trycloudflare.com",
];

const BULLETPROOF_ASN_KEYWORDS = [
  "amarutu",
  "alexhost",
  "shinjiru",
  "liteserver",
  "hostkey",
  "pfcloud",
  "king-servers",
  "deltahost",
  "quasi",
  "server4you",
];

function getTld(domain: string): string {
  const idx = domain.lastIndexOf(".");
  if (idx === -1) return "";
  return domain.slice(idx).toLowerCase();
}

function checkSuspiciousTld(domain: string): { score: number; findings: string[] } {
  const tld = getTld(domain);
  if (SUSPICIOUS_TLDS.has(tld)) {
    return {
      score: 8,
      findings: [`Domain uses a high-risk TLD (${tld}) commonly abused by phishing campaigns.`],
    };
  }
  return { score: 0, findings: [] };
}

function checkFreeHosting(domain: string): { score: number; findings: string[] } {
  const lower = domain.toLowerCase();
  for (const pattern of FREE_HOSTING_PATTERNS) {
    if (lower.endsWith(pattern) || lower === pattern) {
      return {
        score: 6,
        findings: [`Domain is hosted on a free hosting platform (${pattern}), often used in phishing.`],
      };
    }
  }
  return { score: 0, findings: [] };
}

function calculateAgeScore(ageDays: number): { score: number; findings: string[] } {
  if (ageDays < 7) {
    return {
      score: 15,
      findings: [`Domain was registered only ${ageDays} day(s) ago — extremely new and suspicious.`],
    };
  }
  if (ageDays < 30) {
    return {
      score: 10,
      findings: [`Domain was registered ${ageDays} days ago — very recently created.`],
    };
  }
  if (ageDays < 90) {
    return {
      score: 5,
      findings: [`Domain was registered ${ageDays} days ago — relatively new.`],
    };
  }
  return { score: 0, findings: [] };
}

async function fetchRdapCreationDate(domain: string): Promise<string | null> {
  const baseDomain = getBaseDomain(domain);
  if (!baseDomain) return null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3000);

  try {
    const response = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(baseDomain)}`,
      {
        signal: controller.signal,
        headers: { Accept: "application/rdap+json" },
      }
    );
    clearTimeout(timeout);

    if (!response.ok) return null;

    const data = await response.json();

    if (Array.isArray(data.events)) {
      for (const evt of data.events) {
        if (evt.eventAction === "registration" && evt.eventDate) {
          return evt.eventDate;
        }
      }
    }

    return null;
  } catch {
    clearTimeout(timeout);
    return null;
  }
}

function daysBetween(dateStr: string): number {
  const then = new Date(dateStr).getTime();
  const now = Date.now();
  if (isNaN(then)) return -1;
  return Math.floor((now - then) / (1000 * 60 * 60 * 24));
}

export async function checkUrlReputation(domain: string): Promise<UrlReputationResult> {
  const findings: string[] = [];
  const technical: Record<string, string> = {};
  let ageRiskScore = 0;
  let tldRiskScore = 0;
  let hostingRiskScore = 0;
  let domainAge: number | null = null;
  let domainCreationDate: string | null = null;

  technical.checkedDomain = domain;

  const tldCheck = checkSuspiciousTld(domain);
  tldRiskScore = tldCheck.score;
  findings.push(...tldCheck.findings);

  const hostingCheck = checkFreeHosting(domain);
  hostingRiskScore = hostingCheck.score;
  findings.push(...hostingCheck.findings);

  const creationDate = await fetchRdapCreationDate(domain);
  if (creationDate) {
    domainCreationDate = creationDate;
    const age = daysBetween(creationDate);
    if (age >= 0) {
      domainAge = age;
      const ageCheck = calculateAgeScore(age);
      ageRiskScore = ageCheck.score;
      findings.push(...ageCheck.findings);
      technical.domainAge = `${age} days`;
      technical.domainCreated = creationDate;
    }
  } else {
    technical.rdapLookup = "unavailable";
  }

  if (tldRiskScore > 0) {
    technical.tldRisk = getTld(domain);
  }
  if (hostingRiskScore > 0) {
    technical.hostingType = "free/shared";
  }

  const totalScore = ageRiskScore + tldRiskScore + hostingRiskScore;

  return {
    domainAge,
    domainCreationDate,
    ageRiskScore,
    tldRiskScore,
    hostingRiskScore,
    totalScore,
    findings,
    technical,
  };
}
