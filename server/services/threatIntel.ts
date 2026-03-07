import { safeUrl, getBaseDomain } from "./domains";

export interface ThreatSignal {
  type: string;
  severity: "high" | "medium" | "low";
  description: string;
}

export interface ThreatIntelResult {
  score: number;
  findings: string[];
  signals: ThreatSignal[];
  domainEntropy: number;
  matchedIndicators: string[];
}

const SUSPICIOUS_TLDS = new Set([
  ".tk", ".ml", ".ga", ".cf", ".gq",
  ".buzz", ".top", ".xyz", ".icu", ".club",
  ".work", ".click", ".link", ".surf", ".rest",
  ".monster", ".cam", ".ooo", ".fit", ".loan",
  ".racing", ".win", ".bid", ".stream", ".date",
  ".download", ".accountant", ".science", ".cricket",
  ".review", ".party", ".trade", ".webcam", ".faith",
  ".zip", ".mov", ".php",
]);

const FREE_HOSTING_PROVIDERS = new Set([
  "000webhostapp.com", "weebly.com", "wixsite.com",
  "blogspot.com", "wordpress.com", "sites.google.com",
  "firebaseapp.com", "web.app", "netlify.app",
  "vercel.app", "herokuapp.com", "glitch.me",
  "repl.co", "github.io", "pages.dev",
  "workers.dev", "surge.sh", "neocities.org",
  "freenom.com", "infinityfree.net", "rf.gd",
  "epizy.com", "byethost.com",
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl",
  "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
  "cutt.ly", "shorturl.at", "tiny.cc", "lnkd.in",
  "rb.gy", "v.gd", "t.ly", "s.id",
  "qr.ae", "adf.ly", "bc.vc", "soo.gd",
]);

const PHISHING_DOMAIN_PATTERNS = [
  /^secure[-.]?login/i,
  /^account[-.]?verify/i,
  /^update[-.]?account/i,
  /^confirm[-.]?identity/i,
  /^signin[-.]?alert/i,
  /^verify[-.]?now/i,
  /^auth[-.]?confirm/i,
  /^reset[-.]?password/i,
  /^security[-.]?alert/i,
  /^suspended[-.]?account/i,
  /^unlock[-.]?account/i,
  /paypal.*login/i,
  /microsoft.*verify/i,
  /apple.*id.*confirm/i,
  /google.*security/i,
  /amazon.*verify/i,
  /netflix.*update/i,
  /bank.*secure/i,
  /\.login\./i,
  /\.secure\./i,
  /\.verify\./i,
  /\.account\./i,
  /\.auth\./i,
];

function calculateDomainEntropy(domain: string): number {
  const name = domain.split(".")[0] || domain;
  if (name.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const ch of name.toLowerCase()) {
    freq[ch] = (freq[ch] || 0) + 1;
  }

  let entropy = 0;
  const len = name.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 100) / 100;
}

function hasExcessiveSubdomains(hostname: string): boolean {
  const parts = hostname.split(".");
  return parts.length > 4;
}

function hasIPAddress(hostname: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function hasHomographCharacters(domain: string): boolean {
  if (/[^\x00-\x7F]/.test(domain)) return true;
  const labels = domain.toLowerCase().split(".");
  return labels.some((label) => label.startsWith("xn--"));
}

function checkSuspiciousTld(hostname: string): string | null {
  const lower = hostname.toLowerCase();
  const tlds = Array.from(SUSPICIOUS_TLDS);
  for (let i = 0; i < tlds.length; i++) {
    if (lower.endsWith(tlds[i])) return tlds[i];
  }
  return null;
}

function checkFreeHosting(hostname: string): string | null {
  const lower = hostname.toLowerCase();
  const providers = Array.from(FREE_HOSTING_PROVIDERS);
  for (let i = 0; i < providers.length; i++) {
    if (lower === providers[i] || lower.endsWith("." + providers[i])) return providers[i];
  }
  return null;
}

function checkUrlShortener(hostname: string): string | null {
  const lower = hostname.toLowerCase();
  const shorteners = Array.from(URL_SHORTENERS);
  for (let i = 0; i < shorteners.length; i++) {
    if (lower === shorteners[i] || lower.endsWith("." + shorteners[i])) return shorteners[i];
  }
  return null;
}

function checkPhishingPatterns(hostname: string): string | null {
  for (const pattern of PHISHING_DOMAIN_PATTERNS) {
    if (pattern.test(hostname)) return pattern.source;
  }
  return null;
}

async function checkGoogleSafeBrowsing(domain: string): Promise<ThreatSignal | null> {
  try {
    const url = `https://transparencyreport.google.com/transparencyreport/api/v3/safebrowsing/status?site=${encodeURIComponent(domain)}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "PhishGuard/1.0",
      },
    });

    clearTimeout(timeout);

    if (!response.ok) return null;

    const text = await response.text();
    const cleaned = text.replace(/^\)]\}'\n/, "");

    if (cleaned.includes('"unsafe"') || cleaned.includes('"dangerous"')) {
      return {
        type: "safe_browsing_flagged",
        severity: "high",
        description: `Domain "${domain}" is flagged by Google Safe Browsing as potentially dangerous.`,
      };
    }

    return null;
  } catch {
    return null;
  }
}

export async function analyzeThreatIntel(domains: string[], urls: string[] = []): Promise<ThreatIntelResult> {
  let score = 0;
  const findings: string[] = [];
  const signals: ThreatSignal[] = [];
  const matchedIndicators: string[] = [];
  let maxEntropy = 0;

  const allHostnames = new Set<string>();

  for (const domain of domains) {
    if (domain) allHostnames.add(domain.toLowerCase());
  }

  for (const url of urls) {
    const parsed = safeUrl(url);
    if (parsed) {
      allHostnames.add(parsed.hostname.toLowerCase());
    }
  }

  const hostnameList = Array.from(allHostnames);
  for (let hi = 0; hi < hostnameList.length; hi++) {
    const hostname = hostnameList[hi];
    const baseDomain = getBaseDomain(hostname);

    const entropy = calculateDomainEntropy(baseDomain);
    if (entropy > maxEntropy) maxEntropy = entropy;

    if (entropy > 3.5 && baseDomain.length > 10) {
      score += 8;
      signals.push({
        type: "high_entropy_domain",
        severity: "medium",
        description: `Domain "${baseDomain}" has high entropy (${entropy}), suggesting a randomly generated name.`,
      });
      matchedIndicators.push(`high-entropy:${baseDomain}`);
      findings.push(`Domain "${baseDomain}" appears randomly generated (entropy: ${entropy}).`);
    } else if (entropy > 3.0 && baseDomain.length > 12) {
      score += 4;
      signals.push({
        type: "moderate_entropy_domain",
        severity: "low",
        description: `Domain "${baseDomain}" has moderately high entropy (${entropy}).`,
      });
      matchedIndicators.push(`moderate-entropy:${baseDomain}`);
    }

    const suspiciousTld = checkSuspiciousTld(hostname);
    if (suspiciousTld) {
      score += 10;
      signals.push({
        type: "suspicious_tld",
        severity: "medium",
        description: `Domain uses suspicious TLD "${suspiciousTld}", commonly abused in phishing campaigns.`,
      });
      matchedIndicators.push(`suspicious-tld:${suspiciousTld}`);
      findings.push(`The domain uses TLD "${suspiciousTld}", which is frequently abused in phishing.`);
    }

    const freeHost = checkFreeHosting(hostname);
    if (freeHost) {
      score += 8;
      signals.push({
        type: "free_hosting",
        severity: "medium",
        description: `Domain is hosted on free platform "${freeHost}", often used by phishing sites.`,
      });
      matchedIndicators.push(`free-hosting:${freeHost}`);
      findings.push(`Links point to free hosting provider "${freeHost}", commonly used for phishing.`);
    }

    const shortener = checkUrlShortener(hostname);
    if (shortener) {
      score += 6;
      signals.push({
        type: "url_shortener",
        severity: "low",
        description: `Uses URL shortener "${shortener}" to hide the real destination.`,
      });
      matchedIndicators.push(`url-shortener:${shortener}`);
      findings.push(`A URL shortener ("${shortener}") is used to hide the real link destination.`);
    }

    const phishingPattern = checkPhishingPatterns(hostname);
    if (phishingPattern) {
      score += 12;
      signals.push({
        type: "phishing_domain_pattern",
        severity: "high",
        description: `Domain matches known phishing naming pattern.`,
      });
      matchedIndicators.push(`phishing-pattern:${hostname}`);
      findings.push(`Domain "${hostname}" matches a known phishing naming pattern.`);
    }

    if (hasExcessiveSubdomains(hostname)) {
      score += 5;
      signals.push({
        type: "excessive_subdomains",
        severity: "low",
        description: `Domain "${hostname}" has excessive subdomains, a common phishing technique.`,
      });
      matchedIndicators.push(`excessive-subdomains:${hostname}`);
      findings.push(`Domain "${hostname}" uses excessive subdomains to appear legitimate.`);
    }

    if (hasIPAddress(hostname)) {
      score += 10;
      signals.push({
        type: "ip_address_url",
        severity: "medium",
        description: `URL uses a raw IP address instead of a domain name.`,
      });
      matchedIndicators.push(`ip-address:${hostname}`);
      findings.push("A link uses a raw IP address instead of a domain name, which is suspicious.");
    }

    if (hasHomographCharacters(hostname)) {
      score += 15;
      signals.push({
        type: "homograph_attack",
        severity: "high",
        description: `Domain "${hostname}" contains non-ASCII characters that could be a homograph attack.`,
      });
      matchedIndicators.push(`homograph:${hostname}`);
      findings.push(`Domain "${hostname}" contains characters that mimic standard letters (homograph attack).`);
    }
  }

  const safeBrowsingChecks = Array.from(allHostnames).slice(0, 3).map((h) =>
    checkGoogleSafeBrowsing(getBaseDomain(h))
  );

  const safeBrowsingResults = await Promise.all(safeBrowsingChecks);
  for (const result of safeBrowsingResults) {
    if (result) {
      score += 20;
      signals.push(result);
      matchedIndicators.push(`safe-browsing:flagged`);
      findings.push(result.description);
    }
  }

  score = Math.min(score, 50);

  return {
    score,
    findings,
    signals,
    domainEntropy: maxEntropy,
    matchedIndicators,
  };
}
