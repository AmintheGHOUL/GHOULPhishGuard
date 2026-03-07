const KNOWN_BRANDS: Record<string, string[]> = {
  "microsoft.com": ["microsoft", "outlook", "office365", "onedrive", "sharepoint", "teams"],
  "google.com": ["google", "gmail", "youtube", "drive", "docs"],
  "apple.com": ["apple", "icloud", "itunes", "appstore"],
  "amazon.com": ["amazon", "aws", "prime", "kindle"],
  "paypal.com": ["paypal"],
  "netflix.com": ["netflix"],
  "facebook.com": ["facebook", "meta", "instagram"],
  "linkedin.com": ["linkedin"],
  "dropbox.com": ["dropbox"],
  "docusign.com": ["docusign"],
  "chase.com": ["chase", "jpmorgan"],
  "wellsfargo.com": ["wellsfargo", "wells fargo"],
  "bankofamerica.com": ["bankofamerica", "bofa"],
  "dhl.com": ["dhl"],
  "fedex.com": ["fedex"],
  "ups.com": ["ups"],
  "usps.com": ["usps"],
  "twitter.com": ["twitter"],
  "x.com": ["x"],
  "zoom.us": ["zoom"],
  "slack.com": ["slack"],
  "github.com": ["github"],
  "stripe.com": ["stripe"],
  "adobe.com": ["adobe"],
  "salesforce.com": ["salesforce"],
  "intuit.com": ["intuit", "quickbooks", "turbotax"],
  "ebay.com": ["ebay"],
  "walmart.com": ["walmart"],
  "costco.com": ["costco"],
  "att.com": ["att"],
  "verizon.com": ["verizon"],
  "tmobile.com": ["tmobile", "t-mobile"],
};

const HOMOGLYPHS: Record<string, string> = {
  "0": "o",
  "1": "l",
  "l": "i",
  "rn": "m",
  "vv": "w",
  "cl": "d",
  "nn": "m",
};

const HOMOGLYPH_PAIRS: Array<[string, string]> = [
  ["0", "o"],
  ["1", "l"],
  ["1", "i"],
  ["l", "i"],
  ["rn", "m"],
  ["vv", "w"],
  ["cl", "d"],
  ["nn", "m"],
  ["ii", "u"],
  ["q", "g"],
];

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }

  return dp[m][n];
}

function detectHomoglyphs(domain: string, brandName: string): boolean {
  let normalized = domain.toLowerCase();

  for (const [fake, real] of HOMOGLYPH_PAIRS) {
    normalized = normalized.replace(new RegExp(fake.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g"), real);
  }

  if (normalized.includes(brandName) && !domain.includes(brandName)) {
    return true;
  }

  return false;
}

function extractDomainLabel(fullDomain: string): string {
  const parts = fullDomain.split(".");
  if (parts.length <= 1) return fullDomain;
  if (parts.length === 2) return parts[0];
  return parts.slice(0, -1).join(".");
}

export interface ImpersonationResult {
  detected: boolean;
  score: number;
  findings: string[];
  impersonatedBrand: string;
  method: string;
  technical: Record<string, string>;
}

export function detectDomainImpersonation(senderDomain: string): ImpersonationResult {
  const result: ImpersonationResult = {
    detected: false,
    score: 0,
    findings: [],
    impersonatedBrand: "",
    method: "",
    technical: {},
  };

  if (!senderDomain || senderDomain.length < 3) return result;

  const domainLower = senderDomain.toLowerCase();
  const domainLabel = extractDomainLabel(domainLower);

  for (const [realDomain, keywords] of Object.entries(KNOWN_BRANDS)) {
    if (domainLower === realDomain || domainLower.endsWith("." + realDomain)) continue;

    const brandName = realDomain.split(".")[0];

    if (domainLabel.includes(brandName) && domainLower !== realDomain) {
      result.detected = true;
      result.score = 30;
      result.impersonatedBrand = realDomain;
      result.method = "brand-in-subdomain";
      result.findings.push(
        `The sender domain "${senderDomain}" contains the brand name "${brandName}" but is not the real ${realDomain} domain. This is a common impersonation technique.`
      );
      result.technical.impersonationMethod = "Brand name embedded in fake domain";
      result.technical.realBrandDomain = realDomain;
      return result;
    }

    const distance = levenshtein(domainLabel, brandName);
    const maxLen = Math.max(domainLabel.length, brandName.length);

    if (distance > 0 && distance <= 2 && maxLen >= 4) {
      result.detected = true;
      result.score = 25;
      result.impersonatedBrand = realDomain;
      result.method = "typosquatting";
      result.findings.push(
        `The sender domain "${senderDomain}" looks very similar to ${realDomain} (Levenshtein distance: ${distance}). This may be a typosquatting attempt.`
      );
      result.technical.impersonationMethod = "Typosquatting (Levenshtein)";
      result.technical.levenshteinDistance = String(distance);
      result.technical.realBrandDomain = realDomain;
      return result;
    }

    if (detectHomoglyphs(domainLabel, brandName)) {
      result.detected = true;
      result.score = 30;
      result.impersonatedBrand = realDomain;
      result.method = "homoglyph";
      result.findings.push(
        `The sender domain "${senderDomain}" uses look-alike characters to imitate ${realDomain}. For example, "rn" instead of "m", or "0" instead of "o".`
      );
      result.technical.impersonationMethod = "Homoglyph/look-alike characters";
      result.technical.realBrandDomain = realDomain;
      return result;
    }

    for (const keyword of keywords) {
      if (keyword.length >= 4 && domainLabel.includes(keyword) && domainLower !== realDomain) {
        const distance2 = levenshtein(domainLabel, keyword);
        if (distance2 <= 3) {
          result.detected = true;
          result.score = 20;
          result.impersonatedBrand = realDomain;
          result.method = "keyword-match";
          result.findings.push(
            `The sender domain "${senderDomain}" contains "${keyword}" which is associated with ${realDomain}. The email may be impersonating this brand.`
          );
          result.technical.impersonationMethod = "Brand keyword in domain";
          result.technical.matchedKeyword = keyword;
          result.technical.realBrandDomain = realDomain;
          return result;
        }
      }
    }
  }

  return result;
}
