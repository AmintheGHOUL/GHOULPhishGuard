export function safeUrl(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

export function getDomainFromEmail(email: string): string {
  if (!email || !email.includes("@")) return "";
  return (email.split("@").pop() || "").toLowerCase().trim();
}

const MULTI_PART_TLDS = new Set([
  "co.uk", "co.jp", "co.kr", "co.nz", "co.za", "co.in", "co.id",
  "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tw", "com.hk",
  "org.uk", "org.au", "net.au", "net.uk",
  "ac.uk", "gov.uk", "gov.au",
]);

export function getBaseDomain(hostname: string): string {
  if (!hostname) return "";
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}
