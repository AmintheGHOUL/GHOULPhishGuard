import { safeUrl, getBaseDomain, getDomainFromEmail } from "./domains";

export function extractFirstHttpLink(links: Array<{ href: string }> = []) {
  const link = links.find((x) => safeUrl(x.href));
  return link?.href || "";
}

function normalizeDetectedUrl(raw: string): string {
  return raw.trim().replace(/[),.;!?]+$/g, "");
}

export function extractLinksFromText(text: string): Array<{ text: string; href: string }> {
  if (!text) return [];

  const matches = text.match(/\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi) || [];
  const links: Array<{ text: string; href: string }> = [];
  const seen = new Set<string>();

  for (const match of matches) {
    let href = normalizeDetectedUrl(match);
    if (/^www\./i.test(href)) {
      href = `https://${href}`;
    }

    const parsed = safeUrl(href);
    if (!parsed) continue;

    const key = parsed.href.toLowerCase();
    if (seen.has(key)) continue;

    seen.add(key);
    links.push({ text: "", href: parsed.href });
  }

  return links;
}

export function mergeLinks(
  explicitLinks: Array<{ text: string; href: string }> = [],
  detectedLinks: Array<{ text: string; href: string }> = [],
): Array<{ text: string; href: string }> {
  const merged = new Map<string, { text: string; href: string }>();

  for (const link of [...explicitLinks, ...detectedLinks]) {
    const parsed = safeUrl(link.href);
    if (!parsed) continue;

    const normalizedHref = parsed.href;
    const key = normalizedHref.toLowerCase();
    const existing = merged.get(key);

    if (!existing || (!existing.text && link.text)) {
      merged.set(key, {
        text: link.text || existing?.text || "",
        href: normalizedHref,
      });
    }
  }

  return Array.from(merged.values());
}

export function findDomainMismatch(fromEmail: string, replyTo: string, returnPath: string) {
  const senderDomain = getBaseDomain(getDomainFromEmail(fromEmail));
  const replyDomain = getBaseDomain(getDomainFromEmail(replyTo));
  const returnPathDomain = getBaseDomain(getDomainFromEmail(returnPath));

  return {
    senderDomain,
    replyDomain,
    returnPathDomain,
    replyMismatch: !!replyDomain && !!senderDomain && replyDomain !== senderDomain,
    returnPathMismatch: !!returnPathDomain && !!senderDomain && returnPathDomain !== senderDomain,
  };
}
