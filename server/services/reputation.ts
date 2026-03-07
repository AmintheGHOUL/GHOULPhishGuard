import { safeUrl, getBaseDomain } from "./domains";

export function extractFirstHttpLink(links: Array<{ href: string }> = []) {
  const link = links.find((x) => safeUrl(x.href));
  return link?.href || "";
}

export function findDomainMismatch(fromEmail: string, replyTo: string, returnPath: string) {
  const senderDomain = getBaseDomain((fromEmail.split("@")[1]) || "");
  const replyDomain = getBaseDomain((replyTo.split("@")[1]) || "");
  const returnPathDomain = getBaseDomain((returnPath.split("@")[1]) || "");

  return {
    senderDomain,
    replyDomain,
    returnPathDomain,
    replyMismatch: !!replyDomain && !!senderDomain && replyDomain !== senderDomain,
    returnPathMismatch: !!returnPathDomain && !!senderDomain && returnPathDomain !== senderDomain,
  };
}
