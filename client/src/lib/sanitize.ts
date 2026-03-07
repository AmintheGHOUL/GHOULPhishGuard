export function sanitizeText(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

export function sanitizePlain(input: string | undefined | null): string {
  if (!input) return "";
  return input
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "");
}
