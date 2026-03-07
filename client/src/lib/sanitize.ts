export function sanitizePlain(input: string | undefined | null): string {
  if (!input) return "";
  return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "");
}
