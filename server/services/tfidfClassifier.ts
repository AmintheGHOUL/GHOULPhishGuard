const PHISHING_CORPUS_IDF: Record<string, number> = {
  "verify": 4.2,
  "urgent": 4.5,
  "account": 3.1,
  "login": 3.8,
  "security": 3.4,
  "password": 4.0,
  "confirm": 3.9,
  "suspend": 4.8,
  "suspended": 4.8,
  "expire": 4.6,
  "expired": 4.6,
  "update": 2.8,
  "click": 3.3,
  "immediately": 4.4,
  "unauthorized": 4.7,
  "alert": 3.6,
  "warning": 3.7,
  "bank": 3.5,
  "credential": 4.9,
  "credentials": 4.9,
  "reset": 3.6,
  "limit": 3.2,
  "restricted": 4.3,
  "unusual": 4.1,
  "activity": 3.0,
  "detected": 3.5,
  "compromised": 4.8,
  "breach": 4.6,
  "locked": 4.2,
  "unlock": 4.3,
  "validate": 4.0,
  "validation": 4.0,
  "ssn": 5.0,
  "social security": 5.0,
  "credit card": 4.5,
  "debit card": 4.5,
  "pin": 4.0,
  "wire transfer": 4.8,
  "payment": 3.2,
  "invoice": 3.4,
  "receipt": 3.0,
  "refund": 3.8,
  "prize": 4.5,
  "winner": 4.6,
  "congratulations": 4.2,
  "selected": 3.5,
  "reward": 4.0,
  "gift card": 4.5,
  "free": 3.0,
  "offer": 2.8,
  "deal": 2.6,
  "shipping": 3.0,
  "delivery": 2.9,
  "tracking": 2.8,
  "package": 3.0,
  "failed delivery": 4.3,
  "undelivered": 4.4,
  "dear customer": 3.8,
  "dear user": 4.0,
  "dear member": 3.9,
  "valued customer": 4.1,
  "act now": 4.6,
  "limited time": 3.8,
  "final notice": 4.5,
  "last chance": 4.3,
  "within 24 hours": 4.7,
  "within 48 hours": 4.6,
  "action required": 4.4,
  "response required": 4.3,
  "attention required": 4.3,
  "sign in": 3.3,
  "log in": 3.3,
  "click here": 3.9,
  "click below": 3.9,
  "click the link": 4.0,
  "attached file": 3.2,
  "see attached": 3.2,
  "open attachment": 3.8,
  "download": 2.8,
  "enable macros": 5.0,
  "enable content": 4.8,
  "tax return": 4.2,
  "irs": 4.5,
  "hmrc": 4.5,
  "apple id": 4.0,
  "microsoft account": 3.8,
  "paypal": 3.5,
  "helpdesk": 3.4,
  "it department": 3.6,
  "tech support": 3.8,
  "customer service": 2.8,
  "identity": 3.4,
  "verification": 4.0,
  "authenticate": 4.2,
  "reactivate": 4.5,
  "restore": 3.5,
  "recover": 3.6,
  "dispute": 3.4,
  "charge": 3.0,
  "transaction": 3.2,
  "suspicious": 3.8,
  "malicious": 4.2,
  "threat": 3.5,
  "virus": 3.8,
  "infected": 4.2,
};

const LEGITIMATE_DAMPERS: Record<string, number> = {
  "unsubscribe": -1.5,
  "preferences": -1.0,
  "privacy policy": -1.2,
  "terms of service": -1.0,
  "opt out": -1.2,
  "manage notifications": -1.3,
  "no longer wish": -1.2,
  "copyright": -0.8,
  "all rights reserved": -0.8,
  "newsletter": -1.0,
  "digest": -0.8,
  "weekly update": -0.8,
  "monthly report": -0.8,
};

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 1);
}

function computeTF(tokens: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const token of tokens) {
    counts.set(token, (counts.get(token) || 0) + 1);
  }
  const tf = new Map<string, number>();
  for (const [term, count] of counts) {
    tf.set(term, count / tokens.length);
  }
  return tf;
}

function findMultiWordMatches(text: string, dictionary: Record<string, number>): Array<{ term: string; count: number; idf: number }> {
  const lowerText = text.toLowerCase();
  const matches: Array<{ term: string; count: number; idf: number }> = [];

  for (const [term, idf] of Object.entries(dictionary)) {
    if (term.includes(" ")) {
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const regex = new RegExp(`\\b${escaped}\\b`, "gi");
      const found = lowerText.match(regex);
      if (found) {
        matches.push({ term, count: found.length, idf });
      }
    }
  }

  return matches;
}

export interface TfidfResult {
  phishingScore: number;
  topTerms: Array<{ term: string; tfidf: number }>;
  totalTermsMatched: number;
  damperApplied: number;
}

export function classifyWithTfidf(text: string): TfidfResult {
  if (!text || text.trim().length < 10) {
    return { phishingScore: 0, topTerms: [], totalTermsMatched: 0, damperApplied: 0 };
  }

  const tokens = tokenize(text);
  const tf = computeTF(tokens);

  const termScores: Array<{ term: string; tfidf: number }> = [];

  for (const [term, idf] of Object.entries(PHISHING_CORPUS_IDF)) {
    if (term.includes(" ")) continue;

    const termTf = tf.get(term);
    if (termTf && termTf > 0) {
      const tfidf = termTf * idf;
      termScores.push({ term, tfidf });
    }
  }

  const multiWordMatches = findMultiWordMatches(text, PHISHING_CORPUS_IDF);
  for (const match of multiWordMatches) {
    const approxTf = match.count / Math.max(tokens.length, 1);
    const tfidf = approxTf * match.idf;
    termScores.push({ term: match.term, tfidf });
  }

  termScores.sort((a, b) => b.tfidf - a.tfidf);

  let rawScore = 0;
  for (const ts of termScores) {
    rawScore += ts.tfidf;
  }

  let damper = 0;
  const multiWordDampers = findMultiWordMatches(text, LEGITIMATE_DAMPERS);
  for (const match of multiWordDampers) {
    damper += match.idf * match.count;
  }
  for (const [term, weight] of Object.entries(LEGITIMATE_DAMPERS)) {
    if (!term.includes(" ") && tf.has(term)) {
      damper += weight;
    }
  }

  rawScore += damper;

  const normalizedScore = Math.max(0, Math.min(100, Math.round(rawScore * 45)));

  return {
    phishingScore: normalizedScore,
    topTerms: termScores.slice(0, 8),
    totalTermsMatched: termScores.length,
    damperApplied: Math.round(damper * 100) / 100,
  };
}
