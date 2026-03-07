const SVM_VOCABULARY: Record<string, number> = {
  "verify": 0, "urgent": 1, "account": 2, "login": 3, "security": 4,
  "password": 5, "confirm": 6, "suspend": 7, "expire": 8, "update": 9,
  "click": 10, "immediately": 11, "unauthorized": 12, "alert": 13, "warning": 14,
  "bank": 15, "credential": 16, "reset": 17, "restricted": 18, "unusual": 19,
  "activity": 20, "detected": 21, "compromised": 22, "breach": 23, "locked": 24,
  "unlock": 25, "validate": 26, "ssn": 27, "credit": 28, "debit": 29,
  "pin": 30, "wire": 31, "payment": 32, "invoice": 33, "receipt": 34,
  "refund": 35, "prize": 36, "winner": 37, "congratulations": 38, "selected": 39,
  "reward": 40, "gift": 41, "free": 42, "offer": 43, "deal": 44,
  "shipping": 45, "delivery": 46, "tracking": 47, "package": 48, "failed": 49,
  "undelivered": 50, "dear": 51, "customer": 52, "user": 53, "member": 54,
  "valued": 55, "act": 56, "limited": 57, "final": 58, "last": 59,
  "chance": 60, "hours": 61, "action": 62, "required": 63, "response": 64,
  "attention": 65, "sign": 66, "log": 67, "here": 68, "below": 69,
  "link": 70, "attached": 71, "attachment": 72, "download": 73, "enable": 74,
  "macros": 75, "tax": 76, "irs": 77, "apple": 78, "microsoft": 79,
  "paypal": 80, "helpdesk": 81, "department": 82, "support": 83, "identity": 84,
  "verification": 85, "authenticate": 86, "reactivate": 87, "restore": 88, "recover": 89,
  "dispute": 90, "charge": 91, "transaction": 92, "suspicious": 93, "malicious": 94,
  "threat": 95, "virus": 96, "infected": 97, "unsubscribe": 98, "privacy": 99,
  "terms": 100, "opt": 101, "copyright": 102, "newsletter": 103, "notice": 104,
  "request": 105, "access": 106, "denied": 107, "blocked": 108, "temporary": 109,
  "permanent": 110, "close": 111, "terminate": 112, "cancel": 113, "review": 114,
  "important": 115, "critical": 116, "sensitive": 117, "personal": 118, "information": 119,
  "data": 120, "form": 121, "submit": 122, "enter": 123, "provide": 124,
  "transfer": 125, "wiring": 126, "routing": 127, "number": 128, "social": 129,
  "notify": 130, "notification": 131, "resolve": 132, "issue": 133, "problem": 134,
  "error": 135, "upgrade": 136, "renew": 137, "subscription": 138, "expired": 139,
  "overdue": 140, "outstanding": 141, "balance": 142, "owe": 143, "debt": 144,
  "collection": 145, "legal": 146, "court": 147, "arrest": 148, "warrant": 149,
};

const SVM_IDF: number[] = [
  4.2, 4.5, 3.1, 3.8, 3.4, 4.0, 3.9, 4.8, 4.6, 2.8,
  3.3, 4.4, 4.7, 3.6, 3.7, 3.5, 4.9, 3.6, 4.3, 4.1,
  3.0, 3.5, 4.8, 4.6, 4.2, 4.3, 4.0, 5.0, 4.5, 4.5,
  4.0, 4.8, 3.2, 3.4, 3.0, 3.8, 4.5, 4.6, 4.2, 3.5,
  4.0, 4.5, 3.0, 2.8, 2.6, 3.0, 2.9, 2.8, 3.0, 4.3,
  4.4, 3.8, 3.0, 4.0, 3.9, 4.1, 4.6, 3.8, 4.5, 4.3,
  3.5, 3.8, 4.4, 4.3, 4.3, 4.3, 3.3, 3.3, 3.9, 3.9,
  4.0, 3.2, 3.8, 2.8, 4.8, 5.0, 4.2, 4.5, 4.0, 3.8,
  3.5, 3.4, 3.6, 3.8, 3.4, 4.0, 4.2, 4.5, 3.5, 3.6,
  3.4, 3.0, 3.2, 3.8, 4.2, 3.5, 3.8, 4.2, 1.5, 1.0,
  1.0, 1.2, 0.8, 1.0, 4.5, 4.0, 4.3, 4.5, 4.4, 3.8,
  4.5, 4.3, 4.7, 4.0, 3.5, 4.2, 4.6, 3.5, 3.2, 2.8,
  2.6, 3.5, 3.8, 3.6, 3.4, 4.8, 4.3, 3.0, 5.0, 3.2,
  3.8, 3.6, 3.8, 3.5, 3.4, 3.6, 3.8, 4.0, 3.5, 4.6,
  4.2, 3.8, 3.6, 4.0, 4.3, 4.5, 4.6, 4.8, 4.9, 5.0,
];

const SVM_WEIGHTS: number[] = [
  0.82, 0.91, 0.35, 0.68, 0.42, 0.85, 0.74, 0.93, 0.88, 0.15,
  0.55, 0.89, 0.94, 0.52, 0.58, 0.61, 0.96, 0.54, 0.83, 0.78,
  0.28, 0.56, 0.95, 0.90, 0.81, 0.84, 0.76, 0.98, 0.72, 0.71,
  0.73, 0.92, 0.38, 0.45, 0.22, 0.65, 0.87, 0.89, 0.79, 0.48,
  0.75, 0.86, 0.25, 0.18, 0.12, 0.20, 0.19, 0.17, 0.21, 0.82,
  0.85, 0.62, 0.30, 0.70, 0.64, 0.77, 0.88, 0.63, 0.86, 0.80,
  0.50, 0.66, 0.84, 0.81, 0.80, 0.79, 0.44, 0.43, 0.69, 0.68,
  0.72, 0.36, 0.67, 0.16, 0.94, 0.97, 0.78, 0.85, 0.70, 0.60,
  0.56, 0.48, 0.53, 0.62, 0.50, 0.76, 0.80, 0.87, 0.52, 0.55,
  0.46, 0.32, 0.40, 0.65, 0.79, 0.49, 0.63, 0.80, -0.85, -0.60,
  -0.55, -0.70, -0.45, -0.58, 0.86, 0.74, 0.82, 0.84, 0.83, 0.64,
  0.87, 0.81, 0.92, 0.72, 0.48, 0.80, 0.89, 0.52, 0.38, 0.28,
  0.22, 0.50, 0.62, 0.54, 0.44, 0.91, 0.82, 0.30, 0.95, 0.36,
  0.60, 0.54, 0.62, 0.50, 0.46, 0.52, 0.64, 0.72, 0.48, 0.88,
  0.79, 0.66, 0.58, 0.73, 0.82, 0.86, 0.90, 0.93, 0.95, 0.97,
];

const SVM_BIAS = -0.42;

const BIGRAM_FEATURES: Record<string, number> = {
  "verify account": 0.88, "verify identity": 0.90, "verify information": 0.85,
  "urgent action": 0.92, "urgent response": 0.90, "urgent request": 0.88,
  "account suspended": 0.95, "account locked": 0.93, "account compromised": 0.94,
  "click here": 0.75, "click below": 0.74, "click link": 0.76,
  "confirm identity": 0.88, "confirm password": 0.91, "confirm information": 0.86,
  "reset password": 0.72, "update payment": 0.80, "update information": 0.68,
  "enable macros": 0.97, "enable content": 0.95,
  "dear customer": 0.70, "dear user": 0.75, "dear member": 0.72,
  "valued customer": 0.78, "act now": 0.90, "act immediately": 0.92,
  "final notice": 0.88, "final warning": 0.90, "last chance": 0.85,
  "limited time": 0.72, "wire transfer": 0.93, "gift card": 0.88,
  "social security": 0.97, "credit card": 0.82, "bank account": 0.80,
  "personal information": 0.78, "sensitive information": 0.82,
  "failed delivery": 0.84, "action required": 0.86, "response required": 0.84,
  "security alert": 0.76, "security update": 0.65, "security notice": 0.72,
  "unauthorized access": 0.91, "unusual activity": 0.82, "suspicious activity": 0.84,
  "legal action": 0.88, "court order": 0.90, "arrest warrant": 0.95,
  "tax refund": 0.86, "tax return": 0.82,
  "privacy policy": -0.75, "terms service": -0.65, "manage notifications": -0.70,
  "opt out": -0.72, "no longer": -0.60,
};

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 1);
}

function computeTfidfVector(tokens: string[]): number[] {
  const vec = new Array(SVM_IDF.length).fill(0);
  const counts: Record<string, number> = {};

  for (const token of tokens) {
    counts[token] = (counts[token] || 0) + 1;
  }

  const totalTokens = Math.max(tokens.length, 1);

  for (const [term, idx] of Object.entries(SVM_VOCABULARY)) {
    if (counts[term]) {
      const tf = counts[term] / totalTokens;
      vec[idx] = tf * SVM_IDF[idx];
    }
  }

  return vec;
}

function extractBigramFeatures(text: string): number {
  const lower = text.toLowerCase();
  let bigramScore = 0;
  let bigramCount = 0;

  for (const [bigram, weight] of Object.entries(BIGRAM_FEATURES)) {
    const escaped = bigram.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`\\b${escaped}\\b`, "gi");
    const matches = lower.match(regex);
    if (matches) {
      bigramScore += weight * matches.length;
      bigramCount += matches.length;
    }
  }

  return bigramCount > 0 ? bigramScore / bigramCount : 0;
}

function dotProduct(a: number[], b: number[]): number {
  let sum = 0;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    sum += a[i] * b[i];
  }
  return sum;
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export interface SvmResult {
  phishingProbability: number;
  confidence: number;
  svmScore: number;
  topFeatures: Array<{ feature: string; weight: number }>;
  featureCount: number;
}

export function classifyWithSvm(text: string): SvmResult {
  if (!text || text.trim().length < 10) {
    return { phishingProbability: 0, confidence: 0, svmScore: 0, topFeatures: [], featureCount: 0 };
  }

  const tokens = tokenize(text);
  const tfidfVec = computeTfidfVector(tokens);

  const rawDecision = dotProduct(tfidfVec, SVM_WEIGHTS) + SVM_BIAS;

  const bigramBoost = extractBigramFeatures(text);
  const combinedDecision = rawDecision + bigramBoost * 0.4;

  const probability = sigmoid(combinedDecision * 2.5);

  const featureContributions: Array<{ feature: string; weight: number }> = [];
  for (const [term, idx] of Object.entries(SVM_VOCABULARY)) {
    if (tfidfVec[idx] > 0) {
      featureContributions.push({
        feature: term,
        weight: Math.round(tfidfVec[idx] * SVM_WEIGHTS[idx] * 1000) / 1000,
      });
    }
  }

  for (const [bigram, bWeight] of Object.entries(BIGRAM_FEATURES)) {
    if (bWeight > 0 && text.toLowerCase().includes(bigram)) {
      featureContributions.push({
        feature: bigram,
        weight: Math.round(bWeight * 0.4 * 1000) / 1000,
      });
    }
  }

  featureContributions.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

  const confidence = Math.abs(probability - 0.5) * 2;

  return {
    phishingProbability: Math.round(probability * 1000) / 1000,
    confidence: Math.round(confidence * 1000) / 1000,
    svmScore: Math.round(combinedDecision * 1000) / 1000,
    topFeatures: featureContributions.slice(0, 10),
    featureCount: featureContributions.length,
  };
}
