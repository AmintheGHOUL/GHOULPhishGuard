import { createHash } from "crypto";

let classifierPipeline: any = null;
let modelLoadingPromise: Promise<any> | null = null;
let modelLoadFailed = false;

const MODEL_ID = "onnx-community/phishing-email-detection-distilbert_v2.4.1-ONNX";
const MAX_TEXT_LENGTH = 2000;

const LABEL_MAP: Record<string, string> = {
  "LABEL_0": "legitimate_email",
  "LABEL_1": "phishing_url",
  "LABEL_2": "legitimate_url",
  "LABEL_3": "phishing_url_alt",
};

const PHISHING_LABELS = new Set(["LABEL_1", "LABEL_3", "phishing_url", "phishing_url_alt"]);

interface CachedResult {
  phishingProb: number;
  confidence: number;
  label: string;
  timestamp: number;
}

const resultCache = new Map<string, CachedResult>();
const CACHE_TTL = 1000 * 60 * 30;
const MAX_CACHE_SIZE = 200;

function hashText(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

function cleanCache() {
  if (resultCache.size <= MAX_CACHE_SIZE) return;
  const now = Date.now();
  for (const [key, val] of resultCache) {
    if (now - val.timestamp > CACHE_TTL) resultCache.delete(key);
  }
  if (resultCache.size > MAX_CACHE_SIZE) {
    const keys = Array.from(resultCache.keys());
    for (let i = 0; i < keys.length - MAX_CACHE_SIZE; i++) {
      resultCache.delete(keys[i]);
    }
  }
}

async function loadModel() {
  if (classifierPipeline) return classifierPipeline;
  if (modelLoadFailed) return null;

  if (modelLoadingPromise) return modelLoadingPromise;

  modelLoadingPromise = (async () => {
    try {
      console.log(`[DistilBERT] Loading model ${MODEL_ID}...`);
      const { pipeline } = await import("@huggingface/transformers");
      classifierPipeline = await pipeline("text-classification", MODEL_ID, {
        dtype: "q8",
        top_k: 4,
      });
      console.log(`[DistilBERT] Model loaded successfully.`);
      return classifierPipeline;
    } catch (err: any) {
      console.error(`[DistilBERT] Failed to load model: ${err.message}`);
      modelLoadFailed = true;
      modelLoadingPromise = null;
      return null;
    }
  })();

  return modelLoadingPromise;
}

loadModel().catch(() => {});

export interface RealBertResult {
  phishingProbability: number;
  confidence: number;
  label: string;
  modelSource: "real";
  modelVersion: string;
}

export async function classifyWithRealBert(text: string): Promise<RealBertResult | null> {
  if (!text || text.trim().length < 10) return null;

  const truncated = text.slice(0, MAX_TEXT_LENGTH);
  const hash = hashText(truncated);

  const cached = resultCache.get(hash);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return {
      phishingProbability: cached.phishingProb,
      confidence: cached.confidence,
      label: cached.label,
      modelSource: "real",
      modelVersion: "distilbert-phishing-v2.4.1",
    };
  }

  const classifier = await loadModel();
  if (!classifier) return null;

  try {
    const results = await classifier(truncated);
    if (!results || results.length === 0) return null;

    let phishingProb = 0;
    let topLabel = "legitimate_email";
    let topScore = 0;

    const allResults = Array.isArray(results[0]) ? results[0] : results;

    for (const r of allResults) {
      const rawLabel: string = r.label;
      const score: number = r.score;

      if (PHISHING_LABELS.has(rawLabel)) {
        phishingProb += score;
      }

      if (score > topScore) {
        topScore = score;
        topLabel = LABEL_MAP[rawLabel] || rawLabel;
      }
    }

    phishingProb = Math.round(Math.min(1, phishingProb) * 1000) / 1000;
    const confidence = Math.round(topScore * 1000) / 1000;

    cleanCache();
    resultCache.set(hash, { phishingProb, confidence, label: topLabel, timestamp: Date.now() });

    return {
      phishingProbability: phishingProb,
      confidence,
      label: topLabel,
      modelSource: "real",
      modelVersion: "distilbert-phishing-v2.4.1",
    };
  } catch (err: any) {
    console.error(`[DistilBERT] Inference error: ${err.message}`);
    return null;
  }
}

export function isModelLoaded(): boolean {
  return classifierPipeline !== null;
}

export function isModelLoading(): boolean {
  return modelLoadingPromise !== null && !classifierPipeline && !modelLoadFailed;
}
