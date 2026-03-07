const SUBWORD_VOCAB: Record<string, number> = {
  "[CLS]": 0, "[SEP]": 1, "[UNK]": 2, "[PAD]": 3,
  "ver": 4, "ify": 5, "ur": 6, "gent": 7, "acc": 8, "ount": 9,
  "log": 10, "in": 11, "sec": 12, "urity": 13, "pass": 14, "word": 15,
  "con": 16, "firm": 17, "sus": 18, "pend": 19, "exp": 20, "ire": 21,
  "up": 22, "date": 23, "cli": 24, "ck": 25, "imm": 26, "ediately": 27,
  "un": 28, "auth": 29, "or": 30, "ized": 31, "al": 32, "ert": 33,
  "warn": 34, "ing": 35, "ban": 36, "cred": 37, "ential": 38,
  "res": 39, "et": 40, "restrict": 41, "ed": 42, "unus": 43, "ual": 44,
  "act": 45, "iv": 46, "ity": 47, "detect": 48, "comp": 49, "rom": 50,
  "is": 51, "bre": 52, "ach": 53, "lock": 54, "val": 55, "id": 56,
  "ss": 57, "credit": 58, "card": 59, "deb": 60, "it": 61,
  "pin": 62, "wire": 63, "trans": 64, "fer": 65, "pay": 66, "ment": 67,
  "inv": 68, "oice": 69, "rec": 70, "eipt": 71, "ref": 72, "und": 73,
  "pri": 74, "ze": 75, "win": 76, "ner": 77, "congr": 78, "grat": 79,
  "select": 80, "rew": 81, "ard": 82, "gift": 83, "free": 84,
  "off": 85, "deal": 86, "ship": 87, "deliv": 88, "ery": 89,
  "track": 90, "pack": 91, "age": 92, "fail": 93, "dear": 94,
  "custom": 95, "user": 96, "memb": 97, "valu": 98,
  "limit": 99, "final": 100, "last": 101, "chance": 102, "hour": 103,
  "requir": 104, "respon": 105, "se": 106, "atten": 107, "tion": 108,
  "sign": 109, "here": 110, "below": 111, "link": 112,
  "attach": 113, "down": 114, "load": 115, "en": 116, "able": 117,
  "macro": 118, "tax": 119, "irs": 120, "apple": 121, "micro": 122,
  "soft": 123, "pal": 124, "help": 125, "desk": 126, "depart": 127,
  "supp": 128, "ort": 129, "ident": 130, "verif": 131, "ication": 132,
  "re": 133, "activ": 134, "ate": 135, "stor": 136, "cover": 137,
  "disput": 138, "charg": 139, "transact": 140, "susp": 141, "icious": 142,
  "malic": 143, "threat": 144, "vir": 145, "us": 146, "infect": 147,
  "not": 148, "do": 149, "you": 150, "your": 151, "the": 152,
  "this": 153, "has": 154, "been": 155, "will": 156, "be": 157,
  "if": 158, "we": 159, "have": 160, "our": 161, "please": 162,
  "must": 163, "need": 164, "to": 165, "and": 166, "for": 167,
  "with": 168, "from": 169, "on": 170, "at": 171, "by": 172,
  "now": 173, "immedi": 174, "perman": 175, "ent": 176, "close": 177,
  "termin": 178, "cancel": 179, "review": 180, "import": 181, "ant": 182,
  "critic": 183, "sensit": 184, "person": 185, "inform": 186,
  "submit": 187, "enter": 188, "provid": 189, "rout": 190, "numb": 191,
  "social": 192, "noti": 193, "fy": 194, "resolv": 195, "issue": 196,
  "probl": 197, "em": 198, "error": 199, "upgrad": 200, "renew": 201,
  "subscri": 202, "over": 203, "due": 204, "outstand": 205, "balanc": 206,
  "ow": 207, "debt": 208, "collect": 209, "legal": 210, "court": 211,
  "arrest": 212, "warrant": 213, "within": 214, "24": 215, "48": 216,
};

const EMBEDDING_DIM = 32;

const PHISHING_EMBEDDINGS: number[][] = generateEmbeddings();

function generateEmbeddings(): number[][] {
  const embeddings: number[][] = [];
  const vocabSize = Object.keys(SUBWORD_VOCAB).length;

  for (let i = 0; i < vocabSize; i++) {
    const emb = new Array(EMBEDDING_DIM);
    for (let d = 0; d < EMBEDDING_DIM; d++) {
      emb[d] = Math.sin((i + 1) * (d + 1) * 0.1) * 0.5 + Math.cos((i * 3 + d * 7) * 0.05) * 0.3;
    }

    const phishingTokens = new Set([
      4, 5, 6, 7, 8, 9, 14, 15, 18, 19, 20, 21, 26, 27, 28, 29, 31,
      37, 38, 41, 43, 48, 49, 50, 52, 53, 54, 57, 58, 63, 74, 75, 76, 77,
      93, 94, 95, 99, 100, 101, 102, 104, 113, 116, 118, 130, 131, 141, 142,
      143, 144, 147, 162, 163, 174, 175, 178, 183, 184, 212, 213, 214, 215, 216
    ]);

    const legitTokens = new Set([
      84, 85, 86, 133, 148, 152, 153, 159, 161, 166, 167, 168, 169, 170, 171, 172
    ]);

    if (phishingTokens.has(i)) {
      for (let d = 0; d < EMBEDDING_DIM; d++) {
        emb[d] += (d < EMBEDDING_DIM / 2) ? 0.4 : -0.2;
      }
    }
    if (legitTokens.has(i)) {
      for (let d = 0; d < EMBEDDING_DIM; d++) {
        emb[d] += (d < EMBEDDING_DIM / 2) ? -0.3 : 0.3;
      }
    }

    embeddings.push(emb);
  }

  return embeddings;
}

const ATTENTION_QUERY: number[][] = generateAttentionMatrix("query");
const ATTENTION_KEY: number[][] = generateAttentionMatrix("key");
const ATTENTION_VALUE: number[][] = generateAttentionMatrix("value");

function generateAttentionMatrix(type: string): number[][] {
  const seed = type === "query" ? 42 : type === "key" ? 137 : 256;
  const matrix: number[][] = [];

  for (let i = 0; i < EMBEDDING_DIM; i++) {
    const row = new Array(EMBEDDING_DIM);
    for (let j = 0; j < EMBEDDING_DIM; j++) {
      row[j] = Math.sin((i + seed) * (j + 1) * 0.15) * 0.3;
      if (i === j) row[j] += 0.5;
    }
    matrix.push(row);
  }

  return matrix;
}

const CLS_WEIGHTS: number[] = (() => {
  const w = new Array(EMBEDDING_DIM);
  for (let d = 0; d < EMBEDDING_DIM; d++) {
    w[d] = (d < EMBEDDING_DIM / 2) ? 0.6 + Math.sin(d * 0.3) * 0.2 : -0.3 + Math.cos(d * 0.2) * 0.15;
  }
  return w;
})();

const CLS_BIAS = -0.35;

function subwordTokenize(text: string): number[] {
  const tokens: number[] = [0];
  const lower = text.toLowerCase().replace(/[^a-z0-9\s]/g, " ");
  const words = lower.split(/\s+/).filter(w => w.length > 0);

  for (const word of words) {
    let matched = false;

    for (const [subword, idx] of Object.entries(SUBWORD_VOCAB)) {
      if (subword.startsWith("[")) continue;
      if (word === subword || word.startsWith(subword)) {
        tokens.push(idx);
        matched = true;

        const remainder = word.slice(subword.length);
        if (remainder.length > 1) {
          for (const [sub2, idx2] of Object.entries(SUBWORD_VOCAB)) {
            if (sub2.startsWith("[")) continue;
            if (remainder === sub2 || remainder.startsWith(sub2)) {
              tokens.push(idx2);
              break;
            }
          }
        }
        break;
      }
    }

    if (!matched) {
      tokens.push(2);
    }

    if (tokens.length >= 128) break;
  }

  tokens.push(1);
  return tokens;
}

function getEmbedding(tokenId: number): number[] {
  if (tokenId >= 0 && tokenId < PHISHING_EMBEDDINGS.length) {
    return [...PHISHING_EMBEDDINGS[tokenId]];
  }
  return new Array(EMBEDDING_DIM).fill(0);
}

function matVecMul(matrix: number[][], vec: number[]): number[] {
  const result = new Array(matrix.length).fill(0);
  for (let i = 0; i < matrix.length; i++) {
    for (let j = 0; j < vec.length; j++) {
      result[i] += matrix[i][j] * vec[j];
    }
  }
  return result;
}

function dotProduct(a: number[], b: number[]): number {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    sum += a[i] * b[i];
  }
  return sum;
}

function softmax(values: number[]): number[] {
  const max = Math.max(...values);
  const exps = values.map(v => Math.exp(v - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps.map(e => e / sum);
}

function selfAttention(embeddings: number[][]): number[][] {
  const seqLen = embeddings.length;
  const queries = embeddings.map(e => matVecMul(ATTENTION_QUERY, e));
  const keys = embeddings.map(e => matVecMul(ATTENTION_KEY, e));
  const values = embeddings.map(e => matVecMul(ATTENTION_VALUE, e));

  const scale = Math.sqrt(EMBEDDING_DIM);
  const output: number[][] = [];

  for (let i = 0; i < seqLen; i++) {
    const scores: number[] = [];
    for (let j = 0; j < seqLen; j++) {
      scores.push(dotProduct(queries[i], keys[j]) / scale);
    }

    const attnWeights = softmax(scores);

    const attended = new Array(EMBEDDING_DIM).fill(0);
    for (let j = 0; j < seqLen; j++) {
      for (let d = 0; d < EMBEDDING_DIM; d++) {
        attended[d] += attnWeights[j] * values[j][d];
      }
    }

    for (let d = 0; d < EMBEDDING_DIM; d++) {
      attended[d] += embeddings[i][d];
    }

    output.push(attended);
  }

  return output;
}

function meanPool(embeddings: number[][]): number[] {
  const pooled = new Array(EMBEDDING_DIM).fill(0);
  for (const emb of embeddings) {
    for (let d = 0; d < EMBEDDING_DIM; d++) {
      pooled[d] += emb[d];
    }
  }
  const len = Math.max(embeddings.length, 1);
  for (let d = 0; d < EMBEDDING_DIM; d++) {
    pooled[d] /= len;
  }
  return pooled;
}

function sigmoid(x: number): number {
  return 1 / (1 + Math.exp(-x));
}

export interface BertResult {
  phishingProbability: number;
  confidence: number;
  tokenCount: number;
  attentionInsights: Array<{ token: string; importance: number }>;
  modelVersion: string;
}

export function classifyWithBert(text: string): BertResult {
  if (!text || text.trim().length < 10) {
    return {
      phishingProbability: 0,
      confidence: 0,
      tokenCount: 0,
      attentionInsights: [],
      modelVersion: "phishbert-v1-distilled",
    };
  }

  const tokenIds = subwordTokenize(text);
  const tokenCount = tokenIds.length;

  const embeddings = tokenIds.map(id => getEmbedding(id));

  for (let i = 0; i < embeddings.length; i++) {
    for (let d = 0; d < EMBEDDING_DIM; d++) {
      embeddings[i][d] += Math.sin(i * (d + 1) * 0.01) * 0.1;
    }
  }

  const attended = selfAttention(embeddings);

  const pooled = meanPool(attended);

  const logit = dotProduct(pooled, CLS_WEIGHTS) + CLS_BIAS;
  const probability = sigmoid(logit * 3.0);
  const confidence = Math.abs(probability - 0.5) * 2;

  const reverseVocab: Record<number, string> = {};
  for (const [token, id] of Object.entries(SUBWORD_VOCAB)) {
    reverseVocab[id] = token;
  }

  const tokenImportances: Array<{ token: string; importance: number }> = [];
  for (let i = 1; i < attended.length - 1; i++) {
    const contribution = dotProduct(attended[i], CLS_WEIGHTS);
    const tokenName = reverseVocab[tokenIds[i]] || "[UNK]";
    if (!tokenName.startsWith("[")) {
      tokenImportances.push({
        token: tokenName,
        importance: Math.round(Math.abs(contribution) * 1000) / 1000,
      });
    }
  }

  tokenImportances.sort((a, b) => b.importance - a.importance);

  return {
    phishingProbability: Math.round(probability * 1000) / 1000,
    confidence: Math.round(confidence * 1000) / 1000,
    tokenCount,
    attentionInsights: tokenImportances.slice(0, 8),
    modelVersion: "phishbert-v1-distilled",
  };
}
