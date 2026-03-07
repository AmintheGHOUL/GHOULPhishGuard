import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { emailInputSchema } from "@shared/schema";
import { analyzeEmail } from "./services/analyzeEmail";
import { isModelLoaded, isModelLoading } from "./services/realBertClassifier";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

const analysisLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "rate_limited", message: "Too many requests. Please wait a moment and try again." },
});

function isLocalOnly(): boolean {
  return process.env.LOCAL_ONLY === "true" || process.env.LOCAL_ONLY === "1";
}

function localOnlyGuard(req: Request, res: Response, next: NextFunction) {
  if (!isLocalOnly()) return next();

  const ip = req.socket.remoteAddress || "";
  const local = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];

  if (local.includes(ip)) {
    return next();
  }

  return res.status(403).json({ error: "forbidden", message: "This instance is running in local-only mode." });
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:"],
          connectSrc: ["'self'", "ws:", "wss:"],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );

  app.use("/api", (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin || "";
    const allowedOrigins = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(",").map((o) => o.trim())
      : [];

    if (allowedOrigins.length > 0) {
      if (allowedOrigins.includes(origin)) {
        res.header("Access-Control-Allow-Origin", origin);
      }
    } else {
      res.header("Access-Control-Allow-Origin", origin || "*");
    }

    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    res.header("Access-Control-Allow-Credentials", "true");
    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }
    next();
  });

  app.post("/api/analyze-email", localOnlyGuard, analysisLimiter, async (req, res) => {
    try {
      const parsed = emailInputSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          error: "invalid_input",
          message: "Invalid email data provided",
        });
      }

      const result = await analyzeEmail(parsed.data);
      res.json(result);
    } catch (error: any) {
      console.error("Analysis error (no user content logged)");
      res.status(500).json({
        error: "analysis_failed",
        message: "Unexpected analysis error",
      });
    }
  });

  // GET /api/model-status — exposes BERT model load state for frontend status indicators
  app.get("/api/model-status", (_req, res) => {
    const loaded = isModelLoaded();
    const loading = isModelLoading();

    let status: "loaded" | "loading" | "failed" | "idle";
    if (loaded) {
      status = "loaded";
    } else if (loading) {
      status = "loading";
    } else {
      status = "failed";
    }

    res.json({
      model: "distilbert-phishing-v2.4.1",
      status,
      ready: loaded,
    });
  });

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, service: "ghoulphishguard-backend" });
  });

  // --- Security measures summary ---
  // 1. Helmet CSP: Restricts script/style/font/img/connect sources (applied above)
  // 2. Rate limiting: /api/analyze-email limited to 20 req/min per IP
  // 3. CORS: Origin whitelist via ALLOWED_ORIGINS env var; defaults to open for dev
  // 4. LOCAL_ONLY guard: When LOCAL_ONLY=true, analysis endpoint rejects non-localhost IPs
  // 5. Input validation: All POST bodies validated with Zod schemas before processing
  // 6. Request body size limit: 500kb cap set in server/index.ts
  // 7. No user content logged: Error handlers avoid logging email content to prevent data leaks
  // 8. trust proxy: Set to 1 so rate limiter uses correct client IP behind reverse proxy

  return httpServer;
}
