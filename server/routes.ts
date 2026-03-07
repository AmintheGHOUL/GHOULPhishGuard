import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { emailInputSchema } from "@shared/schema";
import { analyzeEmail } from "./services/analyzeEmail";
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

  const forwarded = req.headers["x-forwarded-for"];
  const ip = typeof forwarded === "string" ? forwarded.split(",")[0].trim() : req.socket.remoteAddress || "";
  const local = ["127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"];

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
    const allowedOrigin = process.env.ALLOWED_ORIGIN || req.headers.origin || "";
    if (allowedOrigin) {
      res.header("Access-Control-Allow-Origin", allowedOrigin);
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

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, service: "ghoulphishguard-backend" });
  });

  return httpServer;
}
