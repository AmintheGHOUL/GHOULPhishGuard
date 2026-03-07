import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { emailInputSchema } from "@shared/schema";
import { analyzeEmail } from "./services/analyzeEmail";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  app.use("/api", (req: Request, res: Response, next: NextFunction) => {
    res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    res.header("Access-Control-Allow-Credentials", "true");
    if (req.method === "OPTIONS") {
      return res.sendStatus(204);
    }
    next();
  });

  app.post("/api/analyze-email", async (req, res) => {
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
      console.error("Analysis error:", error);
      res.status(500).json({
        error: "analysis_failed",
        message: error.message || "Unexpected analysis error",
      });
    }
  });

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, service: "phishguard-backend" });
  });

  return httpServer;
}
