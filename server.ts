/**
 * ARC Defender — Express Server Entry Point
 *
 * Serves both:
 * 1. The demo application being monitored (simulating a real API)
 * 2. The ARC Defender dashboard and analytics/security API
 */

import express, { Request, Response } from "express";
import path from "path";
import { config } from "./src/config.js";
import { arcMonitorMiddleware, markLogin } from "./src/monitor.js";
import { arcApi } from "./src/api.js";
import { seedInitialData } from "./src/simulator.js";

const app = express();
const PORT = config.PORT;
const HOST = "0.0.0.0";

// CORS & Security headers for iframe and cross-origin embedding
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Attach monitoring middleware to automatically record requests
app.use(arcMonitorMiddleware);

// Static assets
app.use("/static", express.static(path.join(process.cwd(), "static")));

// ARC Defender API blueprint
app.use("/arc/api", arcApi);
app.use("/arc-api", arcApi);

// Health check endpoints
app.get(["/health", "/arc/health", "/api/health"], (req: Request, res: Response) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// ARC Defender Dashboard - Serve on both root and /arc/dashboard
app.get(["/", "/arc/dashboard", "/dashboard"], (req: Request, res: Response) => {
  res.sendFile(path.join(process.cwd(), "templates", "dashboard.html"));
});

// ====================================================================
// Demo application routes (the "monitored" application)
// ====================================================================

app.get("/api/users", (req: Request, res: Response) => {
  res.json({
    users: [
      { id: 1, name: "Alice" },
      { id: 2, name: "Bob" },
      { id: 3, name: "Charlie" },
    ],
  });
});

app.get("/api/users/:id", (req: Request, res: Response) => {
  const users: Record<number, string> = { 1: "Alice", 2: "Bob", 3: "Charlie" };
  const userId = parseInt(req.params.id, 10);
  if (userId in users) {
    res.json({ id: userId, name: users[userId] });
    return;
  }
  res.status(404).json({ error: "User not found" });
});

app.get("/api/products", (req: Request, res: Response) => {
  res.json({
    products: [
      { id: 1, name: "Widget", price: 9.99 },
      { id: 2, name: "Gadget", price: 24.99 },
    ],
  });
});

app.all("/api/orders", (req: Request, res: Response) => {
  if (req.method === "POST") {
    res.status(201).json({ order_id: 1001, status: "created" });
    return;
  }
  res.json({ orders: [] });
});

app.post("/api/login", (req: Request, res: Response) => {
  const { username, password } = req.body || {};
  if (username === "admin" && password === "secret") {
    markLogin(req, true);
    res.json({ status: "success", message: "Login successful" });
  } else {
    markLogin(req, false);
    res.status(401).json({ status: "failure", message: "Invalid credentials" });
  }
});

app.get("/api/health", (req: Request, res: Response) => {
  res.json({ status: "healthy" });
});

app.get("/api/error", (req: Request, res: Response) => {
  res.status(500).json({ error: "Internal server error" });
});

// Seed initial realistic telemetry on startup
seedInitialData();

app.listen(PORT, HOST, () => {
  console.log(`\n============================================================`);
  console.log(`  ARC Defender Server`);
  console.log(`  Demo API:    http://${HOST}:${PORT}/`);
  console.log(`  Dashboard:   http://${HOST}:${PORT}/arc/dashboard`);
  console.log(`  API docs:    http://${HOST}:${PORT}/arc/api/overview`);
  console.log(`============================================================\n`);
});
