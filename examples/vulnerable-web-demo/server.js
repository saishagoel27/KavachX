#!/usr/bin/env node
// vulnerable-web-demo — a deliberately vulnerable Node.js HTTP server (built-ins only, no deps).
//
// A LONG-RUNNING server target for KavachX's HTTP black-box harness: KavachX starts it with the
// configured start command + env, waits for the port, drives it with HTTP requests, observes the
// responses and filesystem side effects, then mutates requests to prove vulnerabilities.
//
// Each weakness is marked with a SEEDED VULNERABILITY comment naming its CWE.
"use strict";

const http = require("http");
const url = require("url");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const PORT = parseInt(process.env.PORT || "8787", 10);
const HOST = process.env.HOST || "127.0.0.1";
const ASSET_ROOT = path.join(__dirname, "assets");

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const q = parsed.query || {};
  res.setHeader("Content-Type", "application/json");
  try {
    if (parsed.pathname === "/ping") {
      res.end(JSON.stringify({ ok: true, op: "ping" }));
      return;
    }
    if (parsed.pathname === "/export") {
      // SEEDED VULNERABILITY: OS command injection (CWE-78).
      // `name` is interpolated into a string run through a shell.
      const name = String(q.name || "report");
      const out = execSync(`echo Exporting report: ${name}`, { encoding: "utf8" });
      res.end(JSON.stringify({ ok: true, op: "export", output: out.trim() }));
      return;
    }
    if (parsed.pathname === "/asset") {
      // SEEDED VULNERABILITY: path traversal (CWE-22).
      // `path` is joined to ASSET_ROOT and never confined to it.
      const rel = String(q.path || "");
      const content = fs.readFileSync(path.join(ASSET_ROOT, rel), "utf8");
      res.end(JSON.stringify({ ok: true, op: "read_asset", content: content }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ ok: false, error: "not found" }));
  } catch (e) {
    res.statusCode = 500;
    res.end(JSON.stringify({ ok: false, error: String(e.message) }));
  }
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`listening on http://${HOST}:${PORT}\n`);
});
