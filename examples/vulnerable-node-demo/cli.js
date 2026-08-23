#!/usr/bin/env node
// vulnerable-node-demo — a deliberately vulnerable Node.js command-line service.
//
// This is a NON-Python target used to exercise KavachX's language-agnostic black-box harness.
// It reads one JSON request from `--request` and prints one JSON response, so it fits the same
// request -> output model as the Python demo, but there is no Python tracer involved: KavachX
// observes it entirely from the outside (exit code, stdout, filesystem diff, planted tokens).
//
// Each weakness is marked with a `SEEDED VULNERABILITY` comment naming its CWE. The comments are
// there on purpose — the point is that KavachX has to PROVE each one by execution, not by reading
// the comment.
"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const ASSET_ROOT = path.join(__dirname, "assets");

function parseRequest(argv) {
  const i = argv.indexOf("--request");
  if (i === -1 || i + 1 >= argv.length) {
    throw new Error("a JSON request is required: --request '{...}'");
  }
  return JSON.parse(argv[i + 1]);
}

function handle(req) {
  const op = String(req.op || "");

  if (op === "ping") {
    return { ok: true, op: "ping" };
  }

  if (op === "export") {
    // SEEDED VULNERABILITY: OS command injection (CWE-78).
    // `name` is interpolated into a string that is run through a shell.
    const name = String(req.name || "report");
    const output = execSync(`echo Exporting report: ${name}`, { encoding: "utf8" });
    return { ok: true, op: "export", output: output.trim() };
  }

  if (op === "read_asset") {
    // SEEDED VULNERABILITY: path traversal (CWE-22).
    // `relative_path` is joined to ASSET_ROOT and never confined to it.
    const rel = String(req.path || "");
    const full = path.join(ASSET_ROOT, rel);
    const content = fs.readFileSync(full, "utf8");
    return { ok: true, op: "read_asset", path: rel, content: content };
  }

  return { ok: false, error: `unknown op: ${op}` };
}

function main() {
  let req;
  try {
    req = parseRequest(process.argv.slice(2));
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(e.message) }) + "\n");
    process.exit(2);
  }
  try {
    const res = handle(req);
    process.stdout.write(JSON.stringify(res) + "\n");
    process.exit(res.ok ? 0 : 1);
  } catch (e) {
    process.stdout.write(JSON.stringify({ ok: false, error: String(e.message) }) + "\n");
    process.exit(1);
  }
}

main();
