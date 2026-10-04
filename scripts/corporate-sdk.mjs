#!/usr/bin/env node
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { launchCorporateProcess } from "../packages/coding-agent/dist/core/corporate-sandbox.js";

const entry = process.argv[2];
if (!entry) throw new Error("Usage: node scripts/corporate-sdk.mjs path/to/app.mjs [arguments]");
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
await launchCorporateProcess({
	entry: resolve(entry),
	args: process.argv.slice(3),
	cli: join(root, "packages/coding-agent/dist/bundle/cli.js"),
	protectedPaths: [fileURLToPath(import.meta.url)],
});
