#!/usr/bin/env node
import { setupCli } from "./cli/setup.ts";
import { enterCorporateSandbox } from "./core/corporate-sandbox.ts";
import { main } from "./main.ts";

if (await enterCorporateSandbox()) {
	setupCli();
	main(process.argv.slice(2));
}
