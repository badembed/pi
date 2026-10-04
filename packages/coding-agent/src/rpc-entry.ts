#!/usr/bin/env node
import { APP_NAME } from "./config.ts";
import { enterCorporateSandbox } from "./core/corporate-sandbox.ts";
import { configureHttpDispatcher } from "./core/http-dispatcher.ts";
import { main } from "./main.ts";

if (await enterCorporateSandbox()) {
	process.title = `${APP_NAME}-rpc`;
	process.env.PI_CODING_AGENT = "true";
	process.env.AI_AGENT = "pi";
	process.env.PI_OFFLINE = "1";
	process.env.PI_TELEMETRY = "0";
	process.env.ACP_AUTO_UPDATE = "0";
	process.env.PI_EXPERIMENTAL = "0";
	process.emitWarning = (() => {}) as typeof process.emitWarning;

	configureHttpDispatcher();

	main(["--mode", "rpc", ...process.argv.slice(2)]);
}
