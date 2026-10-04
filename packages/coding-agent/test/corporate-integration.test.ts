import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const cli = join(root, "packages/coding-agent/dist/bundle/cli.js");
const extension = process.env.PI_CORPORATE_TEST_EXTENSION ?? resolve(root, "../billion-context-pi/dist/index.js");
const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => {
	for (const close of cleanup.splice(0).reverse()) await close();
});

function run(entry: string, args: string[], cwd: string, agentDir: string, input?: string, awaitAgentEnd = false) {
	return new Promise<{ code: number | null; stdout: string; stderr: string }>((done, reject) => {
		const child = spawn(process.execPath, [entry, ...args], {
			cwd,
			env: {
				...process.env,
				PI_CODING_AGENT_DIR: agentDir,
				CORPORATE_TEST_KEY: "synthetic-corporate-key",
				OPENAI_API_KEY: "synthetic-public-key",
				ACP_LOG_LEVEL: "debug",
				PI_TELEMETRY: "1",
				ACP_AUTO_UPDATE: "1",
				NODE_EXTRA_CA_CERTS: existsSync(join(agentDir, "test-ca.pem")) ? join(agentDir, "test-ca.pem") : undefined,
			},
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
			if (awaitAgentEnd && stdout.includes('"type":"agent_end"')) child.stdin.end();
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
		});
		const timer = setTimeout(() => child.kill("SIGTERM"), 25000);
		child.on("error", reject);
		child.on("close", (code) => {
			clearTimeout(timer);
			done({ code, stdout, stderr });
		});
		if (input !== undefined) child.stdin.write(input);
		if (!awaitAgentEnd) child.stdin.end();
	});
}

async function fixture(withExtension = false, redirect = false, tls = false) {
	const directory = await mkdtemp(join(tmpdir(), "pi-corporate-integration-"));
	cleanup.push(() => rm(directory, { recursive: true, force: true }));
	const cwd = join(directory, "project");
	const agentDir = join(directory, "agent");
	await mkdir(cwd);
	await mkdir(agentDir);
	const requests: { body: string; authorization: string | undefined; path: string | undefined }[] = [];
	const handler = async (req: IncomingMessage, res: ServerResponse) => {
		let body = "";
		for await (const chunk of req) body += chunk;
		requests.push({ body, authorization: req.headers.authorization, path: req.url });
		if (redirect) {
			res.writeHead(307, { Location: "http://127.0.0.1:9/collect" }).end();
			return;
		}
		const parsed = JSON.parse(body) as { messages: { role: string; content: unknown }[] };
		const last = parsed.messages.at(-1);
		const delegate = last?.role === "user" && JSON.stringify(last.content).includes("SYNTHETIC_DELEGATE");
		const callTool = !delegate && last?.role === "user" && JSON.stringify(last.content).includes("RUN_DELEGATE");
		const content = last?.role === "user" ? JSON.stringify(last.content) : "";
		const testTool = callTool
			? { name: "acp_delegate", arguments: { agent: "worker", task: "SYNTHETIC_DELEGATE", async: false } }
			: content.includes("RUN_CODE_WRITE")
				? { name: "write", arguments: { path: "corporate-proof.txt", content: "synthetic-code" } }
				: content.includes("RUN_CODE_READ")
					? { name: "read", arguments: { path: "corporate-proof.txt" } }
					: content.includes("RUN_CODE_BASH")
						? { name: "bash", arguments: { command: "printf corporate-bash" } }
						: undefined;
		const delta = testTool
			? {
					tool_calls: [
						{
							index: 0,
							id: "delegate-test",
							type: "function",
							function: {
								name: testTool.name,
								arguments: JSON.stringify(testTool.arguments),
							},
						},
					],
				}
			: { role: "assistant", content: delegate ? "delegate-ok" : "main-ok" };
		const chunk = (data: unknown) => `data: ${JSON.stringify(data)}\n\n`;
		res.writeHead(200, { "Content-Type": "text/event-stream" });
		res.end(
			chunk({ id: "test", choices: [{ index: 0, delta, finish_reason: null }] }) +
				chunk({ id: "test", choices: [{ index: 0, delta: {}, finish_reason: testTool ? "tool_calls" : "stop" }] }) +
				"data: [DONE]\n\n",
		);
	};
	let tlsOptions: { key: Buffer; cert: Buffer } | undefined;
	if (tls) {
		const key = join(agentDir, "test-key.pem");
		const cert = join(agentDir, "test-ca.pem");
		const generated = spawnSync(
			"openssl",
			[
				"req",
				"-x509",
				"-newkey",
				"rsa:2048",
				"-nodes",
				"-days",
				"1",
				"-subj",
				"/CN=127.0.0.1",
				"-addext",
				"subjectAltName=IP:127.0.0.1",
				"-keyout",
				key,
				"-out",
				cert,
			],
			{ encoding: "utf8" },
		);
		if (generated.status !== 0) throw new Error(`Synthetic certificate generation failed: ${generated.stderr}`);
		tlsOptions = { key: await readFile(key), cert: await readFile(cert) };
	}
	const server = tlsOptions ? createHttpsServer(tlsOptions, handler) : createServer(handler);
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	cleanup.push(async () => {
		server.closeAllConnections();
		await new Promise<void>((done) => server.close(() => done()));
	});
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("No fixture port");
	const origin = `${tls ? "https" : "http"}://127.0.0.1:${address.port}`;
	await writeFile(
		join(agentDir, "network-policy.json"),
		JSON.stringify({
			providers: { corporate: { modelOrigins: [origin] } },
			extensions: withExtension
				? [
						{
							path: extension,
							sha256: createHash("sha256")
								.update(await readFile(extension))
								.digest("hex"),
						},
					]
				: [],
		}),
	);
	await writeFile(
		join(agentDir, "models.json"),
		JSON.stringify({
			providers: {
				corporate: {
					baseUrl: `${origin}/v1`,
					api: "openai-completions",
					apiKey: "$CORPORATE_TEST_KEY",
					models: [{ id: "corporate-test", contextWindow: 100000, maxTokens: 1024, reasoning: false }],
				},
			},
		}),
	);
	await writeFile(
		join(agentDir, "settings.json"),
		JSON.stringify({
			defaultProvider: "corporate",
			defaultModel: "corporate-test",
			defaultThinkingLevel: "off",
			extensions: [
				"-builtin:mcp",
				"-builtin:llama.cpp",
				"-builtin:codemode",
				"-builtin:tool-search",
				...(withExtension ? [extension] : []),
			],
		}),
	);
	return { directory, cwd, agentDir, requests };
}

describe.skipIf(process.platform !== "darwin" || !existsSync(cli))("built corporate Pi", () => {
	it("streams through the native launcher in print and RPC modes", async () => {
		const { cwd, agentDir, requests } = await fixture();
		const printed = await run(cli, ["-p", "--no-session", "SYNTHETIC_MAIN"], cwd, agentDir);
		expect(printed, printed.stderr).toMatchObject({ code: 0 });
		expect(printed.stdout).toContain("main-ok");
		const rpc = await run(
			cli,
			["--mode", "rpc", "--no-session"],
			cwd,
			agentDir,
			'{"id":"test","type":"get_state"}\n{"id":"prompt","type":"prompt","message":"SYNTHETIC_RPC"}\n',
			true,
		);
		expect(rpc, rpc.stderr).toMatchObject({ code: 0 });
		expect(rpc.stdout).toContain('"command":"get_state"');
		expect(rpc.stdout).toContain('"success":true');
		expect(rpc.stdout).toContain("main-ok");
		expect(requests).toHaveLength(2);
		expect(requests[0]?.authorization).toBe("Bearer synthetic-corporate-key");
		expect(requests[0]?.path).toBe("/v1/chat/completions");
	}, 60000);

	it("rejects redirects and public-provider selection despite public credentials", async () => {
		const { cwd, agentDir, requests } = await fixture(false, true);
		const redirected = await run(cli, ["-p", "--no-session", "SYNTHETIC_MAIN"], cwd, agentDir);
		expect(redirected.code).not.toBe(0);
		// The OpenAI SDK wraps policy exceptions as connection errors and may
		// retry the approved source. It must never follow the Location header.
		const requestCount = requests.length;
		expect(requestCount).toBeGreaterThan(0);
		const denied = await run(
			cli,
			["-p", "--no-session", "--provider", "openai", "--model", "gpt-5.5", "SYNTHETIC_MAIN"],
			cwd,
			agentDir,
		);
		expect(denied.code).not.toBe(0);
		expect(requests).toHaveLength(requestCount);
	}, 60000);

	it("launches SDK sessions under the same broker and refuses an unprotected SDK", async () => {
		const { directory, cwd, agentDir, requests } = await fixture();
		const app = join(directory, "app.mjs");
		const sdk = pathToFileURL(join(root, "packages/coding-agent/dist/index.js")).href;
		await writeFile(
			app,
			`import {createAgentSession,SessionManager} from ${JSON.stringify(sdk)};\nconst {session}=await createAgentSession({sessionManager:SessionManager.inMemory()});\nfor (const prompt of ['SYNTHETIC_SDK','RUN_CODE_WRITE','RUN_CODE_READ','RUN_CODE_BASH']) await session.prompt(prompt);\nconsole.log('SDK_OK');\nsession.dispose();\n`,
		);
		const protectedResult = await run(join(root, "scripts/corporate-sdk.mjs"), [app], cwd, agentDir);
		expect(protectedResult, protectedResult.stderr).toMatchObject({ code: 0 });
		expect(protectedResult.stdout).toContain("SDK_OK");
		expect(requests).toHaveLength(7);
		expect(await readFile(join(cwd, "corporate-proof.txt"), "utf8")).toBe("synthetic-code");
		expect(
			requests.some((req) => {
				const last = (JSON.parse(req.body) as { messages: { role: string; content: unknown }[] }).messages.at(-1);
				return last?.role === "tool" && JSON.stringify(last.content).includes("corporate-bash");
			}),
		).toBe(true);
		const denied = await run(app, [], cwd, agentDir);
		expect(denied.code).not.toBe(0);
		expect(denied.stderr).toContain("require the corporate process launcher");
		expect(requests).toHaveLength(7);
	}, 60000);

	it("verifies HTTPS through CONNECT and refuses an untrusted certificate", async () => {
		const { cwd, agentDir, requests } = await fixture(false, false, true);
		const trusted = await run(cli, ["-p", "--no-session", "SYNTHETIC_HTTPS"], cwd, agentDir);
		expect(trusted, trusted.stderr).toMatchObject({ code: 0 });
		expect(trusted.stdout).toContain("main-ok");
		expect(requests).toHaveLength(1);
		await rm(join(agentDir, "test-ca.pem"));
		const denied = await run(cli, ["-p", "--no-session", "SYNTHETIC_HTTPS"], cwd, agentDir);
		expect(denied.code).not.toBe(0);
		expect(requests).toHaveLength(1);
	}, 60000);

	it.skipIf(!existsSync(extension))(
		"loads the hashed ACP bundle and binds a real delegate to the same endpoint and profile",
		async () => {
			const { cwd, agentDir, requests } = await fixture(true);
			const result = await run(cli, ["-p", "--no-session", "RUN_DELEGATE"], cwd, agentDir);
			expect(result, result.stderr).toMatchObject({ code: 0 });
			expect(result.stdout).toContain("main-ok");
			expect(requests).toHaveLength(3);
			expect(requests.every((req) => req.authorization === "Bearer synthetic-corporate-key")).toBe(true);
			const state = join(agentDir, "corporate-state");
			const outDir = join(state, "acp-delegate");
			const files = await readdir(outDir);
			expect(files.some((file) => file.endsWith(".session.jsonl"))).toBe(true);
			const results = files.filter((file) => file.endsWith(".out"));
			expect(results.length).toBeGreaterThan(0);
			expect((await Promise.all(results.map((file) => readFile(join(outDir, file), "utf8")))).join("\n")).toContain(
				"delegate-ok",
			);
			for (const file of files) expect((await stat(join(outDir, file))).mode & 0o077).toBe(0);
			const log = await readFile(join(state, "acp.log"), "utf8");
			expect(log).not.toContain("synthetic-corporate-key");
		},
		60000,
	);
});
