import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CorporateNetworkPolicy } from "../src/core/corporate-network-policy.ts";
import { assertCorporateSandbox, corporateSandboxProfile, startCorporateProxy } from "../src/core/corporate-sandbox.ts";

const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => {
	for (const close of cleanup.splice(0).reverse()) await close();
});

async function fixture() {
	let requests = 0;
	const server = createServer((_req, res) => {
		requests++;
		res.end("approved-model");
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	const address = server.address();
	if (!address || typeof address === "string") throw new Error("Missing server port");
	cleanup.push(() => new Promise<void>((done) => server.close(() => done())));
	const origin = `http://127.0.0.1:${address.port}`;
	const broker = await startCorporateProxy(
		new CorporateNetworkPolicy({ providers: { corporate: { modelOrigins: [origin] } } }),
	);
	cleanup.push(broker.close);
	return { origin, broker, count: () => requests };
}

function proxyRequest(port: number, destination: string, method = "GET") {
	return new Promise<{ status: number; body: string }>((done, reject) => {
		const req = request({ host: "127.0.0.1", port, path: destination, method }, (res) => {
			let body = "";
			res.on("data", (chunk) => {
				body += chunk;
			});
			res.on("end", () => done({ status: res.statusCode ?? 0, body }));
		});
		req.on("error", reject);
		req.end();
	});
}

describe("corporate process isolation", () => {
	it("rejects a forged sandbox environment marker without native isolation", async () => {
		vi.stubEnv("PI_CORPORATE_SANDBOX", "1");
		try {
			await expect(assertCorporateSandbox()).rejects.toThrow("sandbox is not active");
		} finally {
			vi.unstubAllEnvs();
		}
	});
	it("proxies an approved server and blocks a different authority before connection", async () => {
		const { origin, broker, count } = await fixture();
		expect(await proxyRequest(broker.port, `${origin}/v1`)).toEqual({ status: 200, body: "approved-model" });
		for (const url of [origin.replace("127.0.0.1", "localhost"), "http://127.0.0.1:9/", "https://external.test/"]) {
			expect((await proxyRequest(broker.port, url)).status).toBe(403);
		}
		expect(count()).toBe(1);
	});

	it("rejects CONNECT tunnels to unapproved ports", async () => {
		const { broker, count } = await fixture();
		const status = await new Promise<number>((done, reject) => {
			const req = request({ host: "127.0.0.1", port: broker.port, method: "CONNECT", path: "127.0.0.1:9" });
			req.on("connect", (res, socket) => {
				socket.destroy();
				done(res.statusCode ?? 0);
			});
			req.on("error", reject);
			req.end();
		});
		expect(status).toBe(403);
		expect(count()).toBe(0);
	});

	it.skipIf(process.platform !== "darwin")(
		"native sandbox covers Node, curl, grandchildren, files and inherited proxies",
		async () => {
			const { origin, broker, count } = await fixture();
			const dir = await mkdtemp(join(tmpdir(), "pi-sandbox-test-"));
			cleanup.push(() => rm(dir, { recursive: true, force: true }));
			const protectedFile = join(dir, "protected.txt");
			await writeFile(protectedFile, "unchanged");
			const script = join(dir, "probe.cjs");
			await writeFile(
				script,
				`
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const [origin, proxy, protectedFile] = process.argv.slice(2);
const direct = net.connect(Number(new URL(origin).port), '127.0.0.1');
direct.on('connect', () => { console.log('DIRECT_ALLOWED'); direct.destroy(); process.exitCode = 1; });
direct.on('error', error => { console.log('DIRECT_' + error.code); });
const permitted = spawnSync('/usr/bin/curl', ['-fsS', '--max-time', '3', '--noproxy', '', '-x', proxy, origin], { encoding: 'utf8' });
console.log('APPROVED_' + permitted.stdout);
const denied = spawnSync('/usr/bin/curl', ['-fsS', '--max-time', '3', '--noproxy', '*', origin], { encoding: 'utf8' });
console.log('GRANDCHILD_' + denied.status);
try { fs.writeFileSync(protectedFile, 'changed'); console.log('WRITE_ALLOWED'); process.exitCode = 1; }
catch (error) { console.log('WRITE_' + error.code); }
try { fs.linkSync(protectedFile, protectedFile + '.alias'); fs.writeFileSync(protectedFile + '.alias', 'changed'); console.log('ALIAS_ALLOWED'); process.exitCode = 1; }
catch (error) { console.log('ALIAS_' + error.code); }
fs.writeFileSync(protectedFile + '.work', 'coding-tools-work');
`,
			);
			const profile = corporateSandboxProfile(broker.port, [dir], [protectedFile]);
			const result = await new Promise<{ code: number | null; output: string }>((done, reject) => {
				const child = spawn("/usr/bin/sandbox-exec", [
					"-p",
					profile,
					process.execPath,
					script,
					origin,
					`http://127.0.0.1:${broker.port}`,
					protectedFile,
				]);
				let output = "";
				child.stdout.on("data", (chunk) => {
					output += chunk;
				});
				child.stderr.on("data", (chunk) => {
					output += chunk;
				});
				child.on("error", reject);
				child.on("close", (code) => done({ code, output }));
			});
			expect(result.output).toContain("DIRECT_EPERM");
			expect(result.output).toContain("APPROVED_approved-model");
			expect(result.output).toMatch(/GRANDCHILD_[1-9]/);
			expect(result.output).toContain("WRITE_EPERM");
			expect(result.output).toContain("ALIAS_EPERM");
			expect(result.code).toBe(0);
			expect(count()).toBe(1);
			expect(await readFile(protectedFile, "utf8")).toBe("unchanged");
			expect(await readFile(`${protectedFile}.work`, "utf8")).toBe("coding-tools-work");
		},
		15000,
	);
});
