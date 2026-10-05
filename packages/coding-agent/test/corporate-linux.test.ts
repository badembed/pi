import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createServer as createUnixServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const cleanup: (() => Promise<unknown>)[] = [];
afterEach(async () => {
	for (const close of cleanup.splice(0).reverse()) await close();
});

function run(args: string[], cwd: string, env: NodeJS.ProcessEnv) {
	return new Promise<{ code: number | null; stdout: string; stderr: string }>((done, reject) => {
		const child = spawn(process.execPath, args, { cwd, env });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
		});
		child.stdin.end();
		const timer = setTimeout(() => child.kill("SIGTERM"), 20000);
		child.on("error", reject);
		child.on("close", (code) => {
			clearTimeout(timer);
			done({ code, stdout, stderr });
		});
	});
}

describe.skipIf(process.platform !== "linux")("native corporate Linux boundary", () => {
	it("covers raw sockets, proxy bypass, subprocesses, namespaces and protected files", async () => {
		const directory = await mkdtemp(join(tmpdir(), "pi-linux-test-"));
		cleanup.push(() => rm(directory, { recursive: true, force: true }));
		const cwd = join(directory, "project");
		const agentDir = join(directory, "agent");
		await mkdir(cwd);
		await mkdir(agentDir);
		let approved = 0;
		let collected = 0;
		const listen = async (handler: () => void) => {
			const server = createServer((_req, res) => {
				handler();
				res.end(`approved-model-${"x".repeat(200000)}-relay-end`);
			});
			await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
			cleanup.push(async () => {
				server.closeAllConnections();
				await new Promise<void>((done) => server.close(() => done()));
			});
			const address = server.address();
			if (!address || typeof address === "string") throw new Error("Missing port");
			return `http://127.0.0.1:${address.port}`;
		};
		const origin = await listen(() => {
			approved++;
		});
		const collector = await listen(() => {
			collected++;
		});
		let unixConnections = 0;
		const hostSocket = join(cwd, "host.sock");
		const unixServer = createUnixServer((socket) => {
			unixConnections++;
			socket.destroy();
		});
		await new Promise<void>((done) => unixServer.listen(hostSocket, done));
		cleanup.push(() => new Promise<void>((done) => unixServer.close(() => done())));
		const config = { providers: { corporate: { modelOrigins: [origin] } } };
		await writeFile(join(agentDir, "network-policy.json"), JSON.stringify(config));
		const protectedFile = join(agentDir, "models.json");
		await writeFile(protectedFile, "{}");
		const app = join(directory, "probe.mjs");
		const sandbox = pathToFileURL(join(root, "packages/coding-agent/dist/core/corporate-sandbox.js")).href;
		await writeFile(
			app,
			`
import { assertCorporateSandbox } from ${JSON.stringify(sandbox)};
import { spawnSync } from 'node:child_process';
import { writeFileSync, linkSync, readFileSync } from 'node:fs';
import { connect } from 'node:net';
await assertCorporateSandbox();
const [origin, collector, protectedFile, hostSocket] = process.argv.slice(2);
const request = (...args) => spawnSync('/usr/bin/curl', ['--max-time', '2', '-fsS', ...args], {encoding:'utf8'});
const streamed=request('--noproxy', '', '-x', process.env.HTTP_PROXY, origin);
if(streamed.status !== 0 || !streamed.stdout.endsWith('-relay-end')) throw new Error('TRUNCATED_BRIDGE_STREAM');
console.log('APPROVED_approved-model');
if (request('--noproxy', '', '-x', process.env.HTTP_PROXY, collector).status === 0) throw new Error('UNAPPROVED_PROXY_ALLOWED');
if (request('--noproxy', '*', origin).status === 0) throw new Error('DIRECT_CURL_ALLOWED');
console.log('CURL_BYPASS_BLOCKED');
await new Promise((done, reject) => {
 const socket=connect(Number(new URL(origin).port),'127.0.0.1');
 socket.on('connect',()=>{socket.destroy();reject(new Error('DIRECT_NODE_ALLOWED'));});
 socket.on('error',()=>{console.log('DIRECT_NODE_BLOCKED');done();});
});
const python = spawnSync('/usr/bin/python3', ['-c', \`
import socket, errno, sys
for family, kind in [(socket.AF_UNIX,socket.SOCK_STREAM),(socket.AF_INET,socket.SOCK_DGRAM),(socket.AF_INET,socket.SOCK_RAW),(socket.AF_NETLINK,socket.SOCK_RAW)]:
 try: socket.socket(family,kind)
 except OSError as e:
  assert e.errno == errno.EPERM, e
 else: raise Exception('UNSAFE_SOCKET_ALLOWED')
for kind in [socket.SOCK_DGRAM, socket.SOCK_SEQPACKET]:
 try: socket.socketpair(socket.AF_UNIX,kind)
 except OSError as e:
  assert e.errno == errno.EPERM, e
 else: raise Exception('UNSAFE_SOCKETPAIR_ALLOWED')
left,right=socket.socketpair()
right.close()
for operation in [lambda:left.connect(sys.argv[1]),lambda:left.listen(1)]:
 try: operation()
 except OSError: pass
 else: raise Exception('STREAM_PAIR_ESCAPED')
left.close()
print('UNSAFE_SOCKETS_BLOCKED')
\`, hostSocket], {encoding:'utf8'});
if (python.status !== 0) throw new Error(python.stderr);
console.log(python.stdout);
if (spawnSync('/usr/bin/unshare',['--user','--map-root-user','/bin/true']).status===0) throw new Error('NESTED_USERNS_ALLOWED');
console.log('NESTED_USERNS_BLOCKED');
for (const operation of [()=>writeFileSync(protectedFile,'changed'),()=>{linkSync(protectedFile,protectedFile+'.alias');writeFileSync(protectedFile+'.alias','changed');}]) {
 let blocked=false;try {operation();} catch {blocked=true;} if(!blocked) throw new Error('PROTECTED_WRITE_ALLOWED');
}
console.log('PROTECTED_FILES_BLOCKED');
writeFileSync('coding-proof.txt','coding-tools-work');
console.log('LINUX_SANDBOX_OK');
console.log(readFileSync('/proc/self/status','utf8').match(/^Seccomp:.*$/m)[0]);
`,
		);
		const result = await run(
			[join(root, "scripts/corporate-sdk.mjs"), app, origin, collector, protectedFile, hostSocket],
			cwd,
			{
				...process.env,
				PI_CODING_AGENT_DIR: agentDir,
			},
		);
		expect(result, result.stderr).toMatchObject({ code: 0 });
		for (const marker of [
			"APPROVED_approved-model",
			"CURL_BYPASS_BLOCKED",
			"DIRECT_NODE_BLOCKED",
			"UNSAFE_SOCKETS_BLOCKED",
			"NESTED_USERNS_BLOCKED",
			"PROTECTED_FILES_BLOCKED",
			"LINUX_SANDBOX_OK",
		])
			expect(result.stdout).toContain(marker);
		expect(approved).toBe(1);
		expect(collected).toBe(0);
		expect(unixConnections).toBe(0);
		expect(await readFile(protectedFile, "utf8")).toBe("{}");
		expect(await readFile(join(cwd, "coding-proof.txt"), "utf8")).toBe("coding-tools-work");
	}, 30000);

	it("refuses a missing native helper before running the application", async () => {
		const directory = await mkdtemp(join(tmpdir(), "pi-linux-missing-helper-"));
		cleanup.push(() => rm(directory, { recursive: true, force: true }));
		const result = await run([join(root, "scripts/corporate-sdk.mjs"), "/missing/app.mjs"], directory, {
			...process.env,
			PI_PACKAGE_DIR: directory,
		});
		expect(result.code).not.toBe(0);
		expect(result.stderr).toContain("source-built corporate-linux-helper");
		expect(existsSync(join(directory, "dist/corporate-linux-helper"))).toBe(false);
	});

	it.runIf(process.env.PI_CORPORATE_TEST_UNAVAILABLE === "1")(
		"stops when the host refuses namespace setup without making a model request",
		async () => {
			const directory = await mkdtemp(join(tmpdir(), "pi-linux-unavailable-"));
			cleanup.push(() => rm(directory, { recursive: true, force: true }));
			const cwd = join(directory, "project");
			const agent = join(directory, "agent");
			await mkdir(cwd);
			await mkdir(agent);
			let requests = 0;
			const server = createServer((_req, res) => {
				requests++;
				res.end("must-not-be-reached");
			});
			await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
			cleanup.push(async () => {
				server.closeAllConnections();
				await new Promise<void>((done) => server.close(() => done()));
			});
			const address = server.address();
			if (!address || typeof address === "string") throw new Error("Missing port");
			const origin = `http://127.0.0.1:${address.port}`;
			await writeFile(
				join(agent, "network-policy.json"),
				JSON.stringify({ providers: { corporate: { modelOrigins: [origin] } } }),
			);
			await writeFile(
				join(agent, "models.json"),
				JSON.stringify({
					providers: {
						corporate: {
							baseUrl: `${origin}/v1`,
							api: "openai-completions",
							apiKey: "synthetic-key",
							models: [{ id: "test" }],
						},
					},
				}),
			);
			const result = await run(
				[
					join(root, "packages/coding-agent/dist/bundle/cli.js"),
					"-p",
					"--no-session",
					"--provider",
					"corporate",
					"--model",
					"test",
					"SYNTHETIC",
				],
				cwd,
				{ ...process.env, PI_CODING_AGENT_DIR: agent },
			);
			expect(result.code).not.toBe(0);
			expect(result.stderr).toContain("bwrap:");
			expect(requests).toBe(0);
		},
	);
});
