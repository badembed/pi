import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { createServer, request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect, type Socket } from "node:net";
import { homedir, constants as osConstants, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { getAgentDir, getPackageDir } from "../config.ts";
import { CorporateNetworkPolicy } from "./corporate-network-policy.ts";

function canonicalSandboxPath(path: string): string {
	let parent = resolve(path);
	const suffix: string[] = [];
	for (;;) {
		try {
			return join(realpathSync(parent), ...suffix);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			const next = dirname(parent);
			if (next === parent) throw error;
			suffix.unshift(parent.slice(next.length + (next === "/" ? 0 : 1)));
			parent = next;
		}
	}
}

export function corporateSandboxProfile(proxyPort: number, writable: string[], protectedPaths: string[]): string {
	if (!Number.isInteger(proxyPort) || proxyPort <= 0 || proxyPort > 65535) throw new Error("Invalid proxy port.");
	writable = writable.map(canonicalSandboxPath);
	protectedPaths = protectedPaths.map(canonicalSandboxPath);
	const pathRule = (path: string) => `(subpath ${JSON.stringify(path)})`;
	return [
		"(version 1)",
		"(deny default)",
		"(allow process-exec process-fork)",
		"(allow process-info* signal (target same-sandbox))",
		"(allow file-read*)",
		"(allow sysctl-read)",
		'(allow sysctl-write (sysctl-name "kern.tcsm_enable"))',
		"(allow ipc-posix-shm ipc-posix-sem)",
		"(allow pseudo-tty)",
		'(allow file-ioctl (literal "/dev/null") (literal "/dev/tty") (regex #"^/dev/ttys") (literal "/dev/ptmx"))',
		'(allow file-write* (literal "/dev/null") (literal "/dev/tty") (regex #"^/dev/ttys") (literal "/dev/ptmx"))',
		`(allow network-outbound (remote tcp "localhost:${proxyPort}"))`,
		...writable.map((path) => `(allow file-write* ${pathRule(path)})`),
		...protectedPaths.map((path) => `(deny file-write* ${pathRule(path)})`),
		...protectedPaths.flatMap((path) => {
			const ancestors: string[] = [];
			for (let dir = dirname(path); dir !== "/"; dir = dirname(dir)) ancestors.push(dir);
			return ancestors.map((dir) => `(deny file-write-unlink (literal ${JSON.stringify(dir)}))`);
		}),
	].join("\n");
}

/** Rootless namespaces provide the network boundary; the helper installs seccomp before exec. */
export function corporateLinuxSandboxArgs(writable: string[], protectedPaths: string[], launchDir: string): string[] {
	writable = writable.map(canonicalSandboxPath);
	const args = [
		"--unshare-user",
		"--unshare-net",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--disable-userns",
		"--cap-drop",
		"ALL",
		"--die-with-parent",
		"--new-session",
		"--ro-bind",
		"/",
		"/",
		"--tmpfs",
		"/run",
		"--tmpfs",
		"/tmp",
		"--proc",
		"/proc",
		"--remount-ro",
		"/proc",
		"--dev",
		"/dev",
	];
	for (const path of writable) {
		if (path === "/") throw new Error("The corporate writable directory cannot be the filesystem root.");
		args.push("--bind", path, path);
	}
	const emptyDirectory = join(launchDir, "empty-directory");
	const emptyFile = join(launchDir, "empty-file");
	const emptyJson = join(launchDir, "empty.json");
	mkdirSync(emptyDirectory, { mode: 0o700 });
	writeFileSync(emptyFile, "", { mode: 0o600 });
	writeFileSync(emptyJson, "{}", { mode: 0o600 });
	for (const path of [...new Set(protectedPaths.map(canonicalSandboxPath))].sort((a, b) => a.length - b.length)) {
		let source = path;
		if (!existsSync(path)) {
			// An absent path outside the writable mounts is already protected by
			// the read-only root. Creating its mountpoint there would fail startup.
			if (!writable.some((directory) => path === directory || path.startsWith(`${directory}/`))) continue;
			source = path.endsWith(".json")
				? emptyJson
				: /\.(?:gitconfig|zshrc|bashrc)$/.test(path)
					? emptyFile
					: emptyDirectory;
		}
		args.push("--ro-bind", source, path);
	}
	args.push("--chdir", realpathSync(process.cwd()));
	return args;
}

/** The broker runs outside the sandbox; children can reach only its loopback port. */
export async function startCorporateProxy(policy: CorporateNetworkPolicy, socketPath?: string) {
	const sockets = new Set<Socket>();
	const server = createServer((req, res) => {
		let target: URL;
		try {
			target = new URL(req.url ?? "");
			policy.assertNetwork(target.href);
			if (target.protocol !== "http:" && target.protocol !== "https:") throw new Error("Invalid protocol.");
		} catch {
			res.writeHead(403).end("Corporate network policy blocked this request.");
			return;
		}
		const headers: IncomingHttpHeaders = { ...req.headers, host: target.host };
		delete headers["proxy-authorization"];
		delete headers["proxy-connection"];
		const upstream = (target.protocol === "https:" ? httpsRequest : httpRequest)(
			target,
			{ method: req.method, headers },
			(response) => {
				res.writeHead(response.statusCode ?? 502, response.headers);
				response.pipe(res);
			},
		);
		upstream.on("error", () => {
			if (!res.headersSent) res.writeHead(502);
			res.end();
		});
		upstream.on("socket", (socket) => {
			sockets.add(socket);
			socket.on("close", () => sockets.delete(socket));
		});
		res.on("close", () => upstream.destroy());
		req.on("aborted", () => upstream.destroy());
		req.pipe(upstream);
	});
	server.on("connection", (socket) => {
		sockets.add(socket);
		socket.on("error", () => {});
		socket.on("close", () => sockets.delete(socket));
	});
	server.on("connect", (req, client, head) => {
		let target: URL;
		try {
			const authority = req.url ?? "";
			if (!/^(?:\[[\da-fA-F:]+\]|[a-zA-Z\d.-]+):\d+$/.test(authority)) throw new Error("Invalid CONNECT.");
			target = new URL(`https://${authority}`);
			// CONNECT also carries loopback HTTP requests when Undici uses proxyTunnel.
			if (!policy.allowsNetwork(target.href)) {
				target = new URL(`http://${authority}`);
				policy.assertNetwork(target.href);
			}
		} catch {
			client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
			return;
		}
		const upstream = connect(
			Number(target.port) || (target.protocol === "https:" ? 443 : 80),
			target.hostname.replace(/^\[|\]$/g, ""),
		);
		sockets.add(upstream);
		upstream.on("close", () => sockets.delete(upstream));
		upstream.once("connect", () => {
			client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
			if (head.length) upstream.write(head);
			client.pipe(upstream);
			upstream.pipe(client);
		});
		upstream.on("error", () => client.destroy());
		client.on("error", () => upstream.destroy());
		client.on("close", () => upstream.destroy());
	});
	await new Promise<void>((done, reject) => {
		server.once("error", reject);
		if (socketPath) server.listen(socketPath, done);
		else server.listen(0, "127.0.0.1", done);
	});
	const address = server.address();
	if (!address) throw new Error("Corporate proxy failed to start.");
	return {
		port: typeof address === "string" ? 31987 : address.port,
		close: async () => {
			for (const socket of sockets) socket.destroy();
			await new Promise<void>((done) => server.close(() => done()));
		},
	};
}

async function verifyNativeSandbox(): Promise<void> {
	if (process.platform === "linux") {
		const status = readFileSync("/proc/self/status", "utf8");
		const routes = readFileSync("/proc/net/route", "utf8").trim().split("\n").slice(1);
		const ipv6Routes = readFileSync("/proc/net/ipv6_route", "utf8").trim().split("\n").filter(Boolean);
		if (
			!/^NoNewPrivs:\s+1$/m.test(status) ||
			!/^Seccomp:\s+2$/m.test(status) ||
			!/^CapEff:\s+0+$/m.test(status) ||
			routes.length ||
			ipv6Routes.some((line) => line.trim().split(/\s+/).at(-1) !== "lo")
		)
			throw new Error("Corporate sandbox is not active.");
	}
	await new Promise<void>((done, reject) => {
		const socket =
			process.platform === "linux"
				? connect({ path: "/tmp/pi-native-isolation-probe.sock" })
				: connect(9, "127.0.0.1");
		socket.setTimeout(2000, () => {
			socket.destroy();
			reject(new Error("Cannot verify native network isolation."));
		});
		socket.on("connect", () => {
			socket.destroy();
			reject(new Error("Corporate sandbox is not active."));
		});
		socket.on("error", (error: NodeJS.ErrnoException) => {
			if (error.code === "EPERM" || error.code === "EACCES") done();
			else reject(new Error("Corporate sandbox is not active."));
		});
	});
}

export async function assertCorporateSandbox(): Promise<void> {
	if (process.env.PI_CORPORATE_SANDBOX !== "1") {
		throw new Error("Corporate SDK sessions require the corporate process launcher.");
	}
	await verifyNativeSandbox();
}

export async function enterCorporateSandbox(): Promise<boolean> {
	if (process.env.PI_CORPORATE_SANDBOX === "1") {
		await verifyNativeSandbox();
		return true;
	}
	await launchCorporateProcess();
	return false;
}

export async function launchCorporateProcess(
	options: { entry?: string; args?: string[]; cli?: string; protectedPaths?: string[] } = {},
): Promise<void> {
	if (process.env.PI_CORPORATE_SANDBOX === "1")
		throw new Error("A sandboxed process cannot start an unsandboxed broker.");
	if (process.platform !== "darwin" && process.platform !== "linux")
		throw new Error("Corporate process isolation requires macOS or Linux.");
	const linuxHelper = join(getPackageDir(), "dist/corporate-linux-helper");
	if (process.platform === "linux") {
		if (!existsSync(linuxHelper) || !existsSync("/usr/bin/bwrap"))
			throw new Error(
				"Corporate Linux isolation requires /usr/bin/bwrap and the source-built corporate-linux-helper. No unsandboxed fallback.",
			);
		if (statSync("/usr/bin/bwrap").mode & 0o6000)
			throw new Error("Corporate Linux isolation requires non-setuid bubblewrap.");
	}
	process.umask(0o077);
	const agentDir = resolve(getAgentDir());
	mkdirSync(agentDir, { recursive: true, mode: 0o700 });
	const policyPath = join(agentDir, "network-policy.json");
	const config: unknown = JSON.parse(readFileSync(policyPath, "utf8"));
	const policy = new CorporateNetworkPolicy(config);
	// AuthStorage initializes even a keyless profile before reading configured
	// environment keys. Create it in the trusted parent before making it read-only.
	const authPath = join(agentDir, "auth.json");
	if (!existsSync(authPath)) writeFileSync(authPath, "{}", { mode: 0o600, flag: "wx" });
	const stateDir = join(agentDir, "corporate-state");
	mkdirSync(stateDir, { recursive: true, mode: 0o700 });
	const launchDir = mkdtempSync(join(stateDir, "launch-"));
	const snapshot = join(launchDir, "network-policy.json");
	writeFileSync(snapshot, JSON.stringify(config), { mode: 0o600 });
	const scratch = mkdtempSync(join(realpathSync(tmpdir()), "pi-corporate-"));
	const entry = realpathSync(options.entry ?? process.argv[1]);
	const cli = realpathSync(options.cli ?? entry);
	const bridgeDir = join(scratch, "bridge");
	mkdirSync(bridgeDir, { mode: 0o700 });
	const socketPath = process.platform === "linux" ? join(bridgeDir, "broker.sock") : undefined;
	const broker = await startCorporateProxy(policy, socketPath);
	try {
		const proxy = `http://127.0.0.1:${broker.port}`;
		const env = { ...process.env };
		for (const key of Object.keys(env)) {
			if (
				/^(?:DYLD_|LD_|NODE_OPTIONS$|NODE_PATH$|NODE_COMPILE_CACHE$|NODE_TLS_REJECT_UNAUTHORIZED$|SSLKEYLOGFILE$|SSH_AUTH_SOCK$|.*PROXY$)/i.test(
					key,
				)
			)
				delete env[key];
		}
		Object.assign(env, {
			HTTP_PROXY: proxy,
			HTTPS_PROXY: proxy,
			http_proxy: proxy,
			https_proxy: proxy,
			NO_PROXY: "",
			no_proxy: "",
			ALL_PROXY: "",
			all_proxy: "",
			PI_CORPORATE_SANDBOX: "1",
			PI_NETWORK_POLICY_PATH: snapshot,
			PI_CORPORATE_STATE_DIR: stateDir,
			PI_CLI_PATH: cli,
			PI_CORPORATE_CLI_SHA256: createHash("sha256").update(readFileSync(cli)).digest("hex"),
			PI_CODING_AGENT_DIR: agentDir,
			PI_OFFLINE: "1",
			PI_TELEMETRY: "0",
			ACP_AUTO_UPDATE: "0",
			ACP_LOG_FILE: join(stateDir, "acp.log"),
			NODE_COMPILE_CACHE: join(scratch, "node-compile-cache"),
			TMPDIR: scratch,
			TMP: scratch,
			TEMP: scratch,
		});
		const profilePath = join(launchDir, "sandbox.sb");
		const packageDir = getPackageDir();
		const dependencyPaths: string[] = [];
		for (let parent = packageDir; parent !== "/"; parent = dirname(parent)) {
			const modules = join(parent, "node_modules");
			if (existsSync(modules)) dependencyPaths.push(modules);
		}
		const protectedPaths = [
			bridgeDir,
			launchDir,
			policyPath,
			packageDir,
			dirname(packageDir),
			entry,
			cli,
			...dependencyPaths,
			...(options.protectedPaths ?? []),
			...(env.NODE_EXTRA_CA_CERTS ? [env.NODE_EXTRA_CA_CERTS] : []),
			process.execPath,
			join(agentDir, "models.json"),
			join(agentDir, "auth.json"),
			join(agentDir, "settings.json"),
			join(agentDir, "extensions"),
			join(agentDir, "npm"),
			join(agentDir, "bin"),
			join(homedir(), ".ssh"),
			join(homedir(), ".gitconfig"),
			join(homedir(), ".zshrc"),
			join(homedir(), ".bashrc"),
			...policy.getExtensionPaths(),
		];
		const writable = [realpathSync(process.cwd()), agentDir, scratch];
		const command = process.platform === "linux" ? "/usr/bin/bwrap" : "/usr/bin/sandbox-exec";
		let args: string[];
		if (socketPath) {
			args = [
				...corporateLinuxSandboxArgs(writable, protectedPaths, launchDir),
				linuxHelper,
				socketPath,
				String(broker.port),
				process.execPath,
				entry,
				...(options.args ?? process.argv.slice(2)),
			];
		} else {
			writeFileSync(profilePath, corporateSandboxProfile(broker.port, writable, protectedPaths), { mode: 0o600 });
			args = ["-f", profilePath, process.execPath, entry, ...(options.args ?? process.argv.slice(2))];
		}
		chmodSync(launchDir, 0o700);
		const child = spawn(command, args, { env, stdio: "inherit" });
		// Keep the broker alive while the child handles interruption. A raw TUI
		// handles Ctrl+C itself; print-mode foreground processes can both receive it.
		const signals = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
		let shutdownTimer: NodeJS.Timeout | undefined;
		const handlers = signals.map((signal) => () => {
			child.kill(signal);
			if (signal !== "SIGINT" && !shutdownTimer) {
				shutdownTimer = setTimeout(() => child.kill("SIGKILL"), 5000);
				shutdownTimer.unref();
			}
		});
		for (const [index, signal] of signals.entries()) process.on(signal, handlers[index]);
		const terminate = () => child.kill("SIGKILL");
		process.once("exit", terminate);
		try {
			process.exitCode = await new Promise<number>((done, reject) => {
				child.once("error", reject);
				child.once("exit", (code, signal) => done(code ?? (signal ? 128 + osConstants.signals[signal] : 1)));
			});
		} finally {
			if (shutdownTimer) clearTimeout(shutdownTimer);
			for (const [index, signal] of signals.entries()) process.off(signal, handlers[index]);
			process.off("exit", terminate);
		}
	} finally {
		await broker.close();
	}
}
