import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { getAgentDir } from "../config.ts";

export interface CorporateProviderPolicy {
	modelOrigins: readonly string[];
	authOrigins?: readonly string[];
}

export interface CorporatePolicyConfig {
	providers: Record<string, CorporateProviderPolicy>;
	extensions?: readonly { path: string; sha256: string }[];
}

function checkedOrigin(value: string): string {
	const url = new URL(value);
	const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (
		(url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) ||
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		url.pathname !== "/"
	) {
		throw new Error("Corporate policy requires HTTPS origins (HTTP is allowed only for loopback servers).");
	}
	return url.origin;
}

/** Authorization is independent of model catalogs, project settings and request overrides. */
export class CorporateNetworkPolicy {
	private readonly models = new Map<string, ReadonlySet<string>>();
	private readonly auth = new Map<string, ReadonlySet<string>>();
	private readonly extensions = new Map<string, string>();

	constructor(config: unknown) {
		if (typeof config !== "object" || config === null || !("providers" in config)) {
			throw new Error("Invalid corporate policy: expected providers.");
		}
		if (Array.isArray(config) || Object.keys(config).some((key) => key !== "providers" && key !== "extensions")) {
			throw new Error("Unknown corporate policy field.");
		}
		const extensions = "extensions" in config ? config.extensions : [];
		if (!Array.isArray(extensions)) throw new Error("Invalid corporate extension policy.");
		for (const entry of extensions) {
			if (
				typeof entry !== "object" ||
				entry === null ||
				Array.isArray(entry) ||
				Object.keys(entry).some((key) => key !== "path" && key !== "sha256") ||
				typeof entry.path !== "string" ||
				!isAbsolute(entry.path) ||
				typeof entry.sha256 !== "string" ||
				!/^[a-f0-9]{64}$/.test(entry.sha256)
			) {
				throw new Error("Corporate extensions require absolute paths and SHA-256 hashes.");
			}
			const canonical = realpathSync(entry.path);
			if (this.extensions.has(canonical)) throw new Error("Duplicate corporate extension path.");
			this.extensions.set(canonical, entry.sha256);
		}
		const providers = config.providers;
		if (typeof providers !== "object" || providers === null || Array.isArray(providers)) {
			throw new Error("Invalid corporate policy: providers must be an object.");
		}
		for (const [id, entry] of Object.entries(providers)) {
			if (!id || typeof entry !== "object" || entry === null || Array.isArray(entry)) {
				throw new Error("Invalid corporate provider policy.");
			}
			const value = entry as Record<string, unknown>;
			if (Object.keys(value).some((key) => key !== "modelOrigins" && key !== "authOrigins")) {
				throw new Error(`Unknown corporate policy field for ${id}.`);
			}
			for (const [key, target] of [
				["modelOrigins", this.models],
				["authOrigins", this.auth],
			] as const) {
				const origins = value[key] ?? (key === "authOrigins" ? [] : undefined);
				if (!Array.isArray(origins) || origins.some((origin) => typeof origin !== "string")) {
					throw new Error(`Invalid ${key} for corporate provider ${id}.`);
				}
				target.set(id, new Set(origins.map(checkedOrigin)));
			}
		}
	}

	allowsModel(provider: string, address: string): boolean {
		try {
			const url = new URL(address);
			return !url.username && !url.password && (this.models.get(provider)?.has(url.origin) ?? false);
		} catch {
			return false;
		}
	}

	getExtensionPaths(): string[] {
		return [...this.extensions.keys()];
	}

	assertExtension(path: string): void {
		const canonical = realpathSync(path);
		const expected = this.extensions.get(canonical);
		if (!expected || createHash("sha256").update(readFileSync(canonical)).digest("hex") !== expected) {
			throw new Error("Corporate policy blocks this extension: unapproved path or changed bundle.");
		}
	}

	assertModel(provider: string, address: string): void {
		if (!this.allowsModel(provider, address)) {
			throw new Error(
				`Corporate policy blocks the model endpoint for provider ${provider}. Check network-policy.json.`,
			);
		}
	}

	allowsNetwork(address: string): boolean {
		try {
			const url = new URL(address);
			if (url.username || url.password) return false;
			// WebSocket model transports have the same authority as their HTTPS/HTTP endpoints.
			if (url.protocol === "wss:") url.protocol = "https:";
			if (url.protocol === "ws:") url.protocol = "http:";
			return [...this.models.values(), ...this.auth.values()].some((origins) => origins.has(url.origin));
		} catch {
			return false;
		}
	}

	assertNetwork(address: string): void {
		if (!this.allowsNetwork(address)) throw new Error("Corporate policy blocks this network destination.");
	}
}

export function loadCorporateNetworkPolicy(
	path = process.env.PI_NETWORK_POLICY_PATH ?? join(getAgentDir(), "network-policy.json"),
): CorporateNetworkPolicy {
	try {
		return new CorporateNetworkPolicy(JSON.parse(readFileSync(path, "utf8")));
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") {
			return new CorporateNetworkPolicy({ providers: {} });
		}
		throw new Error(`Failed to load corporate network policy: ${path}`, { cause: error });
	}
}
