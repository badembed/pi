import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { loadExtensionsCached } from "../src/core/extensions/loader.ts";

it("checks approval and hash before importing extensions, including on reload", async () => {
	const dir = await mkdtemp(join(tmpdir(), "pi-approved-extension-"));
	const entry = join(dir, "extension.ts");
	const path = join(dir, "network-policy.json");
	const source = "export default function(pi) { pi.events.emit('corporate-test', 'approved'); }";
	await writeFile(entry, source);
	vi.stubEnv("PI_NETWORK_POLICY_PATH", path);
	try {
		await writeFile(path, JSON.stringify({ providers: {} }));
		const unapproved = await loadExtensionsCached([entry], dir);
		expect(unapproved.extensions).toHaveLength(0);
		expect(unapproved.errors[0]?.error).toContain("unapproved path or changed bundle");
		await writeFile(
			path,
			JSON.stringify({
				providers: {},
				extensions: [{ path: entry, sha256: createHash("sha256").update(source).digest("hex") }],
			}),
		);
		const approved = await loadExtensionsCached([entry], dir);
		expect(approved.errors).toEqual([]);
		expect(approved.extensions).toHaveLength(1);
		await writeFile(entry, "throw new Error('UNAPPROVED_CODE_EXECUTED');");
		const changed = await loadExtensionsCached([entry], dir);
		expect(changed.extensions).toHaveLength(0);
		expect(changed.errors[0]?.error).toContain("unapproved path or changed bundle");
		expect(changed.errors[0]?.error).not.toContain("UNAPPROVED_CODE_EXECUTED");
	} finally {
		vi.unstubAllEnvs();
		await rm(dir, { recursive: true, force: true });
	}
});
