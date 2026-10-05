#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform === "linux") {
	const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
	const directory = join(root, "packages/coding-agent");
	const result = spawnSync("cc", [
		"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
		"-Wl,-z,relro,-z,now", "-o", join(directory, "dist/corporate-linux-helper"),
		join(directory, "src/core/corporate-linux-helper.c"),
	], { stdio: "inherit" });
	if (result.error) throw result.error;
	if (result.status !== 0) throw new Error("Corporate Linux helper build failed.");
}
