import { afterEach, expect, it, vi } from "vitest";
import { areExperimentalFeaturesEnabled } from "../src/core/experimental.ts";
import { SettingsManager } from "../src/core/settings-manager.ts";
import { isInstallTelemetryEnabled } from "../src/core/telemetry.ts";
import { fetchWithRetry } from "../src/utils/management-http.ts";
import { getLatestPiRelease } from "../src/utils/version-check.ts";

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
});

it("cannot reenable install telemetry, experiments or remote version checks through settings and environment", async () => {
	const fetch = vi.fn();
	vi.stubGlobal("fetch", fetch);
	vi.stubEnv("PI_TELEMETRY", "1");
	vi.stubEnv("PI_EXPERIMENTAL", "1");
	vi.stubEnv("PI_OFFLINE", "0");
	expect(isInstallTelemetryEnabled(SettingsManager.inMemory({ enableAnalytics: true }), "true")).toBe(false);
	expect(areExperimentalFeaturesEnabled()).toBe(false);
	expect(await getLatestPiRelease("1.0.2", { retry: true })).toBeUndefined();
	expect(fetch).not.toHaveBeenCalled();
});

it("rejects explicit management traffic before transport, even with offline disabled", async () => {
	const fetch = vi.fn();
	vi.stubGlobal("fetch", fetch);
	vi.stubEnv("PI_OFFLINE", "0");
	await expect(
		fetchWithRetry(
			"https://pi.dev/api/latest-version",
			{ method: "POST", body: "synthetic-context" },
			{ maxRetries: 3 },
		),
	).rejects.toThrow("disabled in corporate Pi");
	expect(fetch).not.toHaveBeenCalled();
});
