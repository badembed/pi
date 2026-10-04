import type { SettingsManager } from "./settings-manager.ts";

export function isInstallTelemetryEnabled(
	_settingsManager: SettingsManager,
	_telemetryEnv: string | undefined = process.env.PI_TELEMETRY,
): boolean {
	return false;
}
