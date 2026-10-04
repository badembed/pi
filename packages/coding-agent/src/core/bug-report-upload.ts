import type { BugReportBundle } from "./bug-report.ts";

interface UploadBugReportOptions {
	token?: string;
	signal?: AbortSignal;
	gatewayUrl?: string;
}

export async function uploadBugReport(
	_bundle: BugReportBundle,
	_options: UploadBugReportOptions = {},
): Promise<{ id: string }> {
	throw new Error("Report uploads are disabled in corporate Pi. Save the report locally instead.");
}
