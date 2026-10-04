import * as crypto from "node:crypto";
import type { Container, EditorComponent, TUI } from "@earendil-works/pi-tui";
import type { AgentSession } from "../../core/agent-session.ts";
import { exportSessionToJsonl } from "../../core/session-export.ts";

interface SessionShareContext {
	session: AgentSession;
	ui: TUI;
	editorContainer: Container;
	editor: EditorComponent;
	showStatus: (message: string) => void;
	showError: (message: string) => void;
}

/** Trailing `pi.share` entry carrying the system prompt and tool schemas for the session viewer. */
export function createShareTrailingEntries(
	session: AgentSession,
	parentId: string | null,
	timestamp: string,
): object[] {
	return [
		{
			type: "custom",
			customType: "pi.share",
			id: crypto.randomUUID().slice(0, 8),
			parentId,
			timestamp,
			data: {
				systemPrompt: session.state.systemPrompt,
				tools: session.state.tools.map((tool) => ({
					name: tool.name,
					description: tool.description,
					parameters: tool.parameters,
				})),
			},
		},
	];
}

/** Export the current branch with presentation metadata for Radius. */
export function exportSessionForShare(filePath: string, session: AgentSession): void {
	exportSessionToJsonl(session.sessionManager, filePath, (parentId, timestamp) =>
		createShareTrailingEntries(session, parentId, timestamp),
	);
}

/** Corporate Pi only supports local session export. */
export async function shareSession(context: SessionShareContext): Promise<void> {
	context.showError("Session uploads are disabled in corporate Pi. Use /export to save locally.");
}
