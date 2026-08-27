/** Options for terminal-safe, human-readable text. */
export interface TerminalSanitizeOptions {
	readonly preserveNewlines?: boolean;
	readonly preserveTabs?: boolean;
}

// ESC control strings include a terminator supplied either as BEL or ST.  The
// C1 forms are included because terminal emulators accept both encodings.
const TERMINAL_ESCAPES = /\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\|$)|[PX^_][\s\S]*?(?:\x1b\\|$)|[@-_][ -/]*[@-~]?|.)|\x9b[0-?]*[ -/]*[@-~]|\x9d[^\x07\x9c]*(?:\x07|\x9c|$)|[\x90\x98\x9e\x9f][\s\S]*?(?:\x9c|$)/g;

// These code points can alter reading order, hide content, or create an
// indistinguishable visual boundary. Variation selectors and the emoji ZWJ are
// deliberately not removed: they are part of the intended rendering of emoji.
const INVISIBLE_UNICODE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200c\u200e-\u200f\u202a-\u202e\u2060-\u206f\u2800\u3164\ufeff\ufff0-\ufff8]/g;
const UNICODE_TAGS = /[\u{e0000}-\u{e007f}]/gu;

/**
 * Remove terminal control sequences and invisible directionality controls from
 * untrusted text before it reaches a terminal. Newlines and tabs are opt-in
 * safe layout characters; all other C0/C1 controls are removed.
 */
export function sanitizeTerminalText(value: unknown, options: TerminalSanitizeOptions = {}): string {
	const preserveNewlines = options.preserveNewlines ?? true;
	const preserveTabs = options.preserveTabs ?? true;
	let text = typeof value === "string" ? value : String(value ?? "");
	text = text.replace(TERMINAL_ESCAPES, "").replace(INVISIBLE_UNICODE, "").replace(UNICODE_TAGS, "");
	return text.replace(/[\u0000-\u001f\u007f-\u009f]/g, (control) => {
		if (control === "\n" && preserveNewlines) return "\n";
		if (control === "\t" && preserveTabs) return "\t";
		return "";
	});
}
