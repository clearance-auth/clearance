const SECRET_KEY = /(?:password|secret|token|authorization|cookie|body|html|text|to|from|replyto|destination|payload|envelope)/i;

export type WorkerLogger = { log(level: "debug" | "info" | "warn" | "error", event: string, fields?: Record<string, unknown>): void };

function sanitize(value: unknown, depth = 0): unknown {
	if (depth > 4) return "[truncated]";
	if (value instanceof Error) return { name: value.name, code: "code" in value ? String(value.code) : undefined };
	if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitize(item, depth + 1));
	if (value && typeof value === "object") {
		return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, SECRET_KEY.test(key) ? "[redacted]" : sanitize(item, depth + 1)]));
	}
	if (typeof value === "string") return value.length > 256 ? `${value.slice(0, 256)}…` : value;
	return value;
}

export function createJsonLogger(write: (line: string) => void = (line) => process.stdout.write(`${line}\n`)): WorkerLogger {
	return { log(level, event, fields = {}) { write(JSON.stringify({ time: new Date().toISOString(), level, event, ...sanitize(fields) as object })); } };
}
