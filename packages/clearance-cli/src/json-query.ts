export class JsonQueryError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "JsonQueryError";
	}
}

type JsonQueryToken = string;

/** Parse and validate a selector without inspecting command output. */
export function validateJsonQuery(expression: string): readonly JsonQueryToken[] {
	const query = expression.trim();
	if (query === ".") return [];
	if (!query.startsWith(".")) {
		throw new JsonQueryError("--jq expressions must start with '.'.");
	}
	const tokens = query.slice(1).match(/(?:[A-Za-z_$][\w$-]*|\[(?:\d*)\])/gu);
	const reconstructed = tokens?.join("") ?? "";
	if (!tokens || reconstructed !== query.slice(1).replace(/\./gu, "")) {
		throw new JsonQueryError("Unsupported --jq expression. Use dotted fields, [index], or [].");
	}
	return Object.freeze(tokens);
}

/**
 * Evaluate the intentionally small, deterministic jq subset used by the CLI.
 * Supported selectors are `.`, dotted object fields, numeric array indexes,
 * and `[]` array expansion, for example `.data.users[]` or `.data.items[0].id`.
 */
export function evaluateJsonQuery(value: unknown, expression: string): unknown {
	const query = expression.trim();
	if (query === ".") return value;
	const tokens = validateJsonQuery(query);
	let current: unknown[] = [value];
	let expanded = false;
	for (const token of tokens) {
		if (token === "[]") {
			expanded = true;
			// Selection is deliberately total once its syntax is validated. This
			// keeps a selector from turning a completed mutation or issued secret
			// into a reported command failure merely because the result was empty.
			current = current.flatMap((entry) => Array.isArray(entry) ? entry : []);
			continue;
		}
		const indexMatch = /^\[(\d+)\]$/u.exec(token);
		if (indexMatch) {
			const index = Number(indexMatch[1]);
			current = current.map((entry) => Array.isArray(entry) ? entry[index] ?? null : null);
			continue;
		}
		current = current.map((entry) => {
			if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
				return null;
			}
			const object = entry as Record<string, unknown>;
			return Object.hasOwn(object, token) ? object[token] : null;
		});
	}
	return expanded || current.length !== 1 ? current : current[0];
}
