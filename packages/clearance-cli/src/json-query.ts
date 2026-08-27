export class JsonQueryError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "JsonQueryError";
	}
}

/**
 * Evaluate the intentionally small, deterministic jq subset used by the CLI.
 * Supported selectors are `.`, dotted object fields, numeric array indexes,
 * and `[]` array expansion, for example `.data.users[]` or `.data.items[0].id`.
 */
export function evaluateJsonQuery(value: unknown, expression: string): unknown {
	const query = expression.trim();
	if (query === ".") return value;
	if (!query.startsWith(".")) {
		throw new JsonQueryError("--jq expressions must start with '.'.");
	}
	const tokens = query.slice(1).match(/(?:[A-Za-z_$][\w$-]*|\[(?:\d*)\])/gu);
	const reconstructed = tokens?.join("") ?? "";
	if (!tokens || reconstructed !== query.slice(1).replace(/\./gu, "")) {
		throw new JsonQueryError("Unsupported --jq expression. Use dotted fields, [index], or [].");
	}
	let current: unknown[] = [value];
	let expanded = false;
	for (const token of tokens) {
		if (token === "[]") {
			expanded = true;
			current = current.flatMap((entry) => {
				if (!Array.isArray(entry)) throw new JsonQueryError("--jq [] requires an array.");
				return entry;
			});
			continue;
		}
		const indexMatch = /^\[(\d+)\]$/u.exec(token);
		if (indexMatch) {
			const index = Number(indexMatch[1]);
			current = current.map((entry) => {
				if (!Array.isArray(entry)) throw new JsonQueryError("--jq [index] requires an array.");
				return entry[index] ?? null;
			});
			continue;
		}
		current = current.map((entry) => {
			if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
				throw new JsonQueryError(`--jq could not select ${token} from a non-object value.`);
			}
			const object = entry as Record<string, unknown>;
			return Object.hasOwn(object, token) ? object[token] : null;
		});
	}
	return expanded || current.length !== 1 ? current : current[0];
}
