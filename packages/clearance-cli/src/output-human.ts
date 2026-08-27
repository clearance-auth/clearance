export interface HumanSuccessContent {
	data: unknown;
	summary: string | null;
	notice: string | null;
	next: readonly string[];
}

function label(key: string): string {
	return key
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.replace(/[_-]+/g, " ")
		.replace(/^./, (character) => character.toUpperCase());
}

function scalar(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string") return value;
	if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
		return String(value);
	}
	return JSON.stringify(value);
}

function renderArray(values: readonly unknown[], indent: string): string[] {
	if (values.length === 0) return [`${indent}[]`];
	return values.flatMap((value) => {
		if (value !== null && typeof value === "object") {
			const nested = renderHumanData(value, `${indent}  `);
			const [first = "", ...rest] = nested.split("\n");
			return [`${indent}- ${first.trimStart()}`, ...rest];
		}
		return [`${indent}- ${scalar(value)}`];
	});
}

/** Render arbitrary command data without changing or filtering its shape. */
export function renderHumanData(data: unknown, indent = ""): string {
	if (Array.isArray(data)) return renderArray(data, indent).join("\n");
	if (data !== null && typeof data === "object") {
		const entries = Object.entries(data as Record<string, unknown>);
		if (entries.length === 0) return `${indent}{}`;
		return entries.flatMap(([key, value]) => {
			if (Array.isArray(value)) {
				return [`${indent}${label(key)}:`, ...renderArray(value, `${indent}  `)];
			}
			if (value !== null && typeof value === "object") {
				return [`${indent}${label(key)}:`, renderHumanData(value, `${indent}  `)];
			}
			return [`${indent}${label(key)}: ${scalar(value)}`];
		}).join("\n");
	}
	return `${indent}${scalar(data)}`;
}

export function renderHumanSuccess(content: Readonly<HumanSuccessContent>): string {
	const sections: string[] = [];
	if (content.summary) sections.push(content.summary);
	else sections.push(renderHumanData(content.data));
	if (content.notice) sections.push(`Notice: ${content.notice}`);
	if (content.next.length > 0) {
		sections.push(["Next:", ...content.next.map((step) => `  - ${step}`)].join("\n"));
	}
	return sections.join("\n\n");
}

export function renderHumanError(error: {
	code: string;
	message: string;
	stage: string;
	remediation: string | null;
}): string {
	const lines = [`Error [${error.code}] stage=${error.stage}: ${error.message}`];
	if (error.remediation) lines.push(`Remediation: ${error.remediation}`);
	return lines.join("\n");
}
