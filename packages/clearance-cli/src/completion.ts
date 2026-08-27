import type { CommandOptionSpec, CommandSpecDocument } from "./command-spec.js";

export type CompletionShell = "bash" | "zsh" | "fish";

export type CompletionOption = Pick<CommandOptionSpec, "flags">;

type CompletionNode = {
	readonly path: string;
	readonly commands: readonly string[];
	readonly flags: readonly string[];
};

function flagNames(options: readonly CompletionOption[]): readonly string[] {
	return [...new Set(options.flatMap(({ flags }) => flags.match(/--?[A-Za-z0-9][A-Za-z0-9-]*/gu) ?? []))].sort();
}

function optionNeedsValue(options: readonly CompletionOption[]): readonly string[] {
	return [...new Set(options
		.filter(({ flags }) => /[<[][^>\]]+[>\]]/u.test(flags))
		.flatMap(({ flags }) => flags.match(/--?[A-Za-z0-9][A-Za-z0-9-]*/gu) ?? []))].sort();
}

function completionNodes(
	document: CommandSpecDocument,
	globalOptions: readonly CompletionOption[],
): readonly CompletionNode[] {
	const globalFlags = flagNames(globalOptions);
	const nodes = new Map<string, { commands: Set<string>; flags: Set<string> }>();
	const nodeFor = (path: string) => {
		let node = nodes.get(path);
		if (!node) {
			node = { commands: new Set(), flags: new Set(globalFlags) };
			nodes.set(path, node);
		}
		return node;
	};
	nodeFor("");
	for (const command of document.commands) {
		const parts = command.path.split(" ");
		for (let index = 0; index < parts.length; index += 1) {
			const path = parts.slice(0, index).join(" ");
			nodeFor(path).commands.add(parts[index]!);
		}
		const leaf = nodeFor(command.path);
		for (const flag of flagNames(command.options)) leaf.flags.add(flag);
	}
	return [...nodes.entries()]
		.map(([path, node]) => ({
			path,
			commands: [...node.commands].sort(),
			flags: [...node.flags].sort(),
		}))
		.sort((left, right) => left.path.localeCompare(right.path));
}

function quoteShellWords(words: readonly string[]): string {
	return words.map((word) => `'${word.replaceAll("'", "'\\''")}'`).join(" ");
}

function shellCase(nodes: readonly CompletionNode[]): string {
	return nodes.map(({ path, commands, flags }) => {
		const values = quoteShellWords([...commands, ...flags]);
		return `\t\t${path ? `'${path}'` : "''"}) candidates=(${values});;`;
	}).join("\n");
}

function fishCondition(path: string): string {
	return path ? `__clearance_path_is ${quoteShellWords(path.split(" "))}` : "__clearance_path_is";
}

/**
 * Project command and option completions from the command-spec document. The
 * optional global options should be Commander program options so root flags do
 * not drift from the CLI implementation.
 */
export function renderCompletion(
	shell: CompletionShell,
	document: CommandSpecDocument,
	globalOptions: readonly CompletionOption[] = [],
): string {
	const nodes = completionNodes(document, globalOptions);
	const valueFlags = quoteShellWords(optionNeedsValue([
		...globalOptions,
		...document.commands.flatMap((command) => command.options),
	]));
	if (shell === "bash") {
		return `_clearance_complete() {
	local cur="${"${COMP_WORDS[COMP_CWORD]}"}" word skip_value=0 path=() candidates=()
	for word in "${"${COMP_WORDS[@]:1:COMP_CWORD}"}"; do
	\tif (( skip_value )); then skip_value=0; continue; fi
	\tcase "$word" in
	\t\t${valueFlags}) skip_value=1 ;;
	\t\t--*) ;;
	\t\t*) path+=("$word") ;;
	\tesac
	done
	case "${"${path[*]}"}" in
${shellCase(nodes)}
	esac
	COMPREPLY=( $(compgen -W "${"${candidates[*]}"}" -- "$cur") )
}
complete -F _clearance_complete clearance`;
	}
	if (shell === "zsh") {
		return `#compdef clearance
_clearance() {
	local -a path candidates
	local word skip_value=0
	for word in "${"${words[@]:1:$CURRENT-2}"}"; do
	\tif (( skip_value )); then skip_value=0; continue; fi
	\tcase "$word" in
	\t\t${valueFlags}) skip_value=1 ;;
	\t\t--*) ;;
	\t\t*) path+=("$word") ;;
	\tesac
	done
	case "${"${(j: :)path}"}" in
${shellCase(nodes)}
	esac
	compadd -- $candidates
}
_clearance`;
	}
	const globalFlags = flagNames(globalOptions);
	return `function __clearance_path_is
	set -l expected $argv
	set -l words (commandline -opc | tail -n +2 | string match -rv '^--')
	test (count $words) -eq (count $expected); and test (string join ' ' -- $words) = (string join ' ' -- $expected)
end
${globalFlags.map((flag) => `complete -c clearance -f -a ${quoteShellWords([flag])}`).join("\n")}
${nodes.map(({ path, commands, flags }) => {
	const leafFlags = flags.filter((flag) => !globalFlags.includes(flag));
	const candidates = [...commands, ...leafFlags];
	return candidates.length === 0 ? "" : `complete -c clearance -f -n '${fishCondition(path)}' -a ${quoteShellWords(candidates)}`;
}).filter(Boolean).join("\n")}`;
}
