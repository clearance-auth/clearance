/**
 * The single eligibility check for every CLI interaction.
 *
 * Keep this independent of Commander so callers can make the decision before
 * registering a bare-command action or entering a guided workflow.
 */
export interface InteractionPolicyInput {
	stdin?: { isTTY?: boolean };
	stdout?: { isTTY?: boolean };
	stderr?: { isTTY?: boolean };
	env?: Record<string, string | undefined>;
	noInput?: boolean;
	json?: boolean;
	machineOutput?: boolean;
}

export type InteractionIneligibility =
	| "stdin-not-tty"
	| "stdout-not-tty"
	| "stderr-not-tty"
	| "noninteractive-environment"
	| "ci-environment"
	| "no-input"
	| "machine-output";

export interface InteractionEligibility {
	eligible: boolean;
	reason?: InteractionIneligibility;
}

function isSet(value: string | undefined): boolean {
	return value !== undefined && value.length > 0;
}

/**
 * Return whether it is safe to write prompts. Interaction is deliberately
 * unavailable when any standard stream is redirected, in automation, or when
 * a caller has requested an output contract intended for machines.
 */
export function interactionEligibility(input: InteractionPolicyInput = {}): InteractionEligibility {
	const stdin = input.stdin ?? process.stdin;
	const stdout = input.stdout ?? process.stdout;
	const stderr = input.stderr ?? process.stderr;
	const env = input.env ?? process.env;

	if (!stdin.isTTY) return { eligible: false, reason: "stdin-not-tty" };
	if (!stdout.isTTY) return { eligible: false, reason: "stdout-not-tty" };
	if (!stderr.isTTY) return { eligible: false, reason: "stderr-not-tty" };
	if (isSet(env.CLEARANCE_NONINTERACTIVE)) return { eligible: false, reason: "noninteractive-environment" };
	if (isSet(env.CI)) return { eligible: false, reason: "ci-environment" };
	if (input.noInput) return { eligible: false, reason: "no-input" };
	if (input.json || input.machineOutput) return { eligible: false, reason: "machine-output" };
	return { eligible: true };
}

export function canInteract(input: InteractionPolicyInput = {}): boolean {
	return interactionEligibility(input).eligible;
}
