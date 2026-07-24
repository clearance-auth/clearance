import {
	createRemoteVerifier,
	type RemoteVerifierOptions,
} from "@clearance/verification";

function required(name: "CLEARANCE_ISSUER" | "CLEARANCE_AUDIENCE"): string {
	const value = process.env[name];
	if (!value) throw new Error(`${name} must be set`);
	return value;
}

function options(): RemoteVerifierOptions {
	const base = {
		issuer: required("CLEARANCE_ISSUER"),
		audience: required("CLEARANCE_AUDIENCE"),
	};
	const jwksUrl = process.env.CLEARANCE_JWKS_URL;
	return {
		...base,
		...(jwksUrl ? { jwksUrl } : {}),
		...(process.env.CLEARANCE_ALLOW_INSECURE_LOOPBACK === "true"
			? { allowInsecureLoopback: true }
			: {}),
	};
}

// HTTP requires this explicit option and is still constrained to loopback hosts.
export const verifier = createRemoteVerifier(options());

const BEARER_TOKEN = /^Bearer[ \t]+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i;

export function bearerToken(header: string | undefined): string | null {
	return header?.match(BEARER_TOKEN)?.[1] ?? null;
}
