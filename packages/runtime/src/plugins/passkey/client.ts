import type {
	ClearanceClientOptions,
	ClearanceClientPlugin,
	ClientFetchOption,
	ClientStore,
} from "@clearance/core";
import type {
	PublicKeyCredentialCreationOptionsJSON,
	PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { BetterFetch } from "@better-fetch/fetch";
import { atom } from "nanostores";
import { useAuthQuery } from "../../client";
import type { Session, User } from "../../types";
import { PACKAGE_VERSION } from "../../version";
import { PASSKEY_ERROR_CODES } from "./error-codes";
import type { passkey } from ".";
import type { PublicPasskey } from "./types";

type PasskeyDeletionProof =
	| { type: "password"; password: string }
	| { type: "totp"; code: string }
	| { type: "recovery-code"; code: string }
	| { type: "passkey" };

const getPasskeyActions = (
	$fetch: BetterFetch,
	{
		$listPasskeys,
		$store,
	}: {
		$listPasskeys: ReturnType<typeof atom<number>>;
		$store: ClientStore;
	},
) => {
	const addPasskey = async (
		opts?:
			| {
					name?: string;
					authenticatorAttachment?: "platform" | "cross-platform";
					fetchOptions?: ClientFetchOption;
			  }
			| undefined,
	) => {
		const options = await $fetch<PublicKeyCredentialCreationOptionsJSON>(
			"/passkey/generate-registration-options",
			{
				...opts?.fetchOptions,
				method: "POST",
				body: {
					...(opts?.authenticatorAttachment
						? { authenticatorAttachment: opts.authenticatorAttachment }
						: {}),
				},
				throw: false,
			},
		);
		if (!options.data) {
			return options;
		}
		let credential: Awaited<ReturnType<typeof startRegistration>>;
		try {
			credential = await startRegistration({ optionsJSON: options.data });
		} catch {
			// Generic failure shape: never leak platform, cancellation, or
			// authenticator-specific distinctions to the caller.
			return {
				data: null,
				error: {
					code: "REGISTRATION_FAILED",
					message: PASSKEY_ERROR_CODES.REGISTRATION_FAILED.message,
					status: 400,
					statusText: "BAD_REQUEST",
				},
			};
		}
		const verified = await $fetch<PublicPasskey>("/passkey/verify-registration", {
			...opts?.fetchOptions,
			method: "POST",
			body: {
				response: credential,
				name: opts?.name,
			},
			throw: false,
		});
		if (verified.data) {
			$listPasskeys.set(Date.now());
		}
		return verified;
	};

	const signInPasskey = async (
		opts?: { fetchOptions?: ClientFetchOption } | undefined,
	) => {
		const options = await $fetch<PublicKeyCredentialRequestOptionsJSON>(
			"/passkey/generate-authentication-options",
			{
				...opts?.fetchOptions,
				method: "POST",
				throw: false,
			},
		);
		if (!options.data) {
			return options;
		}
		let credential: Awaited<ReturnType<typeof startAuthentication>>;
		try {
			credential = await startAuthentication({ optionsJSON: options.data });
		} catch {
			// Generic failure shape: never leak platform, cancellation, or
			// authenticator-specific distinctions to the caller.
			return {
				data: null,
				error: {
					code: "AUTHENTICATION_FAILED",
					message: PASSKEY_ERROR_CODES.AUTHENTICATION_FAILED.message,
					status: 400,
					statusText: "BAD_REQUEST",
				},
			};
		}
		const verified = await $fetch<{ session: Session; user: User }>(
			"/passkey/verify-authentication",
			{
				...opts?.fetchOptions,
				method: "POST",
				body: {
					response: credential,
				},
				throw: false,
			},
		);
		if (verified.data) {
			$store.notify("$sessionSignal");
		}
		return verified;
	};

	const renamePasskey = async (opts: {
		id: string;
		name: string;
		fetchOptions?: ClientFetchOption;
	}) => {
		const updated = await $fetch<PublicPasskey>("/passkey/update", {
			...opts.fetchOptions,
			method: "POST",
			body: {
				id: opts.id,
				name: opts.name,
			},
			throw: false,
		});
		if (updated.data) {
			$listPasskeys.set(Date.now());
		}
		return updated;
	};

	const deletePasskey = async (opts: {
		id: string;
		proof: PasskeyDeletionProof;
		fetchOptions?: ClientFetchOption;
	}) => {
		let proof:
			| Exclude<PasskeyDeletionProof, { type: "passkey" }>
			| {
					type: "passkey";
					response: Awaited<ReturnType<typeof startAuthentication>>;
			  };

		if (opts.proof.type === "passkey") {
			const options = await $fetch<PublicKeyCredentialRequestOptionsJSON>(
				"/passkey/generate-deletion-options",
				{
					...opts.fetchOptions,
					method: "POST",
					body: { id: opts.id },
					throw: false,
				},
			);
			if (!options.data) {
				return options;
			}

			let response: Awaited<ReturnType<typeof startAuthentication>>;
			try {
				response = await startAuthentication({ optionsJSON: options.data });
			} catch {
				return {
					data: null,
					error: {
						code: "DELETION_PROOF_FAILED",
						message: PASSKEY_ERROR_CODES.DELETION_PROOF_FAILED.message,
						status: 401,
						statusText: "UNAUTHORIZED",
					},
				};
			}
			proof = { type: "passkey", response };
		} else {
			proof = opts.proof;
		}

		const deleted = await $fetch<{ status: true }>("/passkey/delete", {
			...opts.fetchOptions,
			method: "POST",
			body: { id: opts.id, proof },
			throw: false,
		});
		if (deleted.data) {
			$listPasskeys.set(Date.now());
			$store.notify("$sessionSignal");
		}
		return deleted;
	};

	return {
		signIn: {
			passkey: signInPasskey,
		},
		passkey: {
			addPasskey,
			deletePasskey,
			/** Ownership-scoped rename: the server enforces the caller owns `id`. */
			renamePasskey,
		},
	};
};

export const passkeyClient = () => {
	const $listPasskeys = atom<number>(0);
	return {
		id: "passkey",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof passkey>,
		getActions: (
			$fetch: BetterFetch,
			$store: ClientStore,
			_options: ClearanceClientOptions | undefined,
		) => getPasskeyActions($fetch, { $listPasskeys, $store }),
		getAtoms($fetch: BetterFetch) {
			const listPasskeys = useAuthQuery<PublicPasskey[]>(
				$listPasskeys,
				"/passkey/list",
				$fetch,
				{ method: "GET" },
			);
			return {
				listPasskeys,
				$listPasskeys,
			};
		},
		pathMethods: {
			"/passkey/generate-registration-options": "POST",
			"/passkey/generate-authentication-options": "POST",
			"/passkey/generate-deletion-options": "POST",
			"/passkey/delete": "POST",
			"/passkey/list": "GET",
			"/passkey/update": "POST",
		},
		atomListeners: [
			{
				matcher: (path) =>
					path === "/passkey/verify-registration" ||
					path === "/passkey/update" ||
					path === "/passkey/delete" ||
					path === "/sign-out",
				signal: "$listPasskeys",
			},
			{
				matcher: (path) =>
					path === "/passkey/verify-authentication" || path === "/passkey/delete",
				signal: "$sessionSignal",
			},
		],
		$ERROR_CODES: PASSKEY_ERROR_CODES,
	} satisfies ClearanceClientPlugin;
};
