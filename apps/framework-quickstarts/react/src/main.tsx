/// <reference types="vite/client" />

import { createAuthClient } from "@clearance/runtime/react";
import { useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";

const authClient = createAuthClient({
	baseURL: import.meta.env.VITE_CLEARANCE_URL ?? "http://localhost:3300",
});

function App() {
	const session = authClient.useSession();
	const [email, setEmail] = useState("");
	const [password, setPassword] = useState("");
	const [error, setError] = useState<string | null>(null);

	async function signIn(event: FormEvent<HTMLFormElement>): Promise<void> {
		event.preventDefault();
		setError(null);
		const result = await authClient.signIn.email({ email, password });
		if (result.error) {
			setError(result.error.message ?? "Sign-in failed");
			return;
		}
		await session.refetch();
	}

	if (session.isPending) return <main>Loading session…</main>;
	if (session.data) {
		return (
			<main>
				<h1>Clearance + React</h1>
				<p>Signed in</p>
				<button
					type="button"
					onClick={() => {
						void authClient.signOut().then(() => session.refetch());
					}}
				>
					Sign out
				</button>
			</main>
		);
	}

	return (
		<main>
			<h1>Clearance + React</h1>
			<form onSubmit={signIn}>
				<label>
					Email
					<input
						autoComplete="email"
						onChange={(event) => setEmail(event.currentTarget.value)}
						required
						type="email"
						value={email}
					/>
				</label>
				<label>
					Password
					<input
						autoComplete="current-password"
						onChange={(event) => setPassword(event.currentTarget.value)}
						required
						type="password"
						value={password}
					/>
				</label>
				<button type="submit">Sign in</button>
				{error ? <p role="alert">{error}</p> : null}
			</form>
		</main>
	);
}

const root = document.getElementById("root");
if (!root) throw new Error("React root element is missing");
createRoot(root).render(<App />);
