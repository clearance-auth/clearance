"use client";

import { useState, type FormEvent } from "react";

export default function HomePage() {
	const [token, setToken] = useState("");
	const [result, setResult] = useState("Paste a token and verify it.");

	async function verify(event: FormEvent<HTMLFormElement>): Promise<void> {
		event.preventDefault();
		const response = await fetch("/api/me", {
			headers: token.trim() ? { authorization: `Bearer ${token.trim()}` } : {},
		});
		setResult(JSON.stringify(await response.json(), null, 2));
	}

	return (
		<main style={{ fontFamily: "system-ui", margin: "3rem auto", maxWidth: "42rem" }}>
			<h1>Clearance + Next.js</h1>
			<p>The App Router route handler verifies the token with the remote Clearance JWKS.</p>
			<form onSubmit={verify}>
				<textarea aria-label="Access token" onChange={(event) => setToken(event.target.value)} rows={8} style={{ width: "100%" }} value={token} />
				<p><button type="submit">Verify token</button></p>
			</form>
			<pre>{result}</pre>
		</main>
	);
}
