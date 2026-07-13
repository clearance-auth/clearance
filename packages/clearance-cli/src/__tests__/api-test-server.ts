import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const apiEntry = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"../../../clearance-api/dist/server.js",
);
const OPERATOR_TOKEN = "test-operator-token-for-cli-api-32chars!!";
const servers = new Map<string, { process: ChildProcess; apiUrl: string }>();

function allocatePort(): number {
	return Number(execFileSync(process.execPath, [
		"-e",
		"const net=require('node:net');const s=net.createServer();s.listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close()})",
	], { encoding: "utf8" }).trim());
}

function pause(milliseconds: number): void {
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

export function authenticatedApiEnv(dataPath: string): NodeJS.ProcessEnv {
	const existing = servers.get(dataPath);
	if (existing) {
		return {
			CLEARANCE_OPERATOR_TOKEN: OPERATOR_TOKEN,
			CLEARANCE_API_URL: existing.apiUrl,
		};
	}

	const port = allocatePort();
	const apiUrl = `http://127.0.0.1:${port}`;
	const child = spawn(process.execPath, [apiEntry], {
		env: {
			...process.env,
			DATABASE_URL: "",
			CLEARANCE_DATA_PATH: dataPath,
			CLEARANCE_API_PORT: String(port),
			CLEARANCE_OPERATOR_TOKEN: OPERATOR_TOKEN,
			CLEARANCE_SECRET: "unit-test-secret-value-not-default!!",
			CLEARANCE_BASE_URL: apiUrl,
			CLEARANCE_CORS_ORIGINS: "http://localhost:3100",
			CLEARANCE_CREDENTIAL_KEY: "unit-test-credential-key-material-32b!!",
			CLEARANCE_CREDENTIAL_KEY_ID: "k1",
			NODE_ENV: "development",
		},
		stdio: ["ignore", "ignore", "ignore"],
	});
	servers.set(dataPath, { process: child, apiUrl });

	let ready = false;
	for (let attempt = 0; attempt < 100; attempt += 1) {
		if (child.exitCode !== null) break;
		try {
			execFileSync("curl", ["--fail", "--silent", "--max-time", "1", `${apiUrl}/livez`], {
				stdio: "ignore",
			});
			ready = true;
			break;
		} catch {
			pause(50);
		}
	}
	if (!ready) {
		child.kill("SIGTERM");
		servers.delete(dataPath);
		throw new Error(`Clearance API test server failed to start at ${apiUrl}`);
	}

	return {
		CLEARANCE_OPERATOR_TOKEN: OPERATOR_TOKEN,
		CLEARANCE_API_URL: apiUrl,
	};
}

export function stopAuthenticatedApiServers(): void {
	for (const server of servers.values()) {
		server.process.kill("SIGTERM");
	}
	servers.clear();
}
