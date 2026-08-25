#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { parseDocument } from "yaml";
import { bundledRuntimePackages, publicReleasePackageCount, publicReleasePackages, runtimeClosurePackageNames } from "./release-packages.mjs";

const root = resolve(process.env.CLEARANCE_RELEASE_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const version = process.argv[2]?.trim();
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

function fail(message) {
	process.stderr.write(`release version check failed: ${message}\n`);
	process.exit(1);
}

function read(relative) { return readFileSync(resolve(root, relative), "utf8"); }

function yaml(relative) {
	const document = parseDocument(read(relative), { schema: "core", strict: true, uniqueKeys: true });
	if (document.errors.length > 0) fail(`invalid ${relative}: ${document.errors[0].message}`);
	const value = document.toJS({ maxAliasCount: 0 });
	if (!value || typeof value !== "object") fail(`${relative} must be a mapping`);
	return value;
}

function exportedStringConst(source, name) {
	const file = ts.createSourceFile(`${name}.ts`, source, ts.ScriptTarget.Latest, false, ts.ScriptKind.TS);
	const declarations = [];
	for (const statement of file.statements) {
		if (!ts.isVariableStatement(statement)
			|| !statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
			|| !(statement.declarationList.flags & ts.NodeFlags.Const)) continue;
		for (const declaration of statement.declarationList.declarations) if (ts.isIdentifier(declaration.name) && declaration.name.text === name) declarations.push(declaration);
	}
	return declarations.length === 1 && ts.isStringLiteral(declarations[0].initializer) ? declarations[0].initializer.text : undefined;
}

function healthVersion(source) {
	const file = ts.createSourceFile("server.ts", source, ts.ScriptTarget.Latest, false, ts.ScriptKind.TS);
	const routes = file.statements.flatMap((statement) => {
		if (!ts.isExpressionStatement(statement) || !ts.isCallExpression(statement.expression)) return [];
		const call = statement.expression;
		return ts.isPropertyAccessExpression(call.expression) && ts.isIdentifier(call.expression.expression) && call.expression.expression.text === "app"
			&& call.expression.name.text === "get" && ts.isStringLiteral(call.arguments[0]) && call.arguments[0].text === "/health" ? [call] : [];
	});
	if (routes.length !== 1) return undefined;
	const handler = routes[0].arguments[1];
	if (!handler || (!ts.isArrowFunction(handler) && !ts.isFunctionExpression(handler)) || !ts.isBlock(handler.body)
		|| handler.body.statements.length !== 1 || !ts.isReturnStatement(handler.body.statements[0])) return undefined;
	const response = handler.body.statements[0].expression;
	if (!response || !ts.isCallExpression(response) || !ts.isPropertyAccessExpression(response.expression)
		|| !ts.isIdentifier(response.expression.expression) || response.expression.expression.text !== "c"
		|| response.expression.name.text !== "json" || !response.arguments[0] || !ts.isObjectLiteralExpression(response.arguments[0])
		|| response.arguments[0].properties.some((property) => !ts.isPropertyAssignment(property)
			|| (!ts.isIdentifier(property.name) && !ts.isStringLiteral(property.name)))) return undefined;
	const versions = response.arguments[0].properties.filter((property) =>
		ts.isPropertyAssignment(property)
		&& ((ts.isIdentifier(property.name) && property.name.text === "version") || (ts.isStringLiteral(property.name) && property.name.text === "version")));
	return versions.length === 1 && ts.isPropertyAssignment(versions[0]) && ts.isStringLiteral(versions[0].initializer)
		? versions[0].initializer.text : undefined;
}

function namedStep(steps, name) {
	const matches = steps.map((step, index) => ({ step, index })).filter(({ step }) => step?.name === name);
	if (matches.length !== 1) fail(`release workflow must contain exactly one ${name} step`);
	return matches[0];
}

function identityHarness(run, scenario) {
	const directory = mkdtempSync(join(tmpdir(), "clearance-release-identity-"));
	const bin = join(directory, "bin");
	mkdirSync(bin);
	const git = join(bin, "git");
	writeFileSync(git, `#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\\n' "$*" >> "$CLEARANCE_TEST_GIT_LOG"
case "$*" in
  "rev-parse --is-shallow-repository") printf '%s\\n' "\${CLEARANCE_TEST_GIT_SHALLOW:-false}" ;;
  "rev-parse refs/tags/v"*"{commit}") printf '%s\\n' "\${CLEARANCE_TEST_GIT_TAG_COMMIT:-commit}" ;;
  "rev-parse HEAD") printf '%s\\n' "\${CLEARANCE_TEST_GIT_HEAD_COMMIT:-commit}" ;;
  "rev-parse --verify --quiet origin/master^{commit}") printf '%s\\n' "commit" ;;
  "merge-base --is-ancestor commit origin/master") test "\${CLEARANCE_TEST_GIT_ANCESTOR:-true}" = "true" ;;
  *) printf 'unexpected git invocation: %s\\n' "$*" >&2; exit 64 ;;
esac
`, "utf8");
	chmodSync(git, 0o700);
	const githubOutput = join(directory, "github-output");
	const githubEnv = join(directory, "github-env");
	const gitLog = join(directory, "git-log");
	writeFileSync(githubOutput, "", "utf8");
	writeFileSync(githubEnv, "", "utf8");
	writeFileSync(gitLog, "", "utf8");
	// GitHub Actions uses Bash 5; after its lowercase-repository assertion, this Bash 3 compatibility substitution is equivalent.
	const executableRun = run.includes("${GITHUB_REPOSITORY,,}")
		? run.replaceAll("${GITHUB_REPOSITORY,,}", "${GITHUB_REPOSITORY}")
		: run;
	const result = spawnSync("bash", ["-c", executableRun], {
		encoding: "utf8",
		env: {
			PATH: `${bin}:/usr/bin:/bin`,
			REQUESTED_VERSION: "0.3.0",
			CLEARANCE_RELEASE_SIGNING_KEY: "test-key",
			GITHUB_REPOSITORY: "clearance-auth/clearance",
			GITHUB_SHA: "commit",
			GITHUB_RUN_ID: "1",
			GITHUB_RUN_ATTEMPT: "1",
			RECOVER_PUBLISHED_NPM: "0",
			GITHUB_OUTPUT: githubOutput,
			GITHUB_ENV: githubEnv,
			CLEARANCE_TEST_GIT_LOG: gitLog,
			...scenario,
		},
	});
	return { status: result.status, env: readFileSync(githubEnv, "utf8"), git: readFileSync(gitLog, "utf8") };
}

function verifyIdentity(run) {
	const canonicalWorkflow = "clearance-auth/clearance/.github/workflows/release-sign.yml@refs/heads/master";
	const recovery = { GITHUB_EVENT_NAME: "workflow_dispatch", RECOVER_PUBLISHED_NPM: "1", GITHUB_REF: "refs/heads/master", GITHUB_WORKFLOW_REF: canonicalWorkflow, GITHUB_WORKFLOW_SHA: "commit" };
	const tag = { GITHUB_EVENT_NAME: "push", REQUESTED_VERSION: "v0.3.0", GITHUB_REF: "refs/tags/v0.3.0", GITHUB_WORKFLOW_REF: "", GITHUB_WORKFLOW_SHA: "" };
	const outcomes = [
		[true, tag], [true, recovery],
		[false, { ...tag, REQUESTED_VERSION: "invalid" }],
		[false, { ...tag, CLEARANCE_TEST_GIT_SHALLOW: "true" }], [false, { ...tag, CLEARANCE_TEST_GIT_TAG_COMMIT: "different" }],
		[false, { ...tag, GITHUB_REPOSITORY: "fork/clearance" }],
		[false, { ...recovery, RECOVER_PUBLISHED_NPM: "0" }], [false, { ...recovery, GITHUB_REF: "refs/heads/next" }],
		[false, { ...recovery, GITHUB_WORKFLOW_REF: canonicalWorkflow.replace("master", "next") }], [false, { ...recovery, GITHUB_WORKFLOW_SHA: "wrong" }],
	].map(([allowed, scenario]) => ({ allowed, recovery: scenario.RECOVER_PUBLISHED_NPM === "1", ...identityHarness(run, scenario) }));
	const expectedEnvironment = [
		"VERSION=0.3.0",
		"SOURCE_COMMIT=commit",
		"COSIGN_IDENTITY=https://github.com/clearance-auth/clearance/.github/workflows/release-sign.yml@refs/tags/v0.3.0",
		"IMAGE=ghcr.io/clearance-auth/clearance/clearance:0.3.0",
		"BACKUP_IMAGE=ghcr.io/clearance-auth/clearance/clearance-backup:0.3.0",
		"STAGING_IMAGE=ghcr.io/clearance-auth/clearance/clearance:staging-1-1",
		"STAGING_BACKUP_IMAGE=ghcr.io/clearance-auth/clearance/clearance-backup:staging-1-1",
	];
	const expectedRecoveryGit = [
		"rev-parse --is-shallow-repository",
		"rev-parse refs/tags/v0.3.0^{commit}",
		"rev-parse HEAD",
		"rev-parse HEAD",
	];
	const expectedTagGit = [
		"rev-parse --is-shallow-repository",
		"rev-parse refs/tags/v0.3.0^{commit}",
		"rev-parse HEAD",
		"rev-parse HEAD",
		"rev-parse --is-shallow-repository",
		"rev-parse --verify --quiet origin/master^{commit}",
		"merge-base --is-ancestor commit origin/master",
		"rev-parse HEAD",
	];
	if (outcomes.some(({ allowed, status }) => allowed !== (status === 0))
		|| outcomes.filter(({ allowed }) => allowed).some(({ recovery, env, git }) => {
			const expectedGit = recovery ? expectedRecoveryGit : expectedTagGit;
			const lines = env.trim().split("\n");
			const gitLines = git.trim().split("\n");
			return lines.length !== expectedEnvironment.length || expectedEnvironment.some((expected, index) => lines[index] !== expected)
				|| gitLines.length !== expectedGit.length || expectedGit.some((expected, index) => gitLines[index] !== expected);
		})) {
		fail("identity step must export the exact release contract, accept valid tag/recovery scenarios, and reject forbidden dispatch or invalid recovery");
	}
}

function verifyTagAuthority() {
	const directory = mkdtempSync(join(tmpdir(), "clearance-release-tag-authority-"));
	const remote = join(directory, "origin.git");
	const worktree = join(directory, "worktree");
	const git = (...args) => {
		const result = spawnSync("git", args, { encoding: "utf8" });
		if (result.status !== 0) fail(`tag-authority self-test git ${args.join(" ")} failed: ${result.stderr.trim()}`);
		return result.stdout.trim();
	};
	git("init", "--bare", remote);
	git("init", "--initial-branch=master", worktree);
	git("-C", worktree, "config", "user.email", "release-test@clearance.invalid");
	git("-C", worktree, "config", "user.name", "Release test");
	writeFileSync(join(worktree, "release.txt"), "canonical\n", "utf8");
	git("-C", worktree, "add", "release.txt");
	git("-C", worktree, "commit", "-m", "canonical release commit");
	git("-C", worktree, "remote", "add", "origin", remote);
	git("-C", worktree, "push", "-u", "origin", "master");
	git("-C", worktree, "tag", "v0.3.0");
	git("-C", worktree, "checkout", "--detach", "v0.3.0");
	const script = join(root, "scripts", "verify-release-tag-authority.sh");
	const run = () => spawnSync("bash", [script], { cwd: worktree, encoding: "utf8" });
	if (run().status !== 0) fail("tag-authority self-test rejected a tag commit reachable from origin/master");
	git("-C", worktree, "checkout", "-b", "unmerged-release", "master");
	writeFileSync(join(worktree, "release.txt"), "unmerged\n", "utf8");
	git("-C", worktree, "commit", "-am", "unmerged release commit");
	git("-C", worktree, "tag", "v0.3.1");
	git("-C", worktree, "checkout", "--detach", "v0.3.1");
	if (run().status === 0) fail("tag-authority self-test accepted a tag commit outside origin/master");
}

function selfTest() {
	const workflow = yaml(".github/workflows/release-sign.yml");
	verifyIdentity(namedStep(workflow.jobs?.release?.steps ?? [], "Resolve version and require release signing identity").step.run);
	verifyTagAuthority();
	process.stdout.write("RELEASE_VERIFIER_SELF_TEST_OK\n");
}

if (process.argv[2] === "--self-test") {
	selfTest();
	process.exit(0);
}

if (!version || !semver.test(version)) fail(`expected an exact SemVer version, received ${JSON.stringify(version ?? "")}`);

const packageNames = new Set(publicReleasePackages.map(({ name }) => name));
if (publicReleasePackageCount !== 12 || packageNames.size !== 12 || runtimeClosurePackageNames.length !== 12) {
	fail("release package manifest must define exactly 12 unique packages and closure proofs");
}
for (const relative of [...publicReleasePackages.map(({ manifest }) => manifest), "apps/sample-b2b/package.json"]) {
	if (JSON.parse(read(relative)).version !== version) fail(`${relative} must be version ${version}`);
}
for (const { manifest } of publicReleasePackages) {
	const dependencies = JSON.parse(read(manifest)).dependencies ?? {};
	if (Object.keys(dependencies).some((name) => bundledRuntimePackages.includes(name))) fail(`${manifest} must not publish substitutable runtime packages`);
	if (Object.entries(dependencies).some(([name, range]) => /^(?:workspace:|link:|file:)/.test(String(range)) && !packageNames.has(name))) fail(`${manifest} has an unpublished local production dependency`);
}
const cli = JSON.parse(read("packages/clearance-cli/package.json"));
if (cli.name !== "@clearance/cli" || cli.bin?.clearance !== "./dist/index.js") fail("@clearance/cli must install the clearance binary from ./dist/index.js");
const rootPackage = JSON.parse(read("package.json"));
if (rootPackage.scripts?.["release:rehearse"] !== "bash scripts/rehearse-release-assembly.sh") {
	fail("root release:rehearse script must invoke the shared release assembly script");
}

const chart = yaml("deploy/helm/clearance/Chart.yaml");
const values = yaml("deploy/helm/clearance/values.yaml");
if (chart.version !== version || chart.appVersion !== version || values.image?.tag !== version || values.backup?.image?.tag !== version
	|| (values.console?.image?.tag && values.console.image.tag !== version)) fail("Helm chart and release image tags must match the release version");
if (exportedStringConst(read("packages/clearance-auth/src/create-auth.ts"), "CLEARANCE_AUTH_VERSION") !== version
	|| exportedStringConst(read("packages/management/src/store/snapshot.ts"), "CLEARANCE_RELEASE_VERSION") !== version
	|| healthVersion(read("packages/clearance-api/src/server.ts")) !== version) fail("runtime release constants must match the release version");

const workflow = yaml(".github/workflows/release-sign.yml");
const steps = workflow.jobs?.release?.steps;
if (!Array.isArray(steps)) fail("release workflow must define jobs.release.steps");
const names = steps.filter((step) => typeof step.name === "string").map((step) => step.name);
if (new Set(names).size !== names.length || steps.filter((step) => step.uses).some((step) => !/@[0-9a-f]{40}(?:\s|$)/.test(step.uses))) fail("release workflow step names and action pins must be unique and immutable");
const identity = namedStep(steps, "Resolve version and require release signing identity");
const clean = namedStep(steps, "Install and verify from clean source");
const rehearsal = namedStep(steps, "Rehearse release assembly");
const provisionNpm = namedStep(steps, "Provision integrity-pinned npm CLI");
const recovery = namedStep(steps, "Verify recovery npm packages before signing assets");
const staging = namedStep(steps, "Build and push staging container references");
const finalTags = namedStep(steps, "Create final release tags from verified digests");
const verifyContainerTags = namedStep(steps, "Verify both published container tags match the signed digests");
const publish = namedStep(steps, "Publish public npm packages with trusted provenance");
const anonymousInstall = namedStep(steps, "Prove anonymous public-registry install and imports");
const terraform = steps.map((step, index) => ({ step, index })).find(({ step }) => step.uses === "hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e");
if (!terraform || terraform.step.with?.terraform_version !== "1.5.7" || terraform.index >= clean.index || clean.index >= rehearsal.index
	|| rehearsal.index >= recovery.index || recovery.index >= staging.index || staging.index >= finalTags.index || finalTags.index >= publish.index
	|| rehearsal.step.run !== "pnpm release:rehearse -- \"$VERSION\""
	|| recovery.step.if !== "env.RECOVER_PUBLISHED_NPM == '1'" || publish.step.if !== "env.RECOVER_PUBLISHED_NPM != '1'") {
	fail("release workflow must retain pinned, ordered release gates and the exact shared rehearsal invocation");
}
if (provisionNpm.step.env?.NPM_CLI_VERSION !== "11.16.0"
	|| provisionNpm.step.env?.NPM_CLI_INTEGRITY !== "sha512-A74XL8OxmcegZDMWPkWb5bEQppg8HdYwW3rBD2sPoS4UQHVajfaxBkqyzLeJ3wR0kZ+5xoTjItxXaF7eIXUsyw=="
	|| !provisionNpm.step.run?.includes('test "$(node "$NPM_CLI_DIR/package/bin/npm-cli.js" --version)" = "$NPM_CLI_VERSION"')
	|| !provisionNpm.step.run?.includes('echo "CLEARANCE_NPM_CLI=$NPM_CLI_DIR/package/bin/npm-cli.js" >> "$GITHUB_ENV"')
	|| !recovery.step.run?.includes('node "$CLEARANCE_NPM_CLI" view')
	|| !recovery.step.run?.includes('node "$CLEARANCE_NPM_CLI" audit signatures')
	|| !publish.step.run?.includes('node "$CLEARANCE_NPM_CLI" publish')
	|| !publish.step.run?.includes('node "$CLEARANCE_NPM_CLI" view')
	|| !publish.step.run?.includes('node "$CLEARANCE_NPM_CLI" audit signatures')
	|| !anonymousInstall.step.run?.includes('node "$CLEARANCE_NPM_CLI" --userconfig')) {
	fail("release npm operations must use the integrity-pinned npm CLI explicitly");
}
if (!verifyContainerTags.step.run?.includes("requiredPlatforms")
	|| !verifyContainerTags.step.run?.includes('docker --config "$ANON_DOCKER_CONFIG" pull --platform "$platform" "${repository}@${platform_digest}"')
	|| verifyContainerTags.step.run?.includes('pull --platform linux/amd64 "${repository}@${expected}"')
	|| verifyContainerTags.step.run?.includes('pull --platform linux/arm64 "${repository}@${expected}"')) {
	fail("release container verification must anonymously pull distinct immutable platform manifests rather than rebinding one index digest");
}
verifyIdentity(identity.step.run);
const bundleSigning = namedStep(steps, "Sign package and container-digest bundle");
const bundleVerification = namedStep(steps, "Verify detached signature and asset manifest");
if (bundleSigning.step.env?.CLEARANCE_RELEASE_CERTIFICATE_IDENTITY !== "https://github.com/${{ github.workflow_ref }}"
	|| bundleSigning.step.env?.CLEARANCE_RELEASE_CERTIFICATE_OIDC_ISSUER !== "https://token.actions.githubusercontent.com"
	|| bundleSigning.step.env?.CLEARANCE_RELEASE_ALLOW_RECOVERY_IDENTITY !== "${{ env.RECOVER_PUBLISHED_NPM }}"
	|| bundleSigning.step.env?.CLEARANCE_RELEASE_SIGNING_KEY !== undefined
	|| bundleVerification.step.run?.includes("release-public.pem")
	|| !bundleVerification.step.run?.includes("scripts/verify-release-bundle.sh")) {
	fail("release bundle must use the canonical keyless Sigstore verifier rather than a sibling public key");
}

process.stdout.write(`RELEASE_VERSION_OK ${version}\n`);
