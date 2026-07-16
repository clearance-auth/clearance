#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const ts = createRequire(import.meta.url)("typescript");
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FORBIDDEN = ["migrateCredentialAuthorities","migrateLegacySessionCredentials","credentialAuthorityGeneration","assertNoLegacyCredentialReadersOrWriters","attachInternalCredentialAuthority","readInternalCredentialAuthority","withExclusiveMigrationLease","releaseRuntimeLease"];
const ATTACH = "attachInternalCredentialAuthority", READ = "readInternalCredentialAuthority", FORBIDDEN_SET = new Set(FORBIDDEN);
const PRIVATE = ["db/credential-authority-migration","db/session-credential-migration","internal/credential-authority"];
const SOURCE_ONLY = new Set(["dev-source","development","source"]), errors = [];
const ENV_BOUND = { "@clearance/runtime::./lynx": "requires Lynx runtime globals/macros", "@clearance/runtime::./test": "requires an active Vitest suite" };
const MAX_ID_DEPTH = 14, MAX_ID_NODES = 10000, MAX_AST_FILES = 256, MAX_AST_DEPTH = 64;
const FN_SKIP = new Set(["length","name","arguments","caller","prototype"]);
const fail = (m) => errors.push(m), sorted = (xs) => [...xs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
const rel = (p) => relative(ROOT, p).split(sep).join("/");
const isJs = (p) => /\.(?:mjs|cjs|js)$/.test(p) && !/\.d\.(?:mts|cts|ts)$/.test(p);
const isDecl = (p) => (/\.d\.(?:mts|cts|ts)$/.test(p) || /\.(?:mts|cts|ts)$/.test(p)) && !isJs(p);
const isFile = (p) => existsSync(p) && statSync(p).isFile();
const keySort = (a, b) => String(a).localeCompare(String(b));
const isSourceFile = (p) => /\.(?:mts|cts|ts)$/.test(p) && !/\.d\.(?:mts|cts|ts)$/.test(p);
const F = (n) => ({ k: "F", n }), S = () => ({ k: "S" }), Undef = () => ({ k: "S", undef: true }), U = (reason) => ({ k: "U", reason });
const I = (f, e) => ({ k: "I", f, e }), O = (els) => ({ k: "O", els }), N = (f) => ({ k: "N", f });
/** Structured record: exact own property/index slots + conservative spread/rest remainder. Immutable slots via shallow clones on write. */
const R = (props = null, idxs = null, rest = null) => ({ k: "R", props: props || Object.create(null), idxs: idxs || Object.create(null), rest });
const isUndefOrigin = (o) => !!(o && o.k === "S" && o.undef);
const cloneProps = (p) => Object.assign(Object.create(null), p || null);
const MISSING = null;
const hasOwn = (o, k) => !!o && Object.prototype.hasOwnProperty.call(o, k);
const hasMod = (node, kind) => !!node.modifiers?.some((m) => m.kind === kind);
const isExported = (node) => hasMod(node, ts.SyntaxKind.ExportKeyword);
const isDefaultExport = (node) => hasMod(node, ts.SyntaxKind.DefaultKeyword);
function scriptKindFor(file) {
	const f = file.toLowerCase();
	if (f.endsWith(".tsx")) return ts.ScriptKind.TSX;
	if (f.endsWith(".jsx")) return ts.ScriptKind.JSX;
	return /\.(?:mts|cts|ts)$/.test(f) ? ts.ScriptKind.TS : ts.ScriptKind.JS;
}
const parseSF = (file, text) => ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, scriptKindFor(file));
function listFiles(dir) {
	const out = []; if (!existsSync(dir)) return out; const stack = [dir];
	while (stack.length) { const cur = stack.pop();
		for (const e of readdirSync(cur, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
			const p = join(cur, e.name); if (e.isDirectory()) stack.push(p); else if (e.isFile()) out.push(p); } }
	return sorted(out);
}
function mask(s, maskStrings = false) {
	let r = "", st = "c";
	for (let i = 0; i < s.length; i++) {
		const c = s[i], n = s[i + 1];
		if (st === "l") { if (c === "\n") { st = "c"; r += c; } else r += " "; continue; }
		if (st === "b") { if (c === "*" && n === "/") { st = "c"; r += "  "; i++; } else r += c === "\n" ? "\n" : " "; continue; }
		if (st === "q" || st === "d" || st === "t") {
			if (c === "\\") { if (n !== undefined) { r += maskStrings ? "  " : c + n; i++; } else r += maskStrings ? " " : c; continue; }
			if ((st === "q" && c === "'") || (st === "d" && c === '"') || (st === "t" && c === "`")) { st = "c"; r += c; continue; }
			r += maskStrings ? (c === "\n" ? "\n" : " ") : c; continue;
		}
		if (c === "/" && n === "/") { st = "l"; r += "  "; i++; continue; }
		if (c === "/" && n === "*") { st = "b"; r += "  "; i++; continue; }
		if (c === "'") st = "q"; else if (c === '"') st = "d"; else if (c === "`") st = "t";
		r += c;
	}
	return r;
}
const stripComments = (s) => mask(s, false);
const kwInCode = (syntax, index, text) => { const k = /\b(?:import|export|require)\b/.exec(text); return !!k && syntax.slice(index + k.index, index + k.index + k[0].length) === k[0]; };
function specs(src) {
	const code = stripComments(src), syntax = mask(src, true), out = [];
	for (const re of [
		/(?:^|[;\n({])\s*(?:import|export)\s+(?:type\s+)?(?:[\w*{}\s,.$]*?\s+from\s+)?["']([^"']+)["']/g,
		/(?:^|[;\n({])\s*export\s+\*\s+as\s+[\w$]+\s+from\s+["']([^"']+)["']/g,
		/\bimport\s*\(\s*["']([^"']+)["']\s*\)/g, /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
	]) for (const m of code.matchAll(re)) if (kwInCode(syntax, m.index, m[0])) out.push(m[1]);
	return out;
}
function badSpec(sp) {
	if (!sp) return false;
	if (!sp.startsWith(".") && !sp.startsWith("/") && !sp.startsWith("file:"))
		return sp === "packages/runtime" || sp.startsWith("packages/runtime/") || (sp.startsWith("packages/") && sp.includes("/src"));
	return /(?:^|\/)src(?:\/|$|\?)|packages\/runtime|(?:^|\/)packages\/[^/]+\/src(?:\/|$)|(?:\.\.\/)+(?:runtime\/)?src\//.test(sp.replaceAll("\\", "/"));
}
function walkExports(node, key, conds, out, mode = "all") {
	if (node == null) return;
	if (typeof node === "string") { out.push({ key, conds: [...conds], target: node }); return; }
	if (Array.isArray(node)) { for (const x of node) walkExports(x, key, conds, out, mode); return; }
	for (const k of sorted(Object.keys(node))) { if (mode === "executable" && SOURCE_ONLY.has(k)) continue; walkExports(node[k], key, [...conds, k], out, mode); }
}
function exportTargets(pkg, mode = "all") {
	const out = [], ex = pkg.exports; if (ex == null) return out;
	if (typeof ex === "string" || Array.isArray(ex)) walkExports(ex, ".", [], out, mode);
	else for (const k of sorted(Object.keys(ex))) walkExports(ex[k], k, [], out, mode);
	return out;
}
const isTypes = (t, c) => c.includes("types") || /\.d\.(?:mts|cts|ts)$/.test(t);
const isJsTarget = (t, c) => !isTypes(t, c) && (/\.(?:mjs|cjs|js)$/i.test(t) || ["default","import","require","node","module","development","dev-source","source"].some((x) => c.includes(x)));
const isStaticScanTarget = (t, c) => !isTypes(t, c) && (isJsTarget(t, c) || isSourceFile(t) || /\.(?:mjs|cjs|js)$/i.test(t));
const resolveTarget = (dir, t) => resolve(dir, t.replace(/^\.\//, ""));
function hashedBase(name) {
	const segs = name.replace(/\.(?:mjs|cjs|js)$/i, "").split("-"); if (segs.length < 2) return false;
	const h = (s) => s.length >= 5 && (/[0-9_]/.test(s) || (/[A-Z]/.test(s) && /[a-z]/.test(s)));
	let n = 0; for (let i = segs.length - 1; i >= 1; i--) { if (h(segs[i])) n++; else break; } return n >= 1;
}
function canonicalJs(key, target) {
	const sub = key === "." || key === "" ? "" : key.replace(/^\.\//, ""), norm = target.replace(/^\.\//, "").split(sep).join("/"), ok = new Set();
	for (const ext of [".mjs",".js",".cjs"]) { if (!sub) ok.add(`dist/index${ext}`); else { ok.add(`dist/${sub}${ext}`); ok.add(`dist/${sub}/index${ext}`); } }
	return ok.has(norm) && !hashedBase(norm.split("/").pop());
}
function resolveCandidates(from, sp) {
	const base = resolve(from, sp);
	return [base, `${base}.mjs`, `${base}.js`, `${base}.cjs`, `${base}.mts`, `${base}.cts`, `${base}.ts`,
		join(base, "index.mjs"), join(base, "index.js"), join(base, "index.mts"), join(base, "index.cts"), join(base, "index.ts")];
}
const resolveMod = (from, sp) => { for (const c of resolveCandidates(from, sp)) if (isFile(c)) return c; return null; };
function rootJs(dir, pkg) {
	const t = exportTargets(pkg, "executable").find((e) => e.key === "." && isJsTarget(e.target, e.conds));
	return t ? resolveTarget(dir, t.target) : pkg.module ? resolveTarget(dir, pkg.module) : pkg.main ? resolveTarget(dir, pkg.main) : null;
}
function publicJs(dir, pkg) {
	const m = new Map();
	for (const e of exportTargets(pkg, "executable")) {
		if (!isJsTarget(e.target, e.conds)) continue;
		const a = resolveTarget(dir, e.target); m.set(`${e.key}::${rel(a)}`, { key: e.key, abs: a, target: e.target });
	}
	return sorted(m.keys()).map((k) => m.get(k));
}
function publicDecls(dir, pkg) {
	const m = new Map();
	for (const e of exportTargets(pkg, "all")) {
		if (!isTypes(e.target, e.conds) && !e.target.includes(".d.")) continue;
		m.set(rel(resolveTarget(dir, e.target)), resolveTarget(dir, e.target));
	}
	if (pkg.types) m.set(rel(resolveTarget(dir, pkg.types)), resolveTarget(dir, pkg.types));
	return sorted(m.keys()).map((k) => m.get(k));
}
function allConditionScanTargets(dir, pkg) {
	const m = new Map();
	for (const e of exportTargets(pkg, "all")) {
		if (!isStaticScanTarget(e.target, e.conds)) continue;
		const abs = resolveTarget(dir, e.target), k = rel(abs), sourceOnly = e.conds.some((c) => SOURCE_ONLY.has(c)) || isSourceFile(e.target);
		if (!m.has(k)) m.set(k, { key: e.key, abs, target: e.target, conds: e.conds, sourceOnly }); else if (sourceOnly) m.get(k).sourceOnly = true;
	}
	return sorted(m.keys()).map((k) => m.get(k));
}
function parseExportClause(clause) {
	const pairs = [];
	for (const p of clause.split(",")) {
		const t = p.trim().replace(/^type\s+/, ""); if (!t || t === "*") continue;
		const as = t.match(/^([\w$]+|\*)\s+as\s+([\w$]+)$/);
		if (as) pairs.push({ source: as[1], public: as[2] }); else if (/^[\w$]+$/.test(t)) pairs.push({ source: t, public: t });
	}
	return pairs;
}
function staticExportBindings(src) {
	const code = mask(src, true), names = new Set();
	for (const m of code.matchAll(/\bexport\s+(?:async\s+)?(?:function|class|const|let|var)\s+([\w$]+)/g)) names.add(m[1]);
	for (const m of code.matchAll(/\bexport\s*\{([^}]+)\}(?!\s*from\b)/g)) for (const p of parseExportClause(m[1])) { names.add(p.source); names.add(p.public); }
	for (const m of code.matchAll(/__exportAll\s*\(\s*\{([\s\S]*?)\}\s*\)/g)) for (const p of m[1].matchAll(/(?:^|[,{]\s*)([\w$]+)\s*:/g)) names.add(p[1]);
	for (const m of code.matchAll(/\bexport\s+default\b/g)) {
		let i = m.index + m[0].length; while (i < code.length && /\s/.test(code[i])) i++;
		const rest = code.slice(i), id = /^([\w$]+)/.exec(rest), named = /^(?:async\s+)?function\s+([\w$]+)/.exec(rest) || /^class\s+([\w$]+)/.exec(rest);
		if (named) names.add(named[1]); else if (id && !/^(?:async|function|class)$/.test(id[1])) names.add(id[1]);
	}
	return names;
}
function relativeReexports(src) {
	const code = stripComments(src), syntax = mask(src, true), edges = [];
	for (const m of code.matchAll(/\bexport\s+\*\s+(?:as\s+[\w$]+\s+)?from\s+["'](\.[^"']+)["']/g)) if (kwInCode(syntax, m.index, m[0])) edges.push({ kind: "star", spec: m[1] });
	for (const m of code.matchAll(/\bexport\s*\{([^}]+)\}\s*from\s+["'](\.[^"']+)["']/g)) if (kwInCode(syntax, m.index, m[0])) edges.push({ kind: "named", spec: m[2], pairs: parseExportClause(m[1]) });
	return edges;
}

const isFnLike = (n) => !!(n && (ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n)
	|| ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n)
	|| ts.isFunctionDeclaration(n) || ts.isClassExpression(n) || ts.isClassDeclaration(n)));
const unwrapExpr = (node) => {
	let n = node;
	while (n && (ts.isParenthesizedExpression(n) || ts.isAsExpression(n) || ts.isTypeAssertionExpression(n)
		|| (typeof ts.isSatisfiesExpression === "function" && ts.isSatisfiesExpression(n))
		|| (typeof ts.isNonNullExpression === "function" && ts.isNonNullExpression(n)))) n = n.expression;
	return n;
};
const originEq = (a, b) => {
	if (a === b) return true; if (!a || !b || a.k !== b.k) return false;
	if (a.k === "F") return a.n === b.n; if (a.k === "S") return !!a.undef === !!b.undef; if (a.k === "U") return a.reason === b.reason;
	if (a.k === "I") return a.f === b.f && a.e === b.e; if (a.k === "N") return a.f === b.f;
	if (a.k === "O") return a.els.length === b.els.length && a.els.every((e, i) => originEq(e, b.els[i]));
	if (a.k === "R") {
		const pk = (x) => Object.keys(x.props).sort(), ik = (x) => Object.keys(x.idxs).sort();
		const pa = pk(a), pb = pk(b); if (pa.length !== pb.length || pa.some((k, i) => k !== pb[i] || !originEq(a.props[k], b.props[k]))) return false;
		const ia = ik(a), ib = ik(b); if (ia.length !== ib.length || ia.some((k, i) => k !== ib[i] || !originEq(a.idxs[k], b.idxs[k]))) return false;
		return originEq(a.rest, b.rest) || (a.rest == null && b.rest == null);
	}
	return false;
};
const staticPropKey = (nameNode) => {
	if (!nameNode) return null;
	if (ts.isIdentifier(nameNode) || ts.isStringLiteral(nameNode) || ts.isNumericLiteral(nameNode)) return nameNode.text;
	if (ts.isComputedPropertyName(nameNode)) {
		const e = unwrapExpr(nameNode.expression);
		if (e && (ts.isStringLiteral(e) || ts.isNumericLiteral(e))) return e.text;
		if (e && e.kind === ts.SyntaxKind.TrueKeyword) return "true";
		if (e && e.kind === ts.SyntaxKind.FalseKeyword) return "false";
	}
	return null;
};
const projectProp = (origin, key) => {
	if (!origin || key == null) return MISSING;
	if (origin.k === "R") {
		if (hasOwn(origin.props, key)) return origin.props[key];
		if (origin.rest) return projectProp(origin.rest, key) ?? origin.rest;
		return MISSING;
	}
	if (origin.k === "N") return I(origin.f, key);
	if (origin.k === "O" || origin.k === "F" || origin.k === "U" || origin.k === "I") return origin;
	if (origin.k === "S") return MISSING;
	return origin;
};
const projectIndex = (origin, idx) => {
	const key = String(idx);
	if (!origin) return MISSING;
	if (origin.k === "R") {
		if (hasOwn(origin.idxs, key)) return origin.idxs[key];
		if (origin.rest) return projectIndex(origin.rest, idx) ?? origin.rest;
		return MISSING;
	}
	if (origin.k === "O" || origin.k === "F" || origin.k === "U" || origin.k === "I") return origin;
	if (origin.k === "S") return MISSING;
	return origin;
};
/** Object rest: unselected property slots + remainder (indexes dropped for object rest). */
const restObjectOrigin = (origin, usedKeys) => {
	if (!origin) return S();
	if (origin.k !== "R") return origin;
	const props = Object.create(null);
	for (const k of Object.keys(origin.props)) if (!usedKeys.has(k)) props[k] = origin.props[k];
	return R(props, null, origin.rest);
};
/** Array rest from index: remaining indexes + remainder. */
const restArrayOrigin = (origin, fromIdx) => {
	if (!origin) return S();
	if (origin.k !== "R") return origin;
	const idxs = Object.create(null); let j = 0;
	for (const k of Object.keys(origin.idxs).map(Number).sort((a, b) => a - b))
		if (k >= fromIdx) idxs[String(j++)] = origin.idxs[String(k)];
	return R(null, idxs, origin.rest);
};
const mergeRest = (a, b) => {
	if (!a) return b; if (!b) return a;
	if (a.k === "R" && b.k === "R") {
		const props = cloneProps(a.props), idxs = cloneProps(a.idxs);
		for (const k of Object.keys(b.props)) props[k] = hasOwn(props, k) ? O([props[k], b.props[k]]) : b.props[k];
		for (const k of Object.keys(b.idxs)) idxs[k] = hasOwn(idxs, k) ? O([idxs[k], b.idxs[k]]) : b.idxs[k];
		return R(props, idxs, mergeRest(a.rest, b.rest));
	}
	return O([a, b]);
};
const replacePropSlot = (prev, key, next) => {
	if (prev?.k === "R") { const props = cloneProps(prev.props); props[key] = next; return R(props, cloneProps(prev.idxs), prev.rest); }
	if (!prev || prev.k === "S") { const props = Object.create(null); props[key] = next; return R(props, null, null); }
	return mergeContainerOrigin(prev, next);
};
/** Unknown computed write: merge into remainder without erasing exact slots. */
const mergeUnknownWrite = (prev, next) => {
	if (prev?.k === "R") return R(cloneProps(prev.props), cloneProps(prev.idxs), mergeRest(prev.rest, next));
	return mergeContainerOrigin(prev, next);
};
const applyDefaultIfNeeded = (selected, defaultOrigin) => {
	if (selected === MISSING || isUndefOrigin(selected)) return defaultOrigin !== undefined ? defaultOrigin : (selected === MISSING ? U("missing binding") : selected);
	return selected;
};
/** Bind identifiers from a binding name / pattern into a lexical scope set. */
function bindNames(nameNode, scope) {
	if (!nameNode) return;
	if (ts.isIdentifier(nameNode)) { scope.add(nameNode.text); return; }
	if (ts.isObjectBindingPattern(nameNode) || ts.isArrayBindingPattern(nameNode)) {
		for (const el of nameNode.elements) {
			if (ts.isOmittedExpression(el)) continue;
			if (ts.isBindingElement(el)) bindNames(el.name, scope);
			else if (ts.isIdentifier(el)) scope.add(el.text);
		}
	}
}
const isLexicalVarFlags = (flags) => !!(flags & (ts.NodeFlags.Let | ts.NodeFlags.Const));
const isCallableExpr = (n) => { const x = unwrapExpr(n); return !!(x && (ts.isFunctionExpression(x) || ts.isArrowFunction(x))); };
const isUndefinedArg = (arg) => {
	const a = unwrapExpr(arg);
	return !!(a && (a.kind === ts.SyntaxKind.UndefinedKeyword || (ts.isIdentifier(a) && a.text === "undefined")));
};
/** Merge a write origin into a local container (member / destructuring mutation). Fail-closed: never drop known F. */
function mergeContainerOrigin(prev, next) {
	if (!prev) return next;
	if (prev.k === "R") return mergeUnknownWrite(prev, next);
	if (next?.k === "F") return O([next, prev]);
	if (prev.k === "F") return next?.k === "S" && !next.undef ? prev : O([prev, next]);
	if (prev.k === "O") {
		const hasF = prev.els.some((e) => e?.k === "F");
		if (next?.k === "S" && !next.undef && !hasF) return next;
		if (next?.k === "S" && !next.undef && hasF) return prev;
		return O([...prev.els, next]);
	}
	if (prev.k === "S" && next?.k === "S") return next;
	return O([prev, next]);
}
/** Function-scoped `var` names only (do not enter nested fn bodies; block fn/let/const handled in visit). */
function collectFnScopedNames(node, scope) {
	if (!node) return;
	if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
		|| ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node) || ts.isGetAccessorDeclaration(node)
		|| ts.isSetAccessorDeclaration(node) || ts.isClassExpression(node) || ts.isClassDeclaration(node)) return;
	if (ts.isVariableDeclarationList(node) && !isLexicalVarFlags(node.flags))
		for (const d of node.declarations) bindNames(d.name, scope);
	else ts.forEachChild(node, (c) => collectFnScopedNames(c, scope));
}
/** Free forbidden refs in a function body (strict exported call graphs only). Lexical scopes: params, function-local var/fn, block let/const/class, catch, classic/for-in/for-of; property keys non-binding. */
function forbiddenFreeInFn(fnNode, locals) {
	let found = null;
	const isNestedFn = (n) => n && n !== fnNode && (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n)
		|| ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n));
	const enterFn = (fn, outer) => {
		const scope = new Set(outer);
		for (const p of fn.parameters) bindNames(p.name, scope);
		if (fn.name && ts.isIdentifier(fn.name)) scope.add(fn.name.text);
		if (fn.body) collectFnScopedNames(fn.body, scope);
		if (fn.body) visit(fn.body, scope);
	};
	const visitLoop = (init, extraNodes, body, scope) => {
		const loop = new Set(scope);
		if (init && ts.isVariableDeclarationList(init)) {
			const lexical = isLexicalVarFlags(init.flags);
			if (lexical) for (const d of init.declarations) bindNames(d.name, loop);
			for (const d of init.declarations) {
				if (d.initializer) visit(d.initializer, lexical ? loop : scope);
			}
		} else if (init) visit(init, scope);
		for (const x of extraNodes) if (x) visit(x, loop);
		if (body) visit(body, loop);
	};
	const visit = (n, scope) => {
		if (!n || found) return;
		if (isNestedFn(n)) { enterFn(n, scope); return; }
		if (ts.isClassDeclaration(n) || ts.isClassExpression(n)) {
			const inner = new Set(scope);
			if (n.name && ts.isIdentifier(n.name)) inner.add(n.name.text);
			ts.forEachChild(n, (c) => visit(c, inner));
			return;
		}
		if (ts.isBlock(n)) {
			// Lexical block bindings cover the whole block (incl. TDZ before textual decl).
			const block = new Set(scope);
			for (const st of n.statements) {
				if (ts.isVariableStatement(st) && isLexicalVarFlags(st.declarationList.flags))
					for (const d of st.declarationList.declarations) bindNames(d.name, block);
				else if (ts.isClassDeclaration(st) && st.name) bindNames(st.name, block);
				else if (ts.isFunctionDeclaration(st) && st.name) bindNames(st.name, block);
			}
			for (const st of n.statements) {
				if (ts.isVariableStatement(st) && isLexicalVarFlags(st.declarationList.flags)) {
					for (const d of st.declarationList.declarations)
						if (d.initializer) visit(d.initializer, block);
					continue;
				}
				if (ts.isClassDeclaration(st)) { visit(st, block); continue; }
				if (ts.isFunctionDeclaration(st) && st.name) { enterFn(st, block); continue; }
				visit(st, block);
			}
			return;
		}
		if (ts.isCatchClause(n)) {
			const catchScope = new Set(scope);
			if (n.variableDeclaration) bindNames(n.variableDeclaration.name, catchScope);
			if (n.block) visit(n.block, catchScope);
			return;
		}
		if (ts.isForStatement(n)) { visitLoop(n.initializer, [n.condition, n.incrementor], n.statement, scope); return; }
		if (ts.isForInStatement(n) || ts.isForOfStatement(n)) {
			visit(n.expression, scope);
			visitLoop(n.initializer, [], n.statement, scope);
			return;
		}
		if (ts.isPropertyAccessExpression(n)) { visit(n.expression, scope); return; }
		if (ts.isMetaProperty(n)) return;
		if (ts.isObjectLiteralExpression(n)) {
			for (const p of n.properties) {
				if (ts.isPropertyAssignment(p)) {
					if (p.name && ts.isComputedPropertyName(p.name)) visit(p.name.expression, scope);
					visit(p.initializer, scope);
				} else if (ts.isShorthandPropertyAssignment(p)) visit(p.name, scope);
				else if (ts.isSpreadAssignment(p)) visit(p.expression, scope);
				else if (ts.isMethodDeclaration(p) || ts.isGetAccessorDeclaration(p) || ts.isSetAccessorDeclaration(p)) enterFn(p, scope);
			}
			return;
		}
		if (ts.isIdentifier(n)) {
			if (scope.has(n.text)) return;
			if (FORBIDDEN_SET.has(n.text)) { found = n.text; return; }
			if (locals.get(n.text)?.k === "F") found = locals.get(n.text).n;
			return;
		}
		n.forEachChild((c) => visit(c, scope));
	};
	const root = new Set();
	for (const p of fnNode.parameters) bindNames(p.name, root);
	if (fnNode.body) collectFnScopedNames(fnNode.body, root);
	if (fnNode.body) visit(fnNode.body, root);
	return found;
}
/** Bind a binding name/pattern against a selected RHS origin (exact slot projection; defaults only when missing/undefined). */
function bindPatternFromOrigin(nameNode, rhsOrigin, locals, opt, write) {
	if (!nameNode) return;
	if (ts.isIdentifier(nameNode)) { write(nameNode.text, rhsOrigin === MISSING ? U(`unresolved binding ${nameNode.text}`) : rhsOrigin); return; }
	if (ts.isObjectBindingPattern(nameNode)) {
		const used = new Set();
		for (const el of nameNode.elements) {
			if (ts.isOmittedExpression(el) || !ts.isBindingElement(el)) continue;
			if (el.dotDotDotToken) {
				const rest = restObjectOrigin(rhsOrigin, used);
				bindPatternFromOrigin(el.name, rest, locals, opt, write);
				continue;
			}
			const key = el.propertyName ? staticPropKey(el.propertyName) : (ts.isIdentifier(el.name) ? el.name.text : staticPropKey(el.name));
			if (key != null) used.add(key);
			let selected = key != null ? projectProp(rhsOrigin, key) : (rhsOrigin?.k === "R" ? MISSING : rhsOrigin);
			if (el.initializer) {
				const defO = exprOrigin(el.initializer, locals, opt);
				selected = applyDefaultIfNeeded(selected, defO);
			} else if (selected === MISSING) selected = U("missing binding");
			bindPatternFromOrigin(el.name, selected, locals, opt, write);
		}
		return;
	}
	if (ts.isArrayBindingPattern(nameNode)) {
		let i = 0;
		for (const el of nameNode.elements) {
			if (ts.isOmittedExpression(el)) { i++; continue; }
			if (!ts.isBindingElement(el)) continue;
			if (el.dotDotDotToken) {
				bindPatternFromOrigin(el.name, restArrayOrigin(rhsOrigin, i), locals, opt, write);
				continue;
			}
			let selected = projectIndex(rhsOrigin, i);
			if (el.initializer) {
				const defO = exprOrigin(el.initializer, locals, opt);
				selected = applyDefaultIfNeeded(selected, defO);
			} else if (selected === MISSING) selected = U("missing binding");
			bindPatternFromOrigin(el.name, selected, locals, opt, write);
			i++;
		}
	}
}
/** Evaluate known-call body: param binding + simple local decls/assigns + return origins (both strict and general). */
function evalKnownCall(callNode, callable, callerLocals, opt, seen) {
	// Caller env (callerLocals) evaluates argument/rest origins only; the callee frame is seeded from the callable's
	// own defining locals (its lexical scope at definition time), never from the caller's — otherwise a caller
	// parameter that happens to share a name with a module/outer forbidden binding would incorrectly shadow it
	// inside a callee that never itself declares that name.
	const fn = callable.node, definingLocals = callable.definingLocals;
	const bodyOpt = { ...opt, callSeen: seen, fnBodies: opt.fnBodies }, paramLocals = new Map(definingLocals);
	// Predeclare every parameter as local/TDZ before any default so self/later refs never resolve to module imports.
	for (const p of fn.parameters) {
		const names = new Set(); bindNames(p.name, names);
		for (const nm of names) paramLocals.set(nm, S());
	}
	let argI = 0;
	const args = callNode.arguments || [];
	for (const p of fn.parameters) {
		if (p.dotDotDotToken) {
			const idxs = Object.create(null); let j = 0;
			for (; argI < args.length; argI++) idxs[String(j++)] = exprOrigin(args[argI], callerLocals, bodyOpt);
			const restO = R(null, idxs, null), write = (nm, o) => paramLocals.set(nm, o);
			if (ts.isIdentifier(p.name)) paramLocals.set(p.name.text, restO);
			else bindPatternFromOrigin(p.name, restO, paramLocals, bodyOpt, write);
			continue;
		}
		const arg = args[argI], present = arg !== undefined;
		if (present) argI++;
		let origin;
		if (!present || isUndefinedArg(arg)) {
			if (p.initializer) origin = exprOrigin(p.initializer, paramLocals, bodyOpt);
			else origin = Undef();
		} else origin = exprOrigin(arg, callerLocals, bodyOpt);
		const write = (nm, o) => paramLocals.set(nm, o);
		if (ts.isIdentifier(p.name)) paramLocals.set(p.name.text, origin);
		else bindPatternFromOrigin(p.name, origin, paramLocals, bodyOpt, write);
	}
	// Strict free-ref scan remains fail-closed for control-flow the value model does not fully simulate.
	if (opt.strict) {
		const hit = forbiddenFreeInFn(fn, definingLocals);
		if (hit) return F(hit);
	}
	const locals = new Map(paramLocals), setL = (nm, o) => { locals.set(nm, o); };
	// Nested FunctionDeclaration hoisting registers into the shared fnBodies map so its call sites resolve as known
	// calls; save/restore on this frame's exit keeps a same-named outer/module callable from leaking the shadow.
	const savedFnBodies = opt.fnBodies ? new Map() : null;
	// Every call-frame mutation of the shared fnBodies map (nested FunctionDeclaration hoisting, callable var
	// declarations, callable/non-callable identifier assignments) routes through these so the prior entry is saved
	// before the first write and restored on frame exit — otherwise a call-frame-local callable mutation permanently
	// overwrites a same-named outer/module callable in the shared map.
	const saveFnBody = (name) => {
		if (!savedFnBodies.has(name)) savedFnBodies.set(name, opt.fnBodies.has(name) ? opt.fnBodies.get(name) : undefined);
	};
	const setFnBody = (name, node) => { if (!opt.fnBodies) return; saveFnBody(name); opt.fnBodies.set(name, { node, definingLocals: locals }); };
	const deleteFnBody = (name) => { if (!opt.fnBodies) return; saveFnBody(name); opt.fnBodies.delete(name); };
	const registerFnDecl = (name, node) => setFnBody(name, node);
	const evalAssignLeft = (left, origin) => {
		const L = unwrapExpr(left);
		if (!L) return;
		if (ts.isIdentifier(L)) { if (locals.has(L.text) || FORBIDDEN_SET.has(L.text)) setL(L.text, origin); return; }
		if (ts.isObjectLiteralExpression(L) || ts.isArrayLiteralExpression(L) || ts.isObjectBindingPattern(L) || ts.isArrayBindingPattern(L)) {
			// Destructuring assign inside callee: project slots.
			if (ts.isObjectLiteralExpression(L)) {
				const used = new Set();
				for (const p of L.properties) {
					if (ts.isShorthandPropertyAssignment(p)) { used.add(p.name.text); evalAssignLeft(p.name, projectProp(origin, p.name.text) ?? U("missing")); }
					else if (ts.isPropertyAssignment(p)) {
						const k = staticPropKey(p.name); if (k != null) used.add(k);
						evalAssignLeft(p.initializer, k != null ? (projectProp(origin, k) ?? U("missing")) : origin);
					} else if (ts.isSpreadAssignment(p)) evalAssignLeft(p.expression, restObjectOrigin(origin, used));
				}
				return;
			}
			if (ts.isArrayLiteralExpression(L)) {
				let i = 0;
				for (const el of L.elements) {
					if (ts.isOmittedExpression(el)) { i++; continue; }
					if (ts.isSpreadElement(el)) { evalAssignLeft(el.expression, restArrayOrigin(origin, i)); continue; }
					evalAssignLeft(el, projectIndex(origin, i) ?? U("missing")); i++;
				}
				return;
			}
			bindPatternFromOrigin(L, origin, locals, bodyOpt, setL);
			return;
		}
		if (ts.isPropertyAccessExpression(L) || ts.isElementAccessExpression(L)) {
			const base = unwrapExpr(L.expression);
			if (!ts.isIdentifier(base) || !locals.has(base.text)) return;
			const prev = locals.get(base.text);
			if (ts.isPropertyAccessExpression(L)) setL(base.text, replacePropSlot(prev, L.name.text, origin));
			else {
				const arg = unwrapExpr(L.argumentExpression), k = arg && (ts.isStringLiteral(arg) || ts.isNumericLiteral(arg)) ? arg.text : null;
				if (k != null) setL(base.text, replacePropSlot(prev, k, origin));
				else setL(base.text, mergeUnknownWrite(prev, origin));
			}
		}
	};
	// Block lexical frame: every nested block (depth > 0) restores its own let/const/class/FunctionDeclaration
	// shadows on exit, including on an early-return path, so a block-local shadow of an outer/module/param name
	// never leaks past the closing `}`. Only names this exact block lexically declares are snapshotted/restored;
	// `var` hoists and assignments to pre-existing bindings are untouched so they persist past the block.
	const collectBlockLexicalNames = (stmts, out) => {
		for (const st of stmts) {
			if (ts.isVariableStatement(st) && isLexicalVarFlags(st.declarationList.flags))
				for (const d of st.declarationList.declarations) bindNames(d.name, out);
			else if (ts.isClassDeclaration(st) && st.name) out.add(st.name.text);
			else if (ts.isFunctionDeclaration(st) && st.name) out.add(st.name.text);
		}
	};
	const snapshotSlot = (map, name) => (map && map.has(name) ? { has: true, v: map.get(name) } : { has: false, v: undefined });
	const restoreSlot = (map, name, snap) => { if (!map) return; if (snap.has) map.set(name, snap.v); else map.delete(name); };
	const captureState = () => ({ locals: new Map(locals), fnBodies: opt.fnBodies ? new Map(opt.fnBodies) : null });
	const applyState = (state) => {
		locals.clear(); for (const [k, v] of state.locals) locals.set(k, v);
		if (opt.fnBodies) { opt.fnBodies.clear(); for (const [k, v] of state.fnBodies || []) opt.fnBodies.set(k, v); }
	};
	const statesEqual = (a, b) => {
		if (a.locals.size !== b.locals.size) return false;
		for (const [k, v] of a.locals) if (!b.locals.has(k) || !originEq(v, b.locals.get(k))) return false;
		if (!!a.fnBodies !== !!b.fnBodies) return false;
		if (!a.fnBodies) return true;
		if (a.fnBodies.size !== b.fnBodies.size) return false;
		for (const [k, v] of a.fnBodies) {
			const other = b.fnBodies.get(k);
			if (!other || v.node !== other.node || v.definingLocals !== other.definingLocals) return false;
		}
		return true;
	};
	const runStmts = (stmts, depth) => {
		if (!stmts) return { returns: [], fallsThrough: true };
		if (depth > MAX_AST_DEPTH) return { returns: [U("AST statement depth bound exceeded")], fallsThrough: false };
		let savedLocals = null, savedCallables = null;
		if (depth > 0) {
			const blockNames = new Set(); collectBlockLexicalNames(stmts, blockNames);
			savedLocals = new Map(); savedCallables = opt.fnBodies ? new Map() : null;
			for (const nm of blockNames) {
				savedLocals.set(nm, snapshotSlot(locals, nm));
				if (savedCallables) savedCallables.set(nm, snapshotSlot(opt.fnBodies, nm));
			}
		}
		try {
			for (const st of stmts) {
				if (ts.isVariableStatement(st) && isLexicalVarFlags(st.declarationList.flags)) {
					for (const d of st.declarationList.declarations) {
						const names = new Set(); bindNames(d.name, names);
						for (const nm of names) setL(nm, S());
					}
				} else if (ts.isFunctionDeclaration(st) && st.name) {
					setL(st.name.text, FORBIDDEN_SET.has(st.name.text) ? F(st.name.text) : S());
					if (st.body) registerFnDecl(st.name.text, st);
				} else if (ts.isClassDeclaration(st) && st.name) setL(st.name.text, S());
			}
			const returns = [];
			let fallsThrough = true;
			for (const st of stmts) {
				if (!fallsThrough) break;
				if (ts.isVariableStatement(st)) {
					for (const d of st.declarationList.declarations) {
						const initO = d.initializer ? exprOrigin(d.initializer, locals, bodyOpt) : U("uninitialized");
						bindPatternFromOrigin(d.name, initO, locals, bodyOpt, setL);
						if (ts.isIdentifier(d.name) && opt.fnBodies) {
							if (d.initializer && isCallableExpr(d.initializer)) setFnBody(d.name.text, unwrapExpr(d.initializer));
							else deleteFnBody(d.name.text);
						}
					}
					continue;
				}
				if (ts.isExpressionStatement(st)) {
					const exp = unwrapExpr(st.expression);
					if (ts.isBinaryExpression(exp) && exp.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
						const o = exprOrigin(exp.right, locals, bodyOpt);
						evalAssignLeft(exp.left, o);
						const leftId = unwrapExpr(exp.left);
						if (ts.isIdentifier(leftId) && opt.fnBodies) {
							if (isCallableExpr(exp.right)) setFnBody(leftId.text, unwrapExpr(exp.right));
							else deleteFnBody(leftId.text);
						}
					}
					continue;
				}
				if (ts.isReturnStatement(st)) {
					returns.push(st.expression ? exprOrigin(st.expression, locals, bodyOpt) : Undef());
					fallsThrough = false;
					break;
				}
				if (ts.isBlock(st)) {
					const flow = runStmts(st.statements, depth + 1);
					returns.push(...flow.returns);
					fallsThrough = flow.fallsThrough;
					continue;
				}
				if (ts.isIfStatement(st)) {
					// Branch-flow boundary: the condition is never known statically, so both the then- and
					// else-path are live continuations. Each branch is evaluated from an identical pre-if
					// snapshot of locals/fnBodies (never from the other branch's mutated state), so a later
					// branch can never silently overwrite an earlier branch's write (reversed-order overwrite).
					// A branch that returns contributes its origin; a branch that falls through contributes its
					// resulting locals/fnBodies state. If every branch returns, the merged origins return
					// immediately. Otherwise: if exactly one branch's state continues, execution resumes with
					// it (missing else = the unchanged pre-if state); if several continue with identical
					// resulting state, execution resumes with that shared state; if they diverge and cannot be
					// safely merged, evaluation fails closed rather than guessing which branch "won".
					const preState = captureState();
					const runBranch = (branch) => {
						applyState(preState);
						const flow = !branch ? { returns: [], fallsThrough: true }
							: ts.isBlock(branch) ? runStmts(branch.statements, depth + 1) : runStmts([branch], depth);
						return { flow, state: flow.fallsThrough ? captureState() : null };
					};
					const thenR = runBranch(st.thenStatement), elseR = runBranch(st.elseStatement);
					returns.push(...thenR.flow.returns, ...elseR.flow.returns);
					const continuing = [thenR, elseR].filter((r) => r.flow.fallsThrough).map((r) => r.state);
					if (continuing.length === 0) { applyState(preState); fallsThrough = false; break; }
					if (continuing.length === 1) { applyState(continuing[0]); continue; }
					if (statesEqual(continuing[0], continuing[1])) { applyState(continuing[0]); continue; }
					applyState(preState);
					returns.push(U("AST conditional branch state bound exceeded"));
					fallsThrough = false;
					break;
				}
			}
			return { returns, fallsThrough };
		} finally {
			if (savedLocals) for (const [nm, snap] of savedLocals) restoreSlot(locals, nm, snap);
			if (savedCallables) for (const [nm, snap] of savedCallables) restoreSlot(opt.fnBodies, nm, snap);
		}
	};
	const body = fn.body;
	if (!body) return U("missing function body");
	if (!ts.isBlock(body)) return exprOrigin(body, locals, bodyOpt);
	// Function-scoped `var` names (incl. inside nested blocks/loops) hoist as clean/uninitialized before evaluation,
	// shadowing any outer/module forbidden alias of the same name (but not resetting an already-bound parameter).
	const paramNames = new Set(); for (const p of fn.parameters) bindNames(p.name, paramNames);
	const hoistedVars = new Set(); collectFnScopedNames(body, hoistedVars);
	for (const nm of hoistedVars) if (!paramNames.has(nm)) setL(nm, Undef());
	const flow = runStmts(body.statements, 0);
	if (savedFnBodies) for (const [nm, prev] of savedFnBodies) { if (prev === undefined) opt.fnBodies.delete(nm); else opt.fnBodies.set(nm, prev); }
	const returned = [...flow.returns];
	if (flow.fallsThrough) returned.push(Undef());
	return returned.length === 0 ? Undef() : returned.length === 1 ? returned[0] : O(returned);
}
function exprOrigin(node, locals, opt = {}) {
	const n0 = unwrapExpr(node);
	if (!n0) return U("missing expression");
	if (n0.kind === ts.SyntaxKind.UndefinedKeyword) return Undef();
	if (ts.isIdentifier(n0) && n0.text === "undefined" && !locals.has("undefined")) return Undef();
	if (ts.isIdentifier(n0)) {
		if (FORBIDDEN_SET.has(n0.text) && !locals.has(n0.text)) return F(n0.text);
		if (locals.has(n0.text)) return locals.get(n0.text);
		if (FORBIDDEN_SET.has(n0.text)) return F(n0.text);
		return U(`unresolved identifier ${n0.text}`);
	}
	if (ts.isObjectLiteralExpression(n0)) {
		const props = Object.create(null); let rest = null;
		for (const p of n0.properties) {
			if (ts.isPropertyAssignment(p)) {
				const k = staticPropKey(p.name), v = exprOrigin(p.initializer, locals, opt);
				if (k != null) props[k] = v; else rest = mergeRest(rest, v);
			} else if (ts.isShorthandPropertyAssignment(p)) props[p.name.text] = exprOrigin(p.name, locals, opt);
			else if (ts.isSpreadAssignment(p)) rest = mergeRest(rest, exprOrigin(p.expression, locals, opt));
			else rest = mergeRest(rest, U("complex object property"));
		}
		return R(props, null, rest);
	}
	if (ts.isFunctionExpression(n0) || ts.isArrowFunction(n0) || ts.isClassExpression(n0))
		return n0.name && FORBIDDEN_SET.has(n0.name.text) ? F(n0.name.text) : S();
	if (ts.isLiteralExpression(n0) || n0.kind === ts.SyntaxKind.TrueKeyword || n0.kind === ts.SyntaxKind.FalseKeyword
		|| n0.kind === ts.SyntaxKind.NullKeyword) return S();
	if (ts.isArrayLiteralExpression(n0)) {
		const idxs = Object.create(null); let rest = null, i = 0;
		for (const el of n0.elements) {
			if (ts.isOmittedExpression(el)) { i++; continue; }
			if (ts.isSpreadElement(el)) rest = mergeRest(rest, exprOrigin(el.expression, locals, opt));
			else { idxs[String(i)] = exprOrigin(el, locals, opt); i++; }
		}
		return R(null, idxs, rest);
	}
	// Namespace / structured member: project exact slot when known.
	if (ts.isPropertyAccessExpression(n0)) {
		const base = exprOrigin(n0.expression, locals, opt);
		if (base.k === "N") return I(base.f, n0.name.text);
		if (base.k === "R") { const p = projectProp(base, n0.name.text); return p === MISSING ? U(`missing property ${n0.name.text}`) : p; }
		return base;
	}
	if (ts.isElementAccessExpression(n0)) {
		const base = exprOrigin(n0.expression, locals, opt), arg = unwrapExpr(n0.argumentExpression), k = arg && (ts.isStringLiteral(arg) || ts.isNumericLiteral(arg)) ? arg.text : null;
		if (k != null) {
			if (base.k === "N") return I(base.f, k);
			if (base.k === "R") {
				const p = hasOwn(base.props, k) || !/^\d+$/.test(k) ? projectProp(base, k) : projectIndex(base, k);
				return p === MISSING ? U(`missing index ${k}`) : p;
			}
		}
		return base;
	}
	// Known calls: evaluate in both STRICT_AST and GENERAL_AST when the call itself is module-evaluated / export-reachable.
	if (ts.isCallExpression(n0) && opt.fnBodies) {
		const callee = unwrapExpr(n0.expression);
		if (ts.isIdentifier(callee)) {
			const seen = opt.callSeen || new Set(), key = callee.text;
			if (!seen.has(key) && seen.size < MAX_AST_DEPTH) {
				const callable = opt.fnBodies.get(key);
				if (callable) {
					seen.add(key);
					return evalKnownCall(n0, callable, locals, { ...opt, callSeen: seen }, seen);
				}
			}
		}
		if (opt.strict) return U("unresolvable expression");
	}
	// Export-value surface only: free identifiers / local aliases. Never enter function or class bodies.
	// Property names are not free bindings (obj.forbiddenName must not flag).
	let forb = null; const nested = [];
	const visit = (n) => {
		if (!n || forb) return;
		n = unwrapExpr(n);
		if (!n) return;
		if (isFnLike(n)) {
			if (n.name && ts.isIdentifier(n.name) && FORBIDDEN_SET.has(n.name.text)) forb = n.name.text;
			return;
		}
		if (ts.isPropertyAccessExpression(n)) {
			const base = exprOrigin(n.expression, locals, opt);
			if (base.k === "N") { nested.push(I(base.f, n.name.text)); return; }
			if (base.k === "R") { const p = projectProp(base, n.name.text); if (p && p !== MISSING) nested.push(p); return; }
			if (base.k === "F") { forb = base.n; return; }
			if (base.k === "I" || base.k === "O" || base.k === "U" || base.k === "N") nested.push(base);
			return;
		}
		if (ts.isMetaProperty(n)) { visit(n.expression); return; }
		if (ts.isElementAccessExpression(n)) {
			const base = exprOrigin(n.expression, locals, opt), arg = unwrapExpr(n.argumentExpression), k = arg && (ts.isStringLiteral(arg) || ts.isNumericLiteral(arg)) ? arg.text : null;
			if (k != null && base.k === "R") { const p = projectProp(base, k) !== MISSING ? projectProp(base, k) : projectIndex(base, k); if (p && p !== MISSING) nested.push(p); return; }
			visit(n.expression); visit(n.argumentExpression); return;
		}
		if (ts.isIdentifier(n)) {
			if (FORBIDDEN_SET.has(n.text) && !locals.has(n.text)) { forb = n.text; return; }
			if (locals.has(n.text)) {
				const o = locals.get(n.text);
				if (o.k === "F") forb = o.n;
				else if (o.k === "I" || o.k === "O" || o.k === "U" || o.k === "N" || o.k === "R") nested.push(o);
			} else if (FORBIDDEN_SET.has(n.text)) forb = n.text;
			return;
		}
		n.forEachChild(visit);
	};
	visit(n0);
	if (forb) return F(forb);
	if (nested.length) return nested.length === 1 ? nested[0] : O(nested);
	return U("unresolvable expression");
}
/** Export-reachability AST resolver. Roots: each named export binding and the default export only. Traces: initializers, local aliases, relative import/reexport/star origins. Modes: strictUnresolved = env-bound static only (unknown default/object/expression fail-closed); general (strictUnresolved=false) = forbidden aliases, missing relative reexports, boundary escape only. */
function deriveExportNamespace(entry, readSrc, resolveRel, boundary = null, options = {}) {
	const strictUnresolved = options.strictUnresolved === true, failBareStar = options.failBareStar === true, errs = [], forb = new Set(), cache = new Map(); let filesVisited = 0;
	const noteForb = (n) => { if (FORBIDDEN_SET.has(n)) forb.add(n); }, emptyMod = () => ({ exportMap: new Map(), defaultOrigin: null }), markName = (n, o) => (FORBIDDEN_SET.has(n) ? F(n) : o);
	const bind = (name, origin, locals, exportMap, exported) => {
		locals.set(name, origin);
		if (exported) exportMap.set(name, markName(name, origin));
	};
	function resolveRelFile(from, sp) {
		if (!sp.startsWith(".")) return { err: `bare module ${JSON.stringify(sp)}` };
		const r = resolveRel(dirname(from), sp);
		if (!r) return { err: `unresolved relative reexport ${JSON.stringify(sp)}` };
		if (boundary && relative(boundary, r).startsWith("..")) return { err: `escaped package boundary ${JSON.stringify(sp)}` };
		return { file: r };
	}
	function pushUnresolved(reason, _ctx) {
		const r = reason || "unresolved binding flow";
		// Cycles are fixed-point empty results, never independent blockers.
		if (/cycle/i.test(r)) return;
		// Structural issues always fail (missing relative, boundary escape, bounds, bare star).
		// Do not treat U('bare module namespace') as structural — general mode keeps it opaque.
		if (/unresolved relative reexport|escaped package|missing module|bound exceeded|bare star/i.test(r)) {
			errs.push(r); return;
		}
		if (!strictUnresolved) return;
		// Strict env-bound: fail closed on unknown named/default/object/call expressions and unresolved bindings.
		errs.push(r);
	}
	function collectBad(origin, depth, seen, ctx = "export") {
		if (!origin || depth > MAX_AST_DEPTH) { if (depth > MAX_AST_DEPTH) errs.push("AST binding depth bound exceeded"); return; }
		if (origin.k === "F") { forb.add(origin.n); return; }
		if (origin.k === "S") return;
		if (origin.k === "U") { pushUnresolved(origin.reason, ctx); return; }
		if (origin.k === "O") { for (const el of origin.els) collectBad(el, depth + 1, seen, "object"); return; }
		if (origin.k === "R") {
			for (const k of Object.keys(origin.props)) collectBad(origin.props[k], depth + 1, seen, "object");
			for (const k of Object.keys(origin.idxs)) collectBad(origin.idxs[k], depth + 1, seen, "object");
			if (origin.rest) collectBad(origin.rest, depth + 1, seen, "object");
			return;
		}
		if (origin.k === "N") {
			// Whole namespace object selected: conservatively all named exports + default (ESM namespace semantics).
			const key = `N::${origin.f}`;
			if (seen.has(key)) return;
			seen.add(key);
			const mod = analyze(origin.f, depth + 1);
			for (const o of mod.exportMap.values()) collectBad(o, depth + 1, seen, "export");
			if (mod.defaultOrigin) collectBad(mod.defaultOrigin, depth + 1, seen, "default");
			return;
		}
		if (origin.k === "I") {
			const key = `${origin.f}::${origin.e}`;
			// Benign binding cycle: visited-empty fixed point (no error). Forbidden origins still fail via F on other paths.
			if (seen.has(key)) return;
			seen.add(key);
			const mod = analyze(origin.f, depth + 1);
			if (origin.e === "default") {
				if (mod.defaultOrigin) collectBad(mod.defaultOrigin, depth + 1, seen, "default");
				else pushUnresolved(`unresolved default export binding from ${origin.f}`, "default");
				return;
			}
			if (mod.exportMap.has(origin.e)) collectBad(mod.exportMap.get(origin.e), depth + 1, seen, "export");
			else pushUnresolved(`unresolved export binding ${origin.e} from ${origin.f}`, "export");
		}
	}
	function analyze(file, depth = 0) {
		if (depth > MAX_AST_DEPTH) { errs.push(`AST module depth bound exceeded at ${file}`); return emptyMod(); }
		if (cache.has(file)) {
			const hit = cache.get(file);
			// In-progress module: benign cycle; return empty fixed-point (do not report cycle as fatal).
			if (hit === null) return emptyMod();
			return hit;
		}
		if (++filesVisited > MAX_AST_FILES) { errs.push("AST file bound exceeded"); return emptyMod(); }
		cache.set(file, null);
		const src = readSrc(file);
		if (src == null) { errs.push(`missing module ${file}`); const e = emptyMod(); cache.set(file, e); return e; }
		const sf = parseSF(file, src), locals = new Map(), exportMap = new Map(), fnBodies = new Map(), originOpt = () => ({ strict: strictUnresolved, fnBodies });
		let defaultOrigin = null; const starFiles = [];
		const addDecl = (stmt) => {
			// Function/class bodies are never export-value-scanned in general mode; only the binding name identity matters.
			if (!(ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt))) return;
			const o = stmt.name && FORBIDDEN_SET.has(stmt.name.text) ? F(stmt.name.text) : S();
			if (stmt.name) {
				bind(stmt.name.text, o, locals, exportMap, isExported(stmt) && !isDefaultExport(stmt));
				if (ts.isFunctionDeclaration(stmt) && stmt.body) fnBodies.set(stmt.name.text, { node: stmt, definingLocals: locals });
			}
			if (isExported(stmt) && isDefaultExport(stmt)) defaultOrigin = o;
		};
		for (const stmt of sf.statements) {
			if (!ts.isImportDeclaration(stmt) || !stmt.importClause || !ts.isStringLiteral(stmt.moduleSpecifier) || stmt.importClause.isTypeOnly) continue;
			const sp = stmt.moduleSpecifier.text, clause = stmt.importClause, relR = sp.startsWith(".") ? resolveRelFile(file, sp) : null;
			// Imports alone never fail; only export-reachable use of the local binding does.
			if (clause.name) locals.set(clause.name.text, relR?.file ? I(relR.file, "default") : (relR?.err ? U(relR.err) : S()));
			// import * as ns: relative → N(file); bare package namespace is unknown (not blanket-safe).
			if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings))
				locals.set(clause.namedBindings.name.text, relR?.file ? N(relR.file) : (relR?.err ? U(relR.err) : U("bare module namespace")));
			else if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
				for (const el of clause.namedBindings.elements) {
					if (el.isTypeOnly) continue;
					const imported = (el.propertyName ?? el.name).text, local = el.name.text;
					if (FORBIDDEN_SET.has(imported)) { locals.set(local, F(imported)); continue; }
					// Safe bare named imports (e.g. lynx capitalizeFirstLetter) stay S; relative stay I.
					if (!sp.startsWith(".")) { locals.set(local, S()); continue; }
					locals.set(local, relR?.file ? I(relR.file, imported) : U(relR?.err || `unresolved relative reexport ${JSON.stringify(sp)}`));
				}
			}
		}
		// Hoisted function/class bindings (and fnBodies) before source-order evaluation.
		for (const stmt of sf.statements) addDecl(stmt);
		// Top-level `var` hoisting: predeclare identifier and binding-pattern names before source-order eval.
		for (const stmt of sf.statements) {
			if (!ts.isVariableStatement(stmt) || isLexicalVarFlags(stmt.declarationList.flags)) continue;
			for (const d of stmt.declarationList.declarations) {
				const names = new Set(); bindNames(d.name, names);
				for (const nm of names) if (!locals.has(nm)) locals.set(nm, U(`unresolved binding ${nm}`));
			}
		}
		// Live named roots + live `export { x as default }` finalize after evaluation.
		// `export default expr` is always an expression snapshot at that statement (not a live binding).
		const liveExports = [], liveDefaultLocals = [];
		const setLocal = (name, origin, callable) => {
			locals.set(name, origin);
			if (exportMap.has(name)) exportMap.set(name, markName(name, origin));
			if (callable) fnBodies.set(name, { node: callable, definingLocals: locals });
			else fnBodies.delete(name);
		};
		const bindDeclName = (nameNode, origin, initExpr, exported) => {
			if (ts.isIdentifier(nameNode)) {
				const call = initExpr && isCallableExpr(initExpr) ? unwrapExpr(initExpr) : null;
				bind(nameNode.text, origin, locals, exportMap, exported);
				if (call) fnBodies.set(nameNode.text, { node: call, definingLocals: locals }); else fnBodies.delete(nameNode.text);
				return;
			}
			if (ts.isObjectBindingPattern(nameNode) || ts.isArrayBindingPattern(nameNode)) {
				const write = (nm, o) => bind(nm, o, locals, exportMap, exported);
				bindPatternFromOrigin(nameNode, origin, locals, originOpt(), write);
				return;
			}
			if (exported) errs.push("unresolvable export binding pattern");
		};
		const writeAssignTarget = (left, origin, callable) => {
			const L = unwrapExpr(left);
			if (!L) return;
			if (ts.isIdentifier(L)) {
				if (!locals.has(L.text) && !FORBIDDEN_SET.has(L.text)) return;
				setLocal(L.text, origin, callable);
				return;
			}
			if (ts.isObjectBindingPattern(L) || ts.isArrayBindingPattern(L)) {
				const write = (nm, o) => { if (locals.has(nm) || FORBIDDEN_SET.has(nm)) setLocal(nm, o, null); };
				bindPatternFromOrigin(L, origin, locals, originOpt(), write);
				return;
			}
			if (ts.isObjectLiteralExpression(L)) {
				const used = new Set();
				for (const p of L.properties) {
					if (ts.isShorthandPropertyAssignment(p)) {
						used.add(p.name.text);
						const sel = projectProp(origin, p.name.text);
						writeAssignTarget(p.name, sel === MISSING ? U("missing") : sel, null);
					} else if (ts.isPropertyAssignment(p)) {
						const k = staticPropKey(p.name); if (k != null) used.add(k);
						const sel = k != null ? projectProp(origin, k) : origin;
						writeAssignTarget(p.initializer, sel === MISSING ? U("missing") : sel, null);
					} else if (ts.isSpreadAssignment(p)) writeAssignTarget(p.expression, restObjectOrigin(origin, used), null);
					else if (origin?.k === "F") errs.push("unresolvable assignment pattern");
				}
				return;
			}
			if (ts.isArrayLiteralExpression(L)) {
				let i = 0;
				for (const el of L.elements) {
					if (ts.isOmittedExpression(el)) { i++; continue; }
					if (ts.isSpreadElement(el)) { writeAssignTarget(el.expression, restArrayOrigin(origin, i), null); continue; }
					const sel = projectIndex(origin, i);
					writeAssignTarget(el, sel === MISSING ? U("missing") : sel, null);
					i++;
				}
				return;
			}
			if (ts.isPropertyAccessExpression(L) || ts.isElementAccessExpression(L)) {
				const base = unwrapExpr(L.expression);
				if (ts.isIdentifier(base) && locals.has(base.text)) {
					const prev = locals.get(base.text);
					let next = prev;
					if (ts.isPropertyAccessExpression(L)) next = replacePropSlot(prev, L.name.text, origin);
					else {
						const arg = unwrapExpr(L.argumentExpression), k = arg && (ts.isStringLiteral(arg) || ts.isNumericLiteral(arg)) ? arg.text : null;
						if (k != null) next = replacePropSlot(prev, k, origin);
						else next = mergeUnknownWrite(prev, origin);
					}
					setLocal(base.text, next, null);
				} else if (origin?.k === "F") {
					// Untrackable member target: fail closed so forbidden writes cannot stay silent.
					errs.push("unresolvable member assignment");
				}
			}
		};
		// Right-associative assignment: evaluate nested `a = b = expr`, update every target in order.
		const evalAssign = (left, right) => {
			const R = unwrapExpr(right);
			if (R && ts.isBinaryExpression(R) && R.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
				const nested = evalAssign(R.left, R.right);
				writeAssignTarget(left, nested, null);
				return nested;
			}
			const origin = exprOrigin(right, locals, originOpt()), call = isCallableExpr(right) ? unwrapExpr(right) : null;
			writeAssignTarget(left, origin, call);
			return origin;
		};
		const bindVarDecl = (d, exported, isVar) => {
			if (d.initializer) {
				// Snapshot initializer origin at declaration time (export const bag = { a } freezes a now).
				bindDeclName(d.name, exprOrigin(d.initializer, locals, originOpt()), d.initializer, exported);
				return;
			}
			// Initializer-less `var` never resets a value assigned earlier (hoisted binding retained).
			if (isVar) {
				const names = new Set(); bindNames(d.name, names);
				for (const nm of names) {
					if (!locals.has(nm)) locals.set(nm, U(`unresolved binding ${nm}`));
					if (exported) exportMap.set(nm, markName(nm, locals.get(nm)));
				}
				return;
			}
			bindDeclName(d.name, U(`unresolved binding`), null, exported);
		};
		// Source-order: top-level decls and `=` assigns (incl. patterns / member / nested).
		for (const stmt of sf.statements) {
			if (ts.isVariableStatement(stmt)) {
				const exported = isExported(stmt), isVar = !isLexicalVarFlags(stmt.declarationList.flags);
				for (const d of stmt.declarationList.declarations) bindVarDecl(d, exported, isVar);
				continue;
			}
			if (ts.isExpressionStatement(stmt)) {
				const exp = unwrapExpr(stmt.expression);
				if (!ts.isBinaryExpression(exp) || exp.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
				evalAssign(exp.left, exp.right);
				continue;
			}
			if (ts.isExportAssignment(stmt) && !stmt.isExportEquals) {
				// `export default expr` — expression snapshot at this statement (not live).
				defaultOrigin = exprOrigin(stmt.expression, locals, originOpt());
				continue;
			}
			if (!ts.isExportDeclaration(stmt) || stmt.isTypeOnly) continue;
			const spNode = stmt.moduleSpecifier;
			if (spNode && ts.isStringLiteral(spNode)) {
				const sp = spNode.text;
				if (stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
					// Dependency map: origin annotation only (markName/F/I). Never noteForb here.
					for (const el of stmt.exportClause.elements) {
						if (el.isTypeOnly) continue;
						const srcName = (el.propertyName ?? el.name).text, pub = el.name.text;
						let origin = S();
						if (FORBIDDEN_SET.has(srcName)) origin = F(srcName);
						else if (sp.startsWith(".")) { const r = resolveRelFile(file, sp); origin = r.file ? I(r.file, srcName) : U(r.err); }
						exportMap.set(pub, markName(pub, origin));
					}
				} else if (stmt.exportClause && ts.isNamespaceExport(stmt.exportClause)) {
					// export * as ns: local O origin of target named exports (+ default as ns.default). No noteForb/collectBad.
					const nsName = stmt.exportClause.name.text;
					if (!sp.startsWith(".")) { exportMap.set(nsName, S()); if (failBareStar) errs.push(`bare star reexport ${JSON.stringify(sp)}`); }
					else { const r = resolveRelFile(file, sp); if (r.file) starFiles.push({ file: r.file, asNs: true, nsName }); else { errs.push(r.err); exportMap.set(nsName, U(r.err)); } }
				} else if (!stmt.exportClause) {
					if (!sp.startsWith(".")) { if (failBareStar) errs.push(`bare star reexport ${JSON.stringify(sp)}`); }
					else { const r = resolveRelFile(file, sp); if (r.file) starFiles.push({ file: r.file, asNs: false }); else errs.push(r.err); }
				}
			} else if (stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
				// Local reexport: live binding — resolve after complete top-level evaluation.
				// `export { a as default }` is live/final; plain `export default a` is not.
				for (const el of stmt.exportClause.elements) {
					if (el.isTypeOnly) continue;
					const localName = (el.propertyName ?? el.name).text, pub = el.name.text;
					if (pub === "default") liveDefaultLocals.push(localName);
					else liveExports.push({ localName, pub });
				}
			}
		}
		// Finalize live named / export-as-default roots from final binding state (ESM live bindings).
		for (const { localName, pub } of liveExports) {
			const origin = locals.has(localName) ? locals.get(localName)
				: FORBIDDEN_SET.has(localName) ? F(localName) : U(`unresolved export binding ${localName}`);
			exportMap.set(pub, markName(pub, origin));
		}
		if (liveDefaultLocals.length) {
			const id = liveDefaultLocals[liveDefaultLocals.length - 1];
			defaultOrigin = locals.has(id) ? locals.get(id) : FORBIDDEN_SET.has(id) ? F(id) : U(`unresolved export binding ${id}`);
		}
		// Star/namespace merges build exportMap only. No noteForb/collectBad until root collection.
		for (const star of starFiles) {
			const sub = analyze(star.file, depth + 1);
			if (star.asNs) {
				// ESM module namespace: all named exports + default property when present.
				const els = [...sub.exportMap.values()];
				if (sub.defaultOrigin) els.push(sub.defaultOrigin);
				exportMap.set(star.nsName, markName(star.nsName, O(els)));
			} else for (const [n, o] of sub.exportMap) if (!exportMap.has(n)) exportMap.set(n, o);
		}
		for (const m of src.matchAll(/__exportAll\s*\(\s*\{([\s\S]*?)\}\s*\)/g))
			for (const p of m[1].matchAll(/(?:^|[,{]\s*)([\w$]+)\s*:/g)) { const n = p[1]; exportMap.set(n, markName(n, FORBIDDEN_SET.has(n) ? F(n) : S())); }
		const result = { exportMap, defaultOrigin }; cache.set(file, result); return result;
	}
	const root = analyze(entry, 0), names = new Set(root.exportMap.keys());
	// Final findings only here: root named/default exports and their reachable origins update forb.
	// Dependency modules may carry F origins; unselected ones stay invisible.
	for (const [n, o] of root.exportMap) { noteForb(n); collectBad(o, 0, new Set(), "named-value"); }
	if (root.defaultOrigin) collectBad(root.defaultOrigin, 0, new Set(), "default");
	const bad = FORBIDDEN.filter((n) => forb.has(n) || names.has(n)), errors = [...new Set(errs)];
	return { ok: errors.length === 0 && bad.length === 0, names, errors, bad, namespaceCount: names.size, mode: strictUnresolved ? "strict" : "general" };
}
function memResolve(modules, from, sp) { for (const c of resolveCandidates(from, sp)) if (modules.has(c)) return c; return null; }
const STRICT_AST = { strictUnresolved: true, failBareStar: true };
const GENERAL_AST = { strictUnresolved: false, failBareStar: false };
const deriveMemory = (modules, entry, options = STRICT_AST) =>
	deriveExportNamespace(entry, (f) => (modules.has(f) ? modules.get(f) : null), (from, sp) => memResolve(modules, from, sp), null, options);
const deriveFS = (entry, boundary = null, options = GENERAL_AST) =>
	deriveExportNamespace(entry, (f) => (isFile(f) ? readFileSync(f, "utf8") : null), (from, sp) => resolveMod(from, sp), boundary, options);
function hasForbiddenExport(file, boundary) {
	if (!isFile(file)) return { forbidden: FORBIDDEN.slice(), unresolved: [], errors: ["missing module"] };
	// General ALL/source and public static surface: export-reachability only (not env-bound fail-closed).
	const d = deriveFS(file, boundary, GENERAL_AST);
	const unresolved = d.errors.flatMap((e) => { const m = /unresolved relative reexport ("[^"]+")/.exec(e); return m ? [{ file, spec: JSON.parse(m[1]) }] : []; });
	return { forbidden: d.bad, unresolved, errors: d.errors };
}
const forbiddenInNamespace = (ns) => FORBIDDEN.filter((n) => n in ns || Object.hasOwn(ns, n));
/** new WeakMap/Map (optional ()), Object.create(null), or {}. */
function isStoreInitExpr(expr) {
	const n = unwrapExpr(expr); if (!n) return false;
	if (ts.isNewExpression(n)) { const c = unwrapExpr(n.expression); return ts.isIdentifier(c) && (c.text === "WeakMap" || c.text === "Map") && (!n.arguments || n.arguments.length === 0); }
	if (ts.isCallExpression(n)) {
		const c = unwrapExpr(n.expression), a0 = n.arguments?.[0] && unwrapExpr(n.arguments[0]);
		return ts.isPropertyAccessExpression(c) && ts.isIdentifier(c.expression) && c.expression.text === "Object" && c.name.text === "create" && a0?.kind === ts.SyntaxKind.NullKeyword;
	}
	return ts.isObjectLiteralExpression(n) && n.properties.length === 0;
}
/** Full-AST store discovery with lexical declaration identities. Same spelling in disjoint scopes is distinct; shadowing does not pair protocols incorrectly. */
function buildScopeModel(sf) {
	let nextId = 1;
	const stores = []; // { id, name, index }
	const fns = []; // { name, fn, resolveStore(name)->id|null }
	const declareIn = (scope, name, node) => {
		const id = nextId++;
		scope.bindings.set(name, { id, name, node });
		return id;
	};
	const resolveName = (scope, name) => {
		for (let s = scope; s; s = s.parent) if (s.bindings.has(name)) return s.bindings.get(name);
		return null;
	};
	const markStore = (binding, index) => {
		if (!binding || binding.store) return;
		binding.store = true;
		stores.push({ id: binding.id, name: binding.name, index });
	};
	const visitFn = (fn, parentScope, name) => {
		const scope = { parent: parentScope, bindings: new Map() };
		for (const p of fn.parameters) {
			const names = new Set(); bindNames(p.name, names);
			for (const nm of names) declareIn(scope, nm, p);
		}
		if (fn.name && ts.isIdentifier(fn.name)) declareIn(scope, fn.name.text, fn);
		if (fn.body) {
			if (ts.isBlock(fn.body)) visitBlock(fn.body, scope);
			else visitExpr(fn.body, scope);
		}
		const resolveStore = (nm) => { const b = resolveName(scope, nm); return b && b.store ? b.id : null; };
		if (name) fns.push({ name, fn, resolveStore, scope });
		else if (fn.name && ts.isIdentifier(fn.name)) fns.push({ name: fn.name.text, fn, resolveStore, scope });
	};
	const visitExpr = (n, scope) => {
		if (!n) return;
		if (ts.isFunctionExpression(n) || ts.isArrowFunction(n)) { visitFn(n, scope, null); return; }
		if (ts.isClassExpression(n)) {
			const inner = { parent: scope, bindings: new Map() };
			if (n.name) declareIn(inner, n.name.text, n);
			ts.forEachChild(n, (c) => visitNode(c, inner));
			return;
		}
		n.forEachChild((c) => visitNode(c, scope));
	};
	const visitVarDecl = (d, scope, lexical) => {
		if (!ts.isIdentifier(d.name)) {
			const names = new Set(); bindNames(d.name, names);
			for (const nm of names) declareIn(scope, nm, d);
			if (d.initializer) visitExpr(d.initializer, scope);
			return;
		}
		const b = lexical || !scope.bindings.has(d.name.text)
			? (() => { const id = declareIn(scope, d.name.text, d); return scope.bindings.get(d.name.text); })()
			: scope.bindings.get(d.name.text) || (() => { declareIn(scope, d.name.text, d); return scope.bindings.get(d.name.text); })();
		// For var re-decl, reuse binding identity when already present in function scope.
		if (!lexical && scope.bindings.has(d.name.text)) { /* keep */ }
		else if (!scope.bindings.has(d.name.text)) declareIn(scope, d.name.text, d);
		const binding = resolveName(scope, d.name.text);
		if (d.initializer) {
			if (isStoreInitExpr(d.initializer)) markStore(binding, d.name.getStart(sf));
			visitExpr(d.initializer, scope);
		}
	};
	const visitBlock = (block, parentScope) => {
		const scope = { parent: parentScope, bindings: new Map() };
		// Predeclare block lexical bindings (TDZ) for let/const/class/function.
		for (const st of block.statements) {
			if (ts.isVariableStatement(st) && isLexicalVarFlags(st.declarationList.flags))
				for (const d of st.declarationList.declarations) {
					const names = new Set(); bindNames(d.name, names);
					for (const nm of names) if (!scope.bindings.has(nm)) declareIn(scope, nm, d);
				}
			else if (ts.isClassDeclaration(st) && st.name) declareIn(scope, st.name.text, st);
			else if (ts.isFunctionDeclaration(st) && st.name) declareIn(scope, st.name.text, st);
		}
		// Function-scoped var: declare into nearest function/module scope (parent chain without block-only).
		// Simplified: var binds to parentScope's function scope — walk to root module or use parentScope.parent for blocks inside fn.
		const varScope = parentScope; // for nested blocks inside functions, var is collected via collect-like: hoist to parentScope if we thread fnScope
		for (const st of block.statements) visitStmt(st, scope, varScope);
	};
	const visitStmt = (st, scope, fnScope) => {
		if (ts.isVariableStatement(st)) {
			const lexical = isLexicalVarFlags(st.declarationList.flags), target = lexical ? scope : fnScope;
			for (const d of st.declarationList.declarations) {
				if (ts.isIdentifier(d.name)) {
					if (!target.bindings.has(d.name.text)) declareIn(target, d.name.text, d);
					const binding = resolveName(scope, d.name.text);
					if (d.initializer && isStoreInitExpr(d.initializer)) markStore(binding, d.name.getStart(sf));
					if (d.initializer) {
						const init = unwrapExpr(d.initializer);
						if (ts.isFunctionExpression(init) || ts.isArrowFunction(init))
							visitFn(init, scope, d.name.text);
						else visitExpr(d.initializer, scope);
					}
				} else {
					const names = new Set(); bindNames(d.name, names);
					for (const nm of names) if (!target.bindings.has(nm)) declareIn(target, nm, d);
					if (d.initializer) visitExpr(d.initializer, scope);
				}
			}
			return;
		}
		if (ts.isFunctionDeclaration(st)) {
			if (st.name && !scope.bindings.has(st.name.text)) declareIn(scope, st.name.text, st);
			visitFn(st, scope, st.name ? st.name.text : null);
			return;
		}
		if (ts.isClassDeclaration(st)) {
			const inner = { parent: scope, bindings: new Map() };
			if (st.name) declareIn(inner, st.name.text, st);
			ts.forEachChild(st, (c) => visitNode(c, inner));
			return;
		}
		if (ts.isBlock(st)) { visitBlock(st, scope); return; }
		if (ts.isExpressionStatement(st)) {
			const exp = unwrapExpr(st.expression);
			if (ts.isBinaryExpression(exp) && exp.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
				const left = unwrapExpr(exp.left);
				if (ts.isIdentifier(left) && isStoreInitExpr(exp.right)) {
					const binding = resolveName(scope, left.text);
					if (binding) markStore(binding, left.getStart(sf));
				}
			}
			visitExpr(st.expression, scope);
			return;
		}
		if (ts.isForStatement(st) || ts.isForInStatement(st) || ts.isForOfStatement(st)) {
			const loop = { parent: scope, bindings: new Map() }, init = st.initializer;
			if (init && ts.isVariableDeclarationList(init)) {
				const lexical = isLexicalVarFlags(init.flags), target = lexical ? loop : fnScope;
				for (const d of init.declarations) {
					const names = new Set(); bindNames(d.name, names);
					for (const nm of names) if (!target.bindings.has(nm)) declareIn(target, nm, d);
					if (d.initializer && isStoreInitExpr(d.initializer) && ts.isIdentifier(d.name))
						markStore(resolveName(loop, d.name.text), d.name.getStart(sf));
					if (d.initializer) visitExpr(d.initializer, lexical ? loop : scope);
				}
			} else if (init) visitExpr(init, scope);
			if (ts.isForStatement(st)) { if (st.condition) visitExpr(st.condition, loop); if (st.incrementor) visitExpr(st.incrementor, loop); }
			else visitExpr(st.expression, scope);
			if (st.statement) {
				if (ts.isBlock(st.statement)) visitBlock(st.statement, loop);
				else visitStmt(st.statement, loop, fnScope);
			}
			return;
		}
		if (ts.isTryStatement(st)) {
			if (st.tryBlock) visitBlock(st.tryBlock, scope);
			if (st.catchClause) {
				const cs = { parent: scope, bindings: new Map() };
				if (st.catchClause.variableDeclaration) {
					const names = new Set(); bindNames(st.catchClause.variableDeclaration.name, names);
					for (const nm of names) declareIn(cs, nm, st.catchClause.variableDeclaration);
				}
				if (st.catchClause.block) visitBlock(st.catchClause.block, cs);
			}
			if (st.finallyBlock) visitBlock(st.finallyBlock, scope);
			return;
		}
		if (ts.isIfStatement(st)) {
			visitExpr(st.expression, scope);
			if (st.thenStatement) { if (ts.isBlock(st.thenStatement)) visitBlock(st.thenStatement, scope); else visitStmt(st.thenStatement, scope, fnScope); }
			if (st.elseStatement) { if (ts.isBlock(st.elseStatement)) visitBlock(st.elseStatement, scope); else visitStmt(st.elseStatement, scope, fnScope); }
			return;
		}
		visitNode(st, scope);
	};
	const visitNode = (n, scope) => {
		if (!n) return;
		if (ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n)
			|| ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n)) {
			const nm = n.name && ts.isIdentifier(n.name) ? n.name.text : null;
			visitFn(n, scope, nm);
			return;
		}
		if (ts.isBlock(n)) { visitBlock(n, scope); return; }
		n.forEachChild((c) => visitNode(c, scope));
	};
	// Module scope
	const moduleScope = { parent: null, bindings: new Map() };
	for (const st of sf.statements) {
		// Hoist function decls + var names at module level
		if (ts.isFunctionDeclaration(st) && st.name) declareIn(moduleScope, st.name.text, st);
		if (ts.isVariableStatement(st) && !isLexicalVarFlags(st.declarationList.flags))
			for (const d of st.declarationList.declarations) {
				const names = new Set(); bindNames(d.name, names);
				for (const nm of names) if (!moduleScope.bindings.has(nm)) declareIn(moduleScope, nm, d);
			}
	}
	for (const st of sf.statements) visitStmt(st, moduleScope, moduleScope);
	return { stores, fns };
}
const firstParam = (fn) => { const p = fn.parameters[0]; return p && ts.isIdentifier(p.name) ? p.name.text : null; };
const isExactId = (expr, id) => { const n = unwrapExpr(expr); return !!(n && ts.isIdentifier(n) && n.text === id); };
function walkSkipNestedFns(root, fn, visitNode) {
	const visit = (n) => { if (!n || (isFnLike(n) && n !== fn && n !== root)) return; if (visitNode(n) === false) return; n.forEachChild(visit); };
	visit(root);
}
function hasStoreWrite(body, storeName, storeId, resolveStore, param, fn) {
	let ok = false;
	walkSkipNestedFns(body, fn, (n) => {
		if (ok) return false;
		if (ts.isCallExpression(n)) {
			const cal = unwrapExpr(n.expression), base = ts.isPropertyAccessExpression(cal) ? unwrapExpr(cal.expression) : null, a0 = n.arguments[0] && unwrapExpr(n.arguments[0]);
			if (ts.isPropertyAccessExpression(cal) && cal.name.text === "set" && ts.isIdentifier(base) && ts.isIdentifier(a0) && a0.text === param && n.arguments.length >= 2) {
				const id = resolveStore(base.text);
				if (id === storeId || (id == null && base.text === storeName)) ok = true;
			}
		} else if (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isElementAccessExpression(unwrapExpr(n.left))) {
			const left = unwrapExpr(n.left), base = unwrapExpr(left.expression), arg = unwrapExpr(left.argumentExpression);
			if (ts.isIdentifier(base) && ts.isIdentifier(arg) && arg.text === param) {
				const id = resolveStore(base.text);
				if (id === storeId || (id == null && base.text === storeName)) ok = true;
			}
		}
	});
	return ok;
}
function hasExactParamReturn(fn, param) {
	const body = fn.body; if (!body) return false;
	if (!ts.isBlock(body)) { let n = body; while (ts.isBinaryExpression(n) && n.operatorToken.kind === ts.SyntaxKind.CommaToken) n = n.right; return isExactId(n, param); }
	let ok = false;
	walkSkipNestedFns(body, fn, (n) => { if (ok) return false; if (ts.isReturnStatement(n) && n.expression && isExactId(n.expression, param)) ok = true; });
	return ok;
}
function isStoreReadExpr(expr, storeName, storeId, resolveStore, param) {
	const n = unwrapExpr(expr); if (!n) return false;
	if (ts.isCallExpression(n)) {
		const cal = unwrapExpr(n.expression), a0 = n.arguments[0] && unwrapExpr(n.arguments[0]), base = ts.isPropertyAccessExpression(cal) ? unwrapExpr(cal.expression) : null;
		if (!(ts.isPropertyAccessExpression(cal) && cal.name.text === "get" && ts.isIdentifier(base) && ts.isIdentifier(a0) && a0.text === param && n.arguments.length === 1)) return false;
		const id = resolveStore(base.text);
		return id === storeId || (id == null && base.text === storeName);
	}
	if (ts.isElementAccessExpression(n)) {
		const base = unwrapExpr(n.expression), arg = unwrapExpr(n.argumentExpression);
		if (!(ts.isIdentifier(base) && ts.isIdentifier(arg) && arg.text === param)) return false;
		const id = resolveStore(base.text);
		return id === storeId || (id == null && base.text === storeName);
	}
	return false;
}
function hasExactReadReturn(fn, storeName, storeId, resolveStore, param) {
	const body = fn.body; if (!body) return false;
	if (!ts.isBlock(body)) return isStoreReadExpr(body, storeName, storeId, resolveStore, param);
	let ok = false;
	walkSkipNestedFns(body, fn, (n) => { if (ok) return false; if (ts.isReturnStatement(n) && n.expression && isStoreReadExpr(n.expression, storeName, storeId, resolveStore, param)) ok = true; });
	return ok;
}
const matchesAttach = (fnEntry, store) => {
	const { fn, resolveStore } = fnEntry; const p0 = firstParam(fn);
	return !!(p0 && fn.parameters.length >= 2 && fn.body && hasStoreWrite(fn.body, store.name, store.id, resolveStore, p0, fn) && hasExactParamReturn(fn, p0));
};
const matchesRead = (fnEntry, store) => {
	const { fn, resolveStore } = fnEntry; const p0 = firstParam(fn);
	return !!(p0 && fn.body && hasExactReadReturn(fn, store.name, store.id, resolveStore, p0));
};
/** Optional prebuilt `model` (from buildScopeModel) lets callers analyzing the same exact source reuse one parse/traversal. */
function findProtos(src, file, model) {
	const m = model || buildScopeModel(parseSF(file, src)), out = [], seen = new Set();
	for (const store of m.stores) {
		if (seen.has(store.id)) continue;
		let attach = null, read = null;
		for (const ent of m.fns) {
			if (!attach && matchesAttach(ent, store)) attach = ent.name;
			if (!read && matchesRead(ent, store)) read = ent.name;
		}
		if (attach && read) { seen.add(store.id); out.push({ file, map: store.name, mapId: store.id, attach, read }); }
	}
	return out;
}
function exportAliases(src) {
	const code = mask(src, true), m = new Map();
	for (const x of code.matchAll(/\bexport\s*\{([^}]+)\}(?!\s*from\b)/g)) for (const p of parseExportClause(x[1])) m.set(p.public, p.source);
	for (const x of code.matchAll(/\bexport\s+(?:async\s+)?(?:function|const|let|var|class)\s+([\w$]+)/g)) m.set(x[1], x[1]);
	return m;
}
function namedImports(src) {
	const code = stripComments(src), syntax = mask(src, true), out = [];
	for (const m of code.matchAll(/\bimport\s*\{([^}]+)\}\s*from\s+["']([^"']+)["']/g)) {
		if (!kwInCode(syntax, m.index, m[0])) continue;
		for (const p of m[1].split(",")) {
			const t = p.trim().replace(/^type\s+/, ""), as = t.match(/^([\w$]+)\s+as\s+([\w$]+)$/);
			if (as) out.push({ imported: as[1], local: as[2], spec: m[2] });
			else if (/^[\w$]+$/.test(t)) out.push({ imported: t, local: t, spec: m[2] });
		}
	}
	return out;
}
const authorityWrongSource = (imp, srcAbs, defAbs, def, expRole) =>
	([ATTACH, READ, def.attach, def.read].includes(imp.imported) || [ATTACH, READ].includes(imp.local) || expRole.has(imp.imported))
	&& (!srcAbs || normalize(srcAbs) !== normalize(defAbs));
function calls(src, names) {
	const code = stripComments(src), sites = [];
	for (const name of names) for (const m of code.matchAll(new RegExp(String.raw`\b${name}\s*\(`, "g")))
		if (!/\bfunction\s*$/.test(code.slice(Math.max(0, m.index - 12), m.index))) sites.push(name);
	return sites;
}
function exportExposesPrivate(key, target, needle) {
	const k = key.replace(/^\.\//, ""), t = target.replace(/^\.\//, ""), sc = (s) => (s.match(/\*/g) || []).length, ks = sc(k), ts = sc(t);
	if (ks > 1 || ts > 1) return true;
	if (ks === 0 && ts === 0) return k === needle || k.endsWith("/" + needle) || k.includes(needle) || t.includes(needle)
		|| t.replace(/\.(?:mjs|cjs|js|d\.mts|d\.ts)$/, "") === needle || t.includes(`/${needle}.`);
	if (ks !== 1) return true;
	const i = k.indexOf("*"), pre = k.slice(0, i), suf = k.slice(i + 1);
	if (needle.startsWith(pre) && needle.endsWith(suf)) {
		const mid = needle.slice(pre.length, needle.length - suf.length);
		if (mid && !mid.includes("*")) return true;
	}
	if (ts === 1) {
		const ti = t.indexOf("*"), tp = t.slice(0, ti), tsu = t.slice(ti + 1);
		for (const c of [needle, `${needle}.mjs`, `${needle}.js`, `${needle}.cjs`, `dist/${needle}.mjs`, `dist/${needle}.js`, `dist/${needle}.cjs`])
			if (c.startsWith(tp) && c.endsWith(tsu) && c.slice(tp.length, c.length - tsu.length)) return true;
	}
	return t.includes(needle);
}
const mentionsPrivate = (exportsField, needle) => exportTargets({ exports: exportsField }, "all").filter((e) => exportExposesPrivate(e.key, e.target, needle));
function materializeNs(ns) {
	const o = Object.create(null);
	for (const k of Reflect.ownKeys(ns).sort(keySort)) {
		if (typeof k === "symbol") continue;
		let desc; try { desc = Object.getOwnPropertyDescriptor(ns, k); } catch { continue; }
		if (!desc) continue;
		if (Object.prototype.hasOwnProperty.call(desc, "value")) o[k] = desc.value;
		else if (typeof desc.get === "function") { try { o[k] = desc.get.call(ns); } catch { /* skip */ } }
	} return o;
}
function isTrustedZodInst(o, Z) { if (typeof Z !== "function") return false; try { return o instanceof Z; } catch { return false; } }
function isOpaqueLeaf(v, Z, leaves) { return (leaves instanceof Set && leaves.has(v)) || isTrustedZodInst(v, Z); }
function directDataHit(v, path, wanted) {
	let keys; try { keys = Reflect.ownKeys(v).sort(keySort); } catch { return null; }
	for (const k of keys) { let d; try { d = Object.getOwnPropertyDescriptor(v, k); } catch { continue; }
		if (d && Object.prototype.hasOwnProperty.call(d, "value") && wanted.has(d.value)) return `${path}.${String(k)}`; } return null;
}
function identityReachable(root, targets, trustedZodType = null, opaqueLeaves = null, dbExportsIdentity = null) {
	const wanted = new Set(targets.filter((t) => t != null));
	if (!wanted.size) return { hit: false, overflow: true, path: null, uncertainty: "no targets" };
	const seen = new WeakSet(); let nodes = 0;
	const stack = [{ v: root, path: "$", d: 0 }], push = (v, path, d) => { if (v != null && (typeof v === "object" || typeof v === "function")) stack.push({ v, path, d }); };
	while (stack.length) {
		const { v, path, d } = stack.pop();
		if (v == null || (typeof v !== "object" && typeof v !== "function")) continue;
		if (wanted.has(v)) return { hit: true, overflow: false, path };
		if (seen.has(v)) continue; seen.add(v);
		if (++nodes > MAX_ID_NODES || d >= MAX_ID_DEPTH) return { hit: false, overflow: true, path, uncertainty: "bounds" };
		if (isOpaqueLeaf(v, trustedZodType, opaqueLeaves)) {
			const h = directDataHit(v, path, wanted); if (h) return { hit: true, overflow: false, path: h };
			if (dbExportsIdentity != null && v === dbExportsIdentity) {
				const mat = materializeNs(v);
				for (const k of Reflect.ownKeys(mat).sort(keySort)) if (typeof k !== "symbol" && wanted.has(mat[k])) return { hit: true, overflow: false, path: `${path}.${String(k)}` };
			}
			continue;
		}
		let keys; try { keys = Reflect.ownKeys(v).sort(keySort); } catch { keys = []; }
		for (const k of keys) {
			if (typeof v === "function" && typeof k === "string" && FN_SKIP.has(k)) continue;
			let desc; try { desc = Object.getOwnPropertyDescriptor(v, k); } catch { continue; }
			if (!desc) continue;
			if (!Object.prototype.hasOwnProperty.call(desc, "value")) return { hit: false, overflow: true, path: `${path}.${String(k)}`, uncertainty: "own accessor descriptor" };
			const val = desc.value, p = `${path}.${String(k)}`;
			if (wanted.has(val)) return { hit: true, overflow: false, path: p }; push(val, p, d + 1);
		}
		if (typeof Map === "function" && v instanceof Map) { let i = 0; for (const [mk, mv] of Map.prototype.entries.call(v)) {
			const pk = `${path}[Map.key:${i}]`, pv = `${path}[Map.val:${i}]`;
			if (wanted.has(mk)) return { hit: true, overflow: false, path: pk };
			if (wanted.has(mv)) return { hit: true, overflow: false, path: pv };
			push(mk, pk, d + 1); push(mv, pv, d + 1); i++;
		} } else if (typeof Set === "function" && v instanceof Set) { let i = 0; for (const sv of Set.prototype.values.call(v)) {
			const p = `${path}[Set:${i}]`; if (wanted.has(sv)) return { hit: true, overflow: false, path: p }; push(sv, p, d + 1); i++;
		} }
	}
	return { hit: false, overflow: false, path: null };
}
function nsExportObject(ns, name) {
	if (!ns) return { error: "namespace unavailable" };
	const v = materializeNs(ns)[name];
	return v == null || (typeof v !== "object" && typeof v !== "function") ? { error: `${name} absent or not an object` } : { value: v };
}
function resolveDefinerIdentities(defNs, def, aliases) {
	const attachNames = new Set([def.attach, ATTACH]), readNames = new Set([def.read, READ]);
	for (const [exp, loc] of aliases) {
		if (loc === def.attach || loc === ATTACH) attachNames.add(exp);
		if (loc === def.read || loc === READ) readNames.add(exp);
	}
	const pick = (names, role) => {
		let found = null, label = null;
		for (const n of sorted(names)) {
			if (!(n in defNs) && !Object.hasOwn(defNs, n)) continue;
			const v = defNs[n]; if (typeof v !== "function") continue;
			if (found && found !== v) return { error: `ambiguous ${role} identity via ${label} and ${n}` };
			found = v; label = n;
		}
		return found ? { fn: found, exportName: label } : { error: `missing unambiguous ${role} export identity` };
	};
	const a = pick(attachNames, "attach"), r = pick(readNames, "read");
	if (a.error) return { error: a.error }; if (r.error) return { error: r.error };
	if (a.fn === r.fn) return { error: "attach and read identities are not distinct functions" };
	return { attachFn: a.fn, readFn: r.fn, attachExport: a.exportName, readExport: r.exportName };
}
function resolveRuntimeDefinerIdentities(ns) {
	const a = ns[ATTACH], r = ns[READ];
	if (typeof a !== "function") return { error: `missing exact named export ${ATTACH}` };
	if (typeof r !== "function") return { error: `missing exact named export ${READ}` };
	if (a === r) return { error: "attach and read identities are not distinct functions" };
	return { attachFn: a, readFn: r, attachExport: ATTACH, readExport: READ };
}
async function checkPublicEntry(pkg, key, entry, target) {
	const ek = `${pkg}::${key}`;
	if (Object.hasOwn(ENV_BOUND, ek)) {
		if (!entry || !isFile(entry)) {
			fail(`${pkg} export ${key}: missing ${entry ? rel(entry) : "?"}`);
			return { pkg, key, entry: entry ? rel(entry) : null, target: target ?? null, bad: FORBIDDEN.slice(), mode: "environmentBoundStatic", reason: ENV_BOUND[ek], namespaceCount: 0 };
		}
		// Exact env-bound entries only: strict unknown default/object/expression fail-closed.
		const d = deriveFS(entry, null, STRICT_AST);
		for (const e of d.errors) fail(`${pkg} export ${key}: environmentBoundStatic ${e}`);
		if (d.bad.length) fail(`${pkg} export ${key}: forbidden namespace exports: ${d.bad.join(", ")}`);
		if (!d.ok && !d.errors.length && !d.bad.length) fail(`${pkg} export ${key}: environmentBoundStatic could not derive exhaustive namespace`);
		return { pkg, key, entry: rel(entry), target: target ?? rel(entry), bad: d.bad, mode: "environmentBoundStatic", reason: ENV_BOUND[ek], namespaceCount: d.namespaceCount };
	}
	if (!entry || !isFile(entry)) {
		fail(`${pkg} export ${key}: missing ${entry ? rel(entry) : "?"}`);
		return { pkg, key, entry: entry ? rel(entry) : null, bad: FORBIDDEN.slice(), mode: "dynamicImport", ns: null };
	}
	try {
		const ns = await import(pathToFileURL(entry).href), bad = forbiddenInNamespace(ns);
		if (bad.length) fail(`${pkg} export ${key}: forbidden namespace exports: ${bad.join(", ")}`);
		return { pkg, key, entry: rel(entry), bad, mode: "dynamicImport", ns };
	} catch (e) {
		fail(`${pkg} export ${key}: import failed ${rel(entry)}: ${e.message}`);
		return { pkg, key, entry: rel(entry), bad: FORBIDDEN.slice(), mode: "dynamicImport", ns: null };
	}
}
function runMutationChecks() {
	const errs = []; let n = 0, check = (c, m) => { n++; if (!c) errs.push(m); };
	check(!canonicalJs("./client", "./dist/client-AbCdEf12.mjs"), "hashed export rejected");
	check(!!(canonicalJs("./client", "./dist/client.mjs") && canonicalJs(".", "./dist/index.mjs")), "stable exports ok");
	check(!!(hashedBase("oidc-provider-DpKUimjZ.mjs") && !hashedBase("secret-policy.mjs")), "hash basename");
	check(!!(badSpec("../runtime/src/internal/x.ts") && badSpec("packages/runtime/dist/index.mjs")), "bad specs");
	const found = specs(`// import "../runtime/src/x.ts"\nconst s = 'import "./evil.mjs" from "x"';\nimport "./ok.mjs";\n`);
	check(found.length === 1 && found[0] === "./ok.mjs" && !found.some(badSpec), "comment/string ignored");
	check(specs(`import "../src/foo.ts";`).some(badSpec), "real forbidden specifier");
	const multiImp = specs(`import {\n  foo,\n  bar\n} from "../src/internal/secret.ts";\n`);
	check(multiImp.some((s) => s === "../src/internal/secret.ts") && multiImp.some(badSpec), "multiline import forbidden src");
	const multiExp = specs(`export {\n  baz\n} from "../src/packages-runtime/x.ts";\n`);
	check(multiExp.some((s) => s === "../src/packages-runtime/x.ts") && multiExp.some(badSpec), "multiline export-from forbidden src");
	check(/\battachInternalCredentialAuthority\b/.test(stripComments(`import type { attachInternalCredentialAuthority } from "./x";`)), "decl name");
	check(!/\battachInternalCredentialAuthority\b/.test(stripComments(`// attachInternalCredentialAuthority\nexport const x=1;`)), "comment stripped");
	const p1 = `const internalCredentialAuthorities = /* @__PURE__ */ new WeakMap();\nfunction attachInternalCredentialAuthority(target, config) {\ninternalCredentialAuthorities.set(target, Object.freeze({ ...config }));\nreturn target;\n}\nfunction readInternalCredentialAuthority(target) {\nreturn internalCredentialAuthorities.get(target);\n}\n`;
	check(findProtos(p1, "a").length === 1, "single proto");
	const proto2 = (extra, label) => check(findProtos(p1 + extra, "a").length >= 2, label), storeFn = (n, a, r, bodyA, bodyR) => `function ${a}(t,c){${bodyA}}\nfunction ${r}(t){${bodyR}}\n`;
	proto2(`const altStore = new Map();\n${storeFn("alt","attachAlt","readAlt","altStore.set(t,Object.freeze({...c}));return t;","return altStore.get(t);")}`, "alternate-second-store detected");
	proto2(`const splitStore = new WeakMap();\n${storeFn("s","attachSplit","readSplit","const frozen=Object.freeze({...c});splitStore.set(t,frozen);return t;","return splitStore.get(t);")}`, "split-freeze extra-store detected");
	proto2(`const assignStore = new Map();\n${storeFn("a","attachAssign","readAssign","assignStore.set(t,Object.assign({},c));return t;","return assignStore.get(t);")}`, "Object.assign extra-store detected");
	proto2(`const bareStore = new WeakMap();\n${storeFn("b","attachBare","readBare","bareStore.set(t,c);return t;","return bareStore.get(t);")}`, "no-freeze extra-store detected");
	proto2(`let letStore = new WeakMap();\n${storeFn("l","attachLet","readLet","letStore.set(t,Object.freeze({...c}));return t;","return letStore.get(t);")}`, "let alternate-store detected");
	proto2(`var varStore = new Map();\n${storeFn("v","attachVar","readVar","varStore.set(t,Object.freeze({...c}));return t;","return varStore.get(t);")}`, "var alternate-store detected");
	proto2(`const semiStore = new WeakMap()\n${storeFn("s","attachSemi","readSemi","semiStore.set(t,Object.freeze({...c}));return t;","return semiStore.get(t);")}`, "semicolonless alternate-store detected");
	proto2(`let splitDeclStore\nsplitDeclStore = new WeakMap();\n${storeFn("s","attachSplitDecl","readSplitDecl","splitDeclStore.set(t,Object.freeze({...c}));return t;","return splitDeclStore.get(t);")}`, "split-decl/assign extra-store detected");
	proto2(`const parenStore = new WeakMap();\n${storeFn("p","attachParen","readParen","parenStore.set(t,Object.freeze({...c}));return (t);","return parenStore.get(t);")}`, "parenthesized-return extra-store detected");
	proto2(`const asiStore = new WeakMap()\n${storeFn("a","attachAsi","readAsi","asiStore.set(t,Object.freeze({...c}));return t","return asiStore.get(t)")}`, "ASI-return extra-store detected");
	check(findProtos(`let onlySplit\nonlySplit = new Map();\n${storeFn("o","attachOS","readOS","onlySplit.set(t,c);return (t)","return onlySplit.get(t)")}`, "a").length === 1, "split decl/assign store protocol");
	check(findProtos(`const pStore = Object.create(null);\n${storeFn("p","attachP","readP","pStore[t]=c;return (t);","return pStore[t];")}`, "a").length === 1, "parenthesized return store protocol");
	// Full-file AST store protocol: order/distance, multi-declarator, null-then-assign, bare new, exact-return negatives.
	const farPad = "const pad = 1;\n".repeat(40);
	check(findProtos(`${farPad}const farStore = new WeakMap();\n${farPad}${storeFn("f","attachFar","readFar","farStore.set(t,c);return t;","return farStore.get(t);")}`, "a").length === 1, "AST store protocol far-apart functions");
	check(findProtos(`${storeFn("b","attachBefore","readBefore","beforeStore.set(t,c);return t;","return beforeStore.get(t);")}\nconst beforeStore = new WeakMap();\n`, "a").length === 1, "AST store protocol function-before-store");
	check(findProtos(`const afterStore = new WeakMap();\n${storeFn("a","attachAfter","readAfter","afterStore.set(t,c);return t;","return afterStore.get(t);")}`, "a").length === 1, "AST store protocol function-after-store");
	check(findProtos(`let pad, multiStore = new WeakMap();\n${storeFn("m","attachMulti","readMulti","multiStore.set(t,c);return t;","return multiStore.get(t);")}`, "a").length === 1, "AST multi-declarator store protocol");
	check(findProtos(`let nullStore = null;\nnullStore = new WeakMap();\n${storeFn("n","attachNull","readNull","nullStore.set(t,c);return t;","return nullStore.get(t);")}`, "a").length === 1, "AST null-init then store assign protocol");
	check(findProtos(`const bareNew = new WeakMap;\n${storeFn("w","attachBareNew","readBareNew","bareNew.set(t,c);return t;","return bareNew.get(t);")}`, "a").length === 1, "AST new WeakMap without parens protocol");
	check(findProtos(`const semiAst = new Map()\nfunction attachSemiAst(t,c){semiAst.set(t,c);return t}\nfunction readSemiAst(t){return semiAst.get(t)}\n`, "a").length === 1, "AST semicolonless store protocol");
	check(findProtos(`const badVal = new WeakMap();\nfunction attachBadVal(t,c){badVal.set(t,c);return t.value;}\nfunction readBadVal(t){return badVal.get(t);}\n`, "a").length === 0, "AST exact-return rejects return target.value");
	check(findProtos(`const badCall = new WeakMap();\nfunction attachBadCall(t,c){badCall.set(t,c);return t();}\nfunction readBadCall(t){return badCall.get(t);}\n`, "a").length === 0, "AST exact-return rejects return target()");
	check(findProtos(`const badElse = new WeakMap();\nfunction attachBadElse(t,c){badElse.set(t,c);return targetElse;}\nfunction readBadElse(t){return badElse.get(t);}\n`, "a").length === 0, "AST exact-return rejects return targetElse");
	const aliases = exportAliases(p1 + `export { attachInternalCredentialAuthority as xt, readInternalCredentialAuthority as St };\n`);
	check(aliases.get("xt") === ATTACH && aliases.get("St") === READ, "export aliases");
	const renamed = staticExportBindings(`export { attachInternalCredentialAuthority as attachAuthority };\n`);
	check(renamed.has(ATTACH) && renamed.has("attachAuthority"), "renamed forbidden source binding");
	check(FORBIDDEN.some((x) => renamed.has(x)), "renamed source classified forbidden");
	const unres = relativeReexports(`export { foo } from "./does-not-exist-xyz.mjs";\nexport * from "./also-missing.mjs";\n`);
	check(unres.length === 2 && unres.every((e) => e.spec.startsWith(".")), "unresolved relative reexport edges");
	check(unres.every((e) => resolveMod("/tmp/nonexistent-boundary-clearance", e.spec) === null), "unresolved relative reexport fatal path");
	check(forbiddenInNamespace({ attachAuthority: 1, attachInternalCredentialAuthority: () => {} }).includes(ATTACH), "non-root namespace forbidden rejected");
	check(forbiddenInNamespace({ publicOk: true }).length === 0, "clean namespace accepted");
	const wrong = namedImports(`import { xt as attachInternalCredentialAuthority } from "./other.mjs";`)[0];
	const defFix = { attach: ATTACH, read: READ }, roleFix = new Map([["xt", "attach"], ["St", "read"]]);
	check(authorityWrongSource(wrong, "/pkg/other.mjs", "/pkg/def.mjs", defFix, roleFix), "wrong-source rejected");
	check(authorityWrongSource(wrong, null, "/pkg/def.mjs", defFix, roleFix), "unresolvable-source rejected");
	check(calls(`attachInternalCredentialAuthority(x,y);`, [ATTACH]).length === 1, "semantic callsite");
	const dRen = deriveMemory(new Map([["/e.mjs", "export { attachInternalCredentialAuthority as attachAuthority };\n"]]), "/e.mjs");
	check(!dRen.ok && dRen.bad.includes(ATTACH), "envBound static renamed forbidden");
	const dStar = deriveMemory(new Map([["/e.mjs", 'export * from "./c.mjs";\n'], ["/c.mjs", "export function attachInternalCredentialAuthority(){}\n"]]), "/e.mjs");
	check(!dStar.ok && dStar.bad.includes(ATTACH), "envBound static star reexport forbidden");
	const dBare = deriveMemory(new Map([["/e.mjs", 'export * from "vitest";\n']]), "/e.mjs");
	check(!dBare.ok && dBare.errors.some((e) => e.includes("bare star")), "envBound static bare star rejected");
	const dMem = (src, label, pred, opts) => { const d = deriveMemory(new Map([["/e.mjs", src]]), "/e.mjs", opts ?? STRICT_AST); check(!d.ok && pred(d), label); };
	const dGraph = (mods, label, pred, opts) => { const d = deriveMemory(new Map(mods), "/e.mjs", opts ?? STRICT_AST); check(pred(d), label); };
	const uDef = (d) => !d.ok && d.errors.some((e) => /unresolvable|unresolved|bare module namespace/i.test(e)), badHas = (n) => (d) => !d.ok && d.bad.includes(n);
	dMem("export default attachInternalCredentialAuthority;\n", "envBound static direct default forbidden", badHas(ATTACH));
	dMem("export default { nested: { x: attachInternalCredentialAuthority } };\n", "envBound static nested default forbidden", badHas(ATTACH));
	dMem("export default factory();\n", "envBound static unresolvable default rejected", uDef);
	dMem("const x = attachInternalCredentialAuthority\nexport default x\n", "envBound static alias id default forbidden", badHas(ATTACH));
	dMem("const x = attachInternalCredentialAuthority\nexport default { nested: { x } }\n", "envBound static alias bag default forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.ts';\nexport default hidden;\n"], ["/private.ts", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST import-alias default hidden forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { withExclusiveMigrationLease as lease } from './lease.ts';\nexport { lease };\n"], ["/lease.ts", "export function withExclusiveMigrationLease(){}\n"]],
		"AST withExclusiveMigrationLease as lease reexport forbidden", badHas("withExclusiveMigrationLease"));
	dGraph([["/e.mjs", "import { releaseRuntimeLease as rl } from './rl.ts';\nexport default { nested: { rl } };\n"], ["/rl.ts", "export function releaseRuntimeLease(){}\n"]],
		"AST nested default alias forbidden origin", badHas("releaseRuntimeLease"));
	dGraph([["/e.mjs", "import { credentialAuthorityGeneration as gen } from './g.ts';\nconst bag = { nested: { gen } };\nexport default bag;\n"], ["/g.ts", "export const credentialAuthorityGeneration = 1;\n"]],
		"AST alias-bag credentialAuthorityGeneration forbidden", badHas("credentialAuthorityGeneration"));
	dGraph([["/e.mjs", "import { helper as h } from './safe.ts';\nexport { h as util };\nconst bag = { nested: { h } };\nexport default bag;\nconst localAlias = 1;\nexport { localAlias };\n"], ["/safe.ts", "export function helper(){}\n"]],
		"AST clean alias/nested/default safe bindings accepted", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "const x = 1;\nexport default x;\nconst y = { a: 1 };\nexport { y };\n"]], "AST clean local alias and object export accepted", (d) => d.ok && d.bad.length === 0);
	// General mode: benign cycles, untraceable expressions, and private impl imports must not fail-close.
	dGraph([["/e.mjs", "import { a } from './b.mjs';\nexport { a };\n"], ["/b.mjs", "import { a } from './e.mjs';\nexport { a };\n"]],
		"AST benign binding cycle accepted under general mode", (d) => d.ok && d.bad.length === 0 && !d.errors.some((e) => /cycle/i.test(e)), GENERAL_AST);
	dGraph([["/e.mjs", "export { attachInternalCredentialAuthority as leaked } from './b.mjs';\n"], ["/b.mjs", "export { attachInternalCredentialAuthority } from './e.mjs';\nexport function attachInternalCredentialAuthority(){}\n"]],
		"AST cycle with reachable forbidden origin still rejected", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "export default factory();\nexport const bag = { nested: factory() };\n"]],
		"AST general mode allows untraceable complex exports", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as att } from './p.ts';\nexport function createAuth(x){ att(x); return x; }\nexport const createAuthArrow = (x) => { att(x); return x; };\n"], ["/p.ts", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST private forbidden import inside non-leaking createAuth accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.ts';\nexport default hidden;\n"], ["/private.ts", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST general mode still rejects export-reachable hidden forbidden", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import { withExclusiveMigrationLease as lease } from './lease.ts';\nexport { lease };\n"], ["/lease.ts", "export function withExclusiveMigrationLease(){}\n"]],
		"AST general mode still rejects lease reexport forbidden", badHas("withExclusiveMigrationLease"), GENERAL_AST);
	dGraph([["/e.mjs", "export default obj.attachInternalCredentialAuthority;\nexport const x = opts.withExclusiveMigrationLease;\n"]],
		"AST property-access name is not free binding", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Mixed chunk: safe mcp + forbidden alias; only root-selected names affect final forb.
	dGraph([["/e.mjs", "export { mcp } from './chunk.mjs';\n"], ["/chunk.mjs", "export const mcp = 1;\nexport function attachInternalCredentialAuthority(){}\nexport { attachInternalCredentialAuthority as lt };\nexport { attachInternalCredentialAuthority as ut };\nexport { attachInternalCredentialAuthority as gt };\n"]],
		"AST root reexport of safe mcp from mixed chunk with forbidden aliases accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "export { lt } from './chunk.mjs';\n"], ["/chunk.mjs", "export const mcp = 1;\nexport function attachInternalCredentialAuthority(){}\nexport { attachInternalCredentialAuthority as lt };\nexport { attachInternalCredentialAuthority as ut };\nexport { attachInternalCredentialAuthority as gt };\n"]],
		"AST root reexport of forbidden alias from mixed chunk rejected", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "export * as authority from './private.ts';\n"], ["/private.ts", "export function attachInternalCredentialAuthority(){}\nexport function readInternalCredentialAuthority(){}\nexport function withExclusiveMigrationLease(){}\n"]],
		"AST root export * as authority namespace reaches private forbidden helpers", (d) => !d.ok && d.bad.includes(ATTACH) && d.bad.includes(READ) && d.bad.includes("withExclusiveMigrationLease"), GENERAL_AST);
	dGraph([["/e.mjs", "export { mcp } from './chunk.mjs';\n"], ["/chunk.mjs", "export const mcp = 1;\nexport * as privateNs from './hidden.ts';\n"], ["/hidden.ts", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST root reexport of safe mcp ignores unselected dependency namespace-private", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// import * as ns: selected members via N→I; whole-namespace export conservatively collects all dep exports.
	dGraph([["/e.mjs", "import * as ns from './dep.mjs';\nexport const x = ns.withExclusiveMigrationLease;\n"], ["/dep.mjs", "export const withExclusiveMigrationLease = 1;\n"]],
		"AST import-star selected withExclusiveMigrationLease reexport forbidden", badHas("withExclusiveMigrationLease"), GENERAL_AST);
	dGraph([["/e.mjs", "import * as ns from './dep.mjs';\nexport default { x: ns.attachInternalCredentialAuthority };\n"], ["/dep.mjs", "export const attachInternalCredentialAuthority = 1;\n"]],
		"AST import-star selected attachInternalCredentialAuthority in default bag forbidden", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import * as ns from './dep.mjs';\nexport { ns };\n"], ["/dep.mjs", "export const withExclusiveMigrationLease = 1;\nexport const safe = 1;\n"]],
		"AST import-star namespace object export conservatively exposes forbidden", badHas("withExclusiveMigrationLease"), GENERAL_AST);
	dGraph([["/e.mjs", "import * as ns from './dep.mjs';\nexport const x = ns.safe;\n"], ["/dep.mjs", "export const safe = 1;\nexport const withExclusiveMigrationLease = 1;\n"]],
		"AST import-star selected safe ignores unselected forbidden sibling", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "const safe = 1;\nexport const bag = { withExclusiveMigrationLease: safe };\n"]],
		"AST ordinary object property name is not binding", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Source-order top-level evaluation: assigns + var decls; snapshots vs live roots.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet leaked\nleaked = hidden\nexport { leaked }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST top-level assign propagates forbidden alias", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a, b\na = hidden\nb = a\nexport { b }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST multi-step top-level assign propagates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs'\nlet leaked\nleaked = (hidden)\nexport { leaked }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST parenthesized/semicolonless assign propagates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "let a, b\na = 1\nb = a\nexport { b }\n"]], "AST clean top-level assign chain accepted", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet leaked\nfunction f(){ leaked = hidden }\nexport { leaked }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST general mode ignores assign inside function body", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "let leaked\nexport { leaked }\n"]], "AST unresolved exported binding stays U under strict", uDef);
	// Snapshot at export-const declaration (not final live binding of nested ids).
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p'\nlet a = 1\na = hidden\nexport const bag = { a }\n"], ["/p", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST export bag snapshots forbidden assign before declaration", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p'\nlet a = hidden\na = 1\nexport const bag = { a }\n"], ["/p", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST export bag snapshots safe assign before declaration", (d) => d.ok && d.bad.length === 0);
	// Live named roots resolve final binding; `export default a` snapshots; `export { a as default }` is live.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a = 1\nexport { a }\na = hidden\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST live named export before later forbidden assign", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a = 1\nexport default a\na = hidden\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST default export snapshots safe before later forbidden assign", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a = hidden\nexport default a\na = 1\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST default export snapshots forbidden before later safe assign", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a = hidden\nexport { a as default }\na = 1\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST export-as-default live forbidden then safe overwrite clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a = 1\nexport { a as default }\na = hidden\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST export-as-default live safe then forbidden overwrite fails", badHas(ATTACH));
	dGraph([["/e.mjs", "let a = 1\nexport { a }\na = 2\n"]], "AST safe live named export after later safe assign", (d) => d.ok && d.bad.length === 0);
	// Top-level var hoisting vs let/const; initializer-less var does not clear earlier assign.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\na = hidden\nvar a\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST var hoist predeclare allows pre-assign forbidden export", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\na = hidden\nvar a\na = 1\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST var initializer-less does not clear then safe overwrite", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "a = 1\nvar a\nexport { a }\n"]], "AST var hoist clean pre-assign control", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nvar a = 1\na = hidden\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST var init then assign forbidden at statement", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nvar a = hidden\nvar a = 1\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST var init at statement safely overwrites forbidden", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\n({ a } = { a: hidden })\nvar a\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST var binding-pattern hoist with destructuring assign forbidden", badHas(ATTACH));
	// Recursive assign, declaration/assignment patterns, member/container mutations.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a, b\na = b = hidden\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST nested right-associative assign propagates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "let a, b\na = b = 1\nexport { a, b }\n"]], "AST nested right-associative assign clean control", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst { x: a } = { x: hidden }\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST object binding pattern decl propagates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "const { x: a } = { x: 1 }\nexport { a }\n"]], "AST object binding pattern decl clean control", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a\n[a] = [hidden]\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST array destructuring assign propagates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "let a\n[a] = [1]\nexport { a }\n"]], "AST array destructuring assign clean control", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet a\n({ a } = { a: hidden })\nexport { a }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST object destructuring assign propagates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "let a\n({ a } = { a: 1 })\nexport { a }\n"]], "AST object destructuring assign clean control", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = { x: 1 }\nbag.x = hidden\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST dotted member write updates container forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "const bag = { x: 1 }\nbag.x = 2\nexport { bag }\n"]], "AST dotted member write clean control", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = { x: 1 }\nbag['x'] = hidden\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST computed member write updates container forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "const bag = { x: 1 }\nbag['x'] = 2\nexport { bag }\n"]], "AST computed member write clean control", (d) => d.ok && d.bad.length === 0);
	// Callable metadata: assign function/arrow updates fnBodies; non-callable deletes stale.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet factory = () => 1\nfactory = () => hidden\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict fnBodies update after arrow assign leaks forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet factory = () => hidden\nfactory = () => 1\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict fnBodies replace forbidden with safe callable", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet factory = () => hidden\nfactory = 1\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict non-callable reassignment deletes fnBodies fail-closed", uDef);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet factory = () => hidden\nfactory = () => 1\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST general mode does not scan reassigned callable body", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Parameter-default call semantics: evaluate default only when arg omitted or explicit undefined.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = hidden) { return x }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict param default omitted arg evaluates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = hidden) { return x }\nexport const y = factory(undefined)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict param default explicit undefined evaluates forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = hidden) { return x }\nexport const y = factory(1)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict param default skipped when non-undefined arg supplied", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(hidden, x = hidden) { return x }\nexport const y = factory(1)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict param named hidden shadows import in later default", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = hidden, y = x) { return y }\nexport const z = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict earlier param default still sees module forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(...rest) { return rest }\nexport const y = factory(1)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict rest param no-default clean control", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x) { return x }\nexport const y = factory(1)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict no-default param clean control", (d) => d.ok && d.bad.length === 0);
	// Classic for / for-in / for-of lexical scopes (let/const patterns; var function-scoped).
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(){ for (let hidden = 1;;) { return hidden } }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict for-loop let shadow of forbidden import clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(){ for (let hidden = 1;;) {} return hidden }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict use outside for-loop shadow resolves module import", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(){ for (const x of [1]) { return hidden } }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict unshadowed for-of body free ref fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(){ for (const { hidden } of [{ hidden: 1 }]) { return hidden } }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict destructured for-of binding shadow clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(){ for (var hidden = 1;;) {} return hidden }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict var for-loop binding is function-scoped shadow clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(){ for (const k in { a: 1 }) { const hidden = k; return hidden } }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict for-in body local shadow clean", (d) => d.ok && d.bad.length === 0);
	// Recursive object/array spread origin tracing (namespace spread enumerates whole N).
	dGraph([["/e.mjs", "import * as ns from './dep.mjs';\nexport const bag = { ...ns };\n"], ["/dep.mjs", "export const withExclusiveMigrationLease = 1;\nexport const safe = 1;\n"]],
		"AST object spread of relative namespace with forbidden fails", badHas("withExclusiveMigrationLease"), GENERAL_AST);
	dGraph([["/e.mjs", "import * as ns from './dep.mjs';\nexport const bag = { ...ns };\n"], ["/dep.mjs", "export const safe = 1;\nexport const other = 2;\n"]],
		"AST object spread of clean relative namespace accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst inner = { hidden }\nexport const bag = { ...inner }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST recursive local object spread preserves forbidden", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "const inner = { safe: 1 }\nexport const bag = { ...inner }\n"]],
		"AST recursive clean local object spread accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nexport const bag = [ ...[hidden] ]\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST array spread preserves forbidden origin", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "export const bag = [ ...[1, 2] ]\n"]],
		"AST clean array spread accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Strict env-bound: exported call graph closes over forbidden alias; bare namespace escapes fail closed.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ return hidden }\nexport const leaked = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict exported call graph leaks forbidden alias", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ return hidden }\nexport const leaked = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST general mode export-reachable call still leaks forbidden", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ return hidden }\nfunction unused(){ return factory() }\nexport const ok = 1\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST general mode non-export-reachable call body ignored", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Lexical scope: param/local/block shadow module import; unshadowed free ref still fails strict.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(hidden){ return hidden }\nexport const leaked = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict param shadow of forbidden import is clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ return hidden }\nexport const leaked = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict unshadowed closure over forbidden import fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ { const hidden = 1; return hidden } }\nexport const leaked = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict block-scoped shadow of forbidden import is clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ { const hidden = 1 } return hidden }\nexport const leaked = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict use outside block shadow resolves module import", badHas(ATTACH));
	// Block TDZ/predeclaration: uses and initializers before textual decl resolve to local block binding.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ return hidden; const hidden = 1 }\nexport const x = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict TDZ return before block const is local shadow clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ const x = hidden; const hidden = 1; return x }\nexport const x = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict TDZ initializer before block const is local shadow clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ return hidden; function hidden(){} }\nexport const x = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict block function decl before use shadows import clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ let hidden = 1; hidden = 2; return hidden }\nexport const x = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict assigned/mutated local shadow of forbidden import is clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ try { throw 1 } catch (hidden) { return hidden } }\nexport const x = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict catch binding shadows forbidden import clean", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './private.mjs';\nfunction factory(){ try { throw 1 } catch (hidden) {} return hidden }\nexport const x = factory()\n"], ["/private.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST strict use outside catch binding resolves module import", badHas(ATTACH));
	dGraph([["/e.mjs", "import * as pkg from 'some-package';\nexport { pkg };\n"]], "AST strict bare namespace named export fail-closed", uDef);
	dGraph([["/e.mjs", "import * as pkg from 'some-package';\nexport default pkg;\n"]], "AST strict bare namespace default export fail-closed", uDef);
	dGraph([["/e.mjs", "import * as pkg from 'some-package';\nexport const bag = { pkg };\n"]], "AST strict bare namespace object export fail-closed", uDef);
	// General mode: bare-package namespace is opaque U; export-reachable forms must not fail independently.
	dGraph([["/e.mjs", "import * as pkg from 'some-package';\nexport { pkg };\n"]], "AST general bare namespace named export accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "import * as pkg from 'some-package';\nexport default pkg;\n"]], "AST general bare namespace default export accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "import * as pkg from 'some-package';\nexport const bag = { pkg };\n"]], "AST general bare namespace object export accepted", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dMem("export const leaked = factory();\n", "AST strict named unresolvable call fail-closed", uDef);
	// --- A) Structured keyed/indexed container origins ---
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst { safe } = { safe: 1, bad: hidden }\nexport { safe }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST selected safe sibling with forbidden sibling passes", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst { bad } = { safe: 1, bad: hidden }\nexport { bad }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST selected forbidden sibling fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst { safe, ...rest } = { safe: 1, bad: hidden }\nexport { rest }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST rest containing forbidden fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst { x = hidden } = { x: 1 }\nexport { x }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST present safe property skips forbidden default", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst { x = hidden } = {}\nexport { x }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST missing property applies forbidden default", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst { x = hidden } = { x: undefined }\nexport { x }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST explicit-undefined property applies forbidden default", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = { nested: { hidden } }\nbag.safe = 1\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST exact member write retains nested forbidden sibling slot", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = {}\nbag.x = hidden\nbag.x = 1\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST exact slot overwrite clears forbidden", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = {}\nbag.x = hidden\nbag.y = 1\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST different property write retains forbidden slot", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = { nested: { hidden } }\nbag['safe'] = 1\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST computed-known member write retains nested forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = {}\nbag['x'] = hidden\nbag['x'] = 1\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST computed-known slot overwrite clears forbidden", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = {}\nbag['x'] = hidden\nbag['y'] = 1\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST computed-known different key retains forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst arr = [1, hidden]\nconst [safe] = arr\nexport { safe }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST nested array selected safe index passes", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst arr = [1, hidden]\nconst [, bad] = arr\nexport { bad }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST nested array selected forbidden index fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst arr = [1, hidden]\nconst [safe, ...rest] = arr\nexport { rest }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST array rest containing forbidden fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst k = 'x'\nconst bag = {}\nbag[k] = hidden\nexport { bag }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST unknown computed write conservatively retains forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = { ['nested']: { hidden } }\nexport const x = bag['nested']\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST computed-known property read projects forbidden slot", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst bag = { ['safe']: 1, bad: hidden }\nexport const x = bag['safe']\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST computed-known property read projects safe slot only", (d) => d.ok && d.bad.length === 0);
	// --- B) Bounded known-call value evaluation ---
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction id(x){ return x }\nexport const y = id(hidden)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST known-call id(hidden) propagates forbidden arg", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction id(x){ return x }\nexport const y = id(1)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST known-call id(1) safe arg passes", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction id(x){ const y = x; return y }\nexport const z = id(hidden)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST known-call local const y=x; return y propagates", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction id(x){ return x }\nfunction wrap(v){ return id(v) }\nexport const y = wrap(hidden)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST nested wrap(id(hidden)) fails", badHas(ATTACH));
	// P0: a callee's free variables must resolve against its own defining lexical environment, never the caller's
	// current locals. getHidden closes over the module `hidden` import; noisy's same-named safe parameter must not
	// leak into getHidden's frame just because noisy happens to be the caller.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from \"./p.mjs\";\nfunction getHidden(){return hidden}\nfunction noisy(hidden){return getHidden();}\nexport const leaked=noisy(42);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST GENERAL caller safe-param shadow must not leak into unrelated callee frame", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from \"./p.mjs\";\nfunction getHidden(){return hidden}\nfunction noisy(hidden){return getHidden();}\nexport const leaked=noisy(42);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST STRICT caller safe-param shadow must not leak into unrelated callee frame", badHas(ATTACH));
	// Safe control: when the shadowing parameter is used directly by its own function (not through a distinct callee
	// that closes over the module binding), the shadow genuinely makes the call safe.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction noisy(hidden){return hidden;}\nexport const safe=noisy(42);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST caller param shadow used by its own function stays safe", (d) => d.ok && d.bad.length === 0);
	// Nested closure must capture the callee's OWN locals (its param shadow), not the caller's — the mirror image of
	// the P0 case: here the shadow belongs to the same frame the nested helper closes over, so it stays safe.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction wrap(hidden){ function helper(){ return hidden; } return helper(); }\nexport const safe = wrap(1);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST nested closure resolves callee's own param shadow safely", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Live/source-order module binding: a callable's defining locals is the live module `locals` Map reference, so a
	// call evaluated after a later reassignment must see the final bound value, not a snapshot taken at definition.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet val = 1;\nfunction getVal(){ return val; }\nval = hidden;\nexport const leaked = getVal();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST callable sees live module binding reassigned forbidden before call", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nlet val = hidden;\nfunction getVal(){ return val; }\nval = 1;\nexport const safe = getVal();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST callable sees live module binding reassigned safe before call", (d) => d.ok && d.bad.length === 0);
	// Nested FunctionDeclaration hoisted inside a known callee must register as a known callable (not disappear from
	// fnBodies), closing over the callee's own current locals so a forbidden argument routed through it still leaks.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './definer.mjs';\nfunction wrap(v) { function helper() { return v; } return helper(); }\nexport const leaked = wrap(hidden);\n"], ["/definer.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST GENERAL nested FunctionDeclaration hoisted callable leaks forbidden arg", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './definer.mjs';\nfunction wrap(v) { function helper() { return v; } return helper(); }\nexport const leaked = wrap(hidden);\n"], ["/definer.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST STRICT nested FunctionDeclaration hoisted callable leaks forbidden arg", badHas(ATTACH));
	dGraph([["/e.mjs", "function wrap(v) { function helper() { return v; } return helper(); }\nexport const leaked = wrap(1);\n"]],
		"AST safe nested FunctionDeclaration wrap(1) passes", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Reassignment invalidation: overwriting the hoisted nested callable with a safe closure must clear the leak.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './definer.mjs';\nfunction wrap(v) { function helper() { return v; } helper = () => 1; return helper(); }\nexport const safe = wrap(hidden);\n"], ["/definer.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST nested FunctionDeclaration reassigned to safe closure clears forbidden", (d) => d.ok && d.bad.length === 0);
	// Same-name collision: the nested helper only shadows fnBodies for its own call frame; the outer module-scope
	// helper of the same name must resolve correctly again once that frame exits (no permanent shared-map leak).
	dGraph([["/e.mjs", "function helper(){ return 1 }\nfunction wrap(v){ function helper() { return v; } return helper(); }\nconst ignored = wrap(1);\nexport const safe = helper();\n"]],
		"AST nested same-name helper shadow restores outer callable after call exits", (d) => d.ok && d.bad.length === 0);
	// P1 fix: a callable `var` declaration inside a call frame must save/restore the shared fnBodies entry just like
	// nested FunctionDeclaration hoisting — otherwise the frame-local callable permanently overwrites a same-named
	// outer/module helper once the call returns, and later calls to that outer helper resolve the leaked closure.
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from \"./definer.mjs\";\nfunction helper(){return hidden}\nfunction wrap(v){ var helper=function(){return v}; return helper(); }\nconst ignored=wrap(1);\nexport const leaked=helper();\n"], ["/definer.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST var-declared call-frame-local callable leaks into outer helper without restore", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "function helper(){ return 1 }\nfunction wrap(v){ var helper = function(){ return v; }; return helper(); }\nconst ignored = wrap(2);\nexport const safe = helper();\n"]],
		"AST var-declared call-frame-local safe callable does not taint outer safe helper after restore", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './definer.mjs';\nfunction wrap(v) { var helper = function() { return v; }; helper = () => 1; return helper(); }\nexport const safe = wrap(hidden);\n"], ["/definer.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST var-declared callable reassigned to safe closure clears forbidden in same frame", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = { nested: hidden }){ return x }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST omitted nested object default fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = { nested: hidden }){ return x }\nexport const y = factory(undefined)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST explicit-undefined nested object default fails", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = { nested: hidden }){ return x }\nexport const y = factory({ nested: 1 })\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST supplied argument skips forbidden default", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import * as ns from './dep.mjs';\nfunction factory(x = ns.withExclusiveMigrationLease){ return x }\nexport const y = factory()\n"], ["/dep.mjs", "export const withExclusiveMigrationLease = 1;\n"]],
		"AST namespace-member default resolves forbidden", badHas("withExclusiveMigrationLease"));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(hidden = hidden){ return hidden }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST param hidden=hidden TDZ shadows module import", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = hidden, hidden = 1){ return x }\nexport const y = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST later param name TDZ-shadows import in earlier default", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = 1, y = x){ return y }\nexport const z = factory()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST earlier initialized param available to later default", (d) => d.ok && d.bad.length === 0);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction factory(x = 1, y = x){ return y }\nexport const z = factory(hidden)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST earlier param supplied forbidden reaches later default", badHas(ATTACH));
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction f(){ return hidden }\nexport const y = f()\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST GENERAL export-reachable f(){return hidden} fails", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nfunction f(){ return hidden }\nexport function g(){ return f() }\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST GENERAL non-export-reachable call inside exported fn body ignored", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	dGraph([["/e.mjs", "import { attachInternalCredentialAuthority as hidden } from './p.mjs';\nconst id = (x) => x\nexport const y = id(hidden)\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST arrow known-call propagates forbidden arg", badHas(ATTACH));
	// P0 fix: runStmts must snapshot/restore each nested block's own lexical (let/const/class/FunctionDeclaration)
	// shadows on block exit so they never persist past the closing `}`. Without the fix, a block-local shadow of an
	// outer/module forbidden binding wrongly stays bound after the block, making a leaking return look safe.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nlet x=hidden;\nfunction wrap(){ { const x=1; } return x; }\nexport const leaked=wrap();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST GENERAL block const shadow must not persist past block, outer forbidden binding leaks", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction get(){return hidden}\nfunction wrap(){ { const get=()=>1; get(); } return get(); }\nexport const leaked=wrap();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST GENERAL block const callable shadow must not persist past block, outer forbidden callable leaks", badHas(ATTACH), GENERAL_AST);
	// Safe mirror of the P0 case: a block that only *temporarily* shadows a safe outer binding with a forbidden value
	// must not taint the outer binding once the block exits and control returns to it.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction wrap(){ let x = 1; { const x = hidden; } return x; }\nexport const safe=wrap();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST block const shadow of safe outer restores clean value after block exit", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Safe control: a block *assignment* (not a new lexical declaration) to a true outer/function binding is not a
	// block-local shadow and must persist past the block — only declarations this exact block introduces restore.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction wrap(){ let x=1; { x=hidden; } return x; }\nexport const leaked=wrap();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST assignment to outer binding inside block persists past block exit", badHas(ATTACH));
	// Safe control: a function-scoped `var` declared textually inside a block is not a block lexical declaration and
	// must remain visible (not restored) after the block.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction wrap(){ { var y = hidden; } return y; }\nexport const leaked=wrap();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST function-scoped var declared inside block remains visible after block", badHas(ATTACH));
	// Class-declaration and destructuring block shadows must restore the same as plain let/const on normal exit. The
	// class-declaration predeclare pass always binds the shadow name to a clean value, so the outer binding must be
	// forbidden here — only then does an unrestored shadow (wrongly clean) versus a restored outer (forbidden) differ.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction wrap(){ let X = hidden; { class X {} } return X; }\nexport const leaked=wrap();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST block class declaration shadow restores forbidden outer after normal block exit", badHas(ATTACH));
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction wrap(){ let a = 1; { const {a} = {a: hidden}; } return a; }\nexport const safe=wrap();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST block destructuring shadow restores after normal block exit", (d) => d.ok && d.bad.length === 0, GENERAL_AST);
	// Early-return path: a return statement located directly inside a nested block must still trigger that block's
	// restore (via `finally`) before the enclosing call frame observes the shared callable map again.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction helper(){ return 1 }\nfunction wrap(v){ { const helper = () => v; return helper(); } }\nconst ignored = wrap(hidden);\nexport const safe = helper();\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST early return inside nested block still restores callable shadow on early-return path", (d) => d.ok && d.bad.length === 0);
	// The block's own return value must reflect the shadowed origin computed before restoration runs.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction wrap(v){ { const y = v; return y; } }\nexport const leaked = wrap(hidden);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST early return origin computed from block-local shadow before restore runs", badHas(ATTACH));
	// P1 fix: a non-exhaustive if (return in one branch only) must not discard fallthrough to the
	// statements after it - the continuing path (missing else = unchanged baseline) must still execute.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction f(v){ if(v) return 1; return hidden; }\nexport const y=f(0);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST GENERAL non-exhaustive if fallthrough to later forbidden return rejected", badHas(ATTACH), GENERAL_AST);
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction f(v){ if(v) return hidden; return 1; }\nexport const y=f(0);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST non-exhaustive if retains forbidden terminating branch alongside safe fallthrough", badHas(ATTACH), GENERAL_AST);
	// Exhaustive if (both branches return) may merge origins and return immediately.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction f(v){ if(v) return hidden; else return 1; }\nexport const y=f(0);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST exhaustive if merges branch origins forbidden", badHas(ATTACH));
	dGraph([["/e.mjs", "function f(v){ if(v) return 1; else return 2; }\nexport const y=f(0);\n"]],
		"AST exhaustive if merges branch origins safe", (d) => d.ok && d.bad.length === 0);
	// Reversed-order overwrite: each branch must evaluate from the same pre-if snapshot, never from the other
	// branch's mutated locals - a forbidden write in one branch must not be hidden by the other branch's safe
	// write executing "after" it in source order.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction f(v){ let x=1; if(v){x=hidden}else{x=1} return x; }\nexport const y=f(0);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST reversed branch-state overwrite rejected instead of ending safe", (d) => !d.ok);
	// Safe identical continuing branches (both fall through to the same resulting state) must still pass.
	dGraph([["/e.mjs", "function f(v){ let x=1; if(v){x=1}else{x=1} return x; }\nexport const y=f(0);\n"]],
		"AST safe identical continuing branches accepted", (d) => d.ok && d.bad.length === 0);
	// Callable-state control: a branch that redefines a same-named callable must not leak its definingLocals
	// state into the other branch's continuation when the branches otherwise diverge.
	dGraph([["/e.mjs", "import {attachInternalCredentialAuthority as hidden} from './p.mjs';\nfunction f(v){ let g = () => 1; if(v){ g = () => hidden; } return g(); }\nexport const y=f(0);\n"], ["/p.mjs", "export function attachInternalCredentialAuthority(){}\n"]],
		"AST non-exhaustive if callable-state divergence fails closed", (d) => !d.ok);
	// --- C) Scope-identity-aware full-AST store-protocol discovery ---
	check(findProtos(p1 + `function nest(){\nconst nestedStore = new WeakMap();\nfunction attachN(t,c){nestedStore.set(t,c);return t;}\nfunction readN(t){return nestedStore.get(t);}\n}\n`, "a").length >= 2, "nested second complete protocol fails");
	check(findProtos(p1 + `function nest(){\nconst onlyStore = new WeakMap();\n}\n`, "a").length === 1, "nested incomplete store alone does not count");
	check(findProtos(p1 + `function nest(){\nconst internalCredentialAuthorities = new WeakMap();\nfunction attachShadow(t,c){internalCredentialAuthorities.set(t,c);return t;}\nfunction readShadow(t){return internalCredentialAuthorities.get(t);}\n}\n`, "a").length >= 2, "same-name shadowed nested complete protocol is second definition");
	check(findProtos(p1 + `function nest(){\nconst harmless = new Map();\nconst x = harmless;\n}\n`, "a").length === 1, "unrelated harmless local Map ignored");
	check(findProtos(`{\nconst blockStore = new WeakMap();\nfunction attachB(t,c){blockStore.set(t,c);return t;}\nfunction readB(t){return blockStore.get(t);}\n}\n`, "a").length === 1, "block-scoped complete protocol discovered");
	check(findProtos(p1 + `{\nconst alt = new Map();\nfunction attachA(t,c){alt.set(t,c);return t;}\nfunction readA(t){return alt.get(t);}\n}\n`, "a").length >= 2, "block-scoped second complete protocol detected");
	// Env-bound safe shapes: function decls + relative reexports + bare named (not namespace) imports.
	dGraph([["/e.mjs", "import { helper as h } from 'bare-pkg';\nimport { useStore } from './store.mjs';\nfunction createAuthClient(){ return h }\nexport { createAuthClient, useStore }\n"], ["/store.mjs", "export function useStore(){}\n"]],
		"AST strict env-bound-like safe function and relative/bare named imports accepted", (d) => d.ok && d.bad.length === 0);
	const privDev = { "./internal/credential-authority": { development: "./dist/internal/credential-authority.mjs" } };
	check(mentionsPrivate(privDev, "internal/credential-authority").length > 0, "ALL-mode development private export rejected");
	const privSrc = { "./internal/credential-authority": { import: { source: "./dist/internal/credential-authority.mjs", default: "./dist/public.mjs" } } };
	check(mentionsPrivate(privSrc, "internal/credential-authority").length > 0, "ALL-mode nested source private export rejected");
	check(exportTargets({ exports: privDev }, "all").length === 1 && exportTargets({ exports: privDev }, "executable").length === 0, "executable omits development; ALL retains it");
	check(mentionsPrivate({ "./db/*": "./dist/db/*.mjs" }, "db/credential-authority-migration").length > 0, "wildcard ./db/* private export rejected");
	check(mentionsPrivate({ "./internal/*": { development: "./dist/internal/*.mjs" } }, "internal/credential-authority").length > 0, "wildcard ./internal/* private export rejected");
	check(mentionsPrivate({ "./widgets/*": "./dist/widgets/*.mjs" }, "db/credential-authority-migration").length === 0, "clean wildcard export accepted");
	check(mentionsPrivate({ "./x/**/*": "./dist/**/*.mjs" }, "db/credential-authority-migration").length > 0, "malformed multi-star wildcard fail-closed");
	const ca = () => "attach", cr = () => "read", idHit = (g) => identityReachable(g, [ca, cr]).hit === true;
	check(idHit({ attachAuthority: ca }), "identity direct renamed value");
	check(idHit({ localAttach: ca }), "identity import-local-equivalent renamed value");
	check(idHit({ default: ca }), "identity default export value");
	check(idHit({ bag: { nested: { fn: ca } } }), "identity nested bag value");
	check(idHit({ xs: [0, cr], m: new Map([["k", ca]]), s: new Set([cr]) }), "identity array/map/set value");
	check(identityReachable({ publicOk: true, n: 1 }, [ca, cr]).hit === false, "identity clean graph accepted");
	const rtA = () => "rtA", rtR = () => "rtR", authA = () => "authA", authR = () => "authR";
	check(identityReachable({ leaked: rtA }, [rtA, rtR]).hit && !identityReachable({ leaked: rtA }, [authA, authR]).hit, "runtime-only leak caught by runtime identity set only");
	check(identityReachable({ leaked: authA }, [authA, authR]).hit && !identityReachable({ leaked: authA }, [rtA, rtR]).hit, "auth-only leak caught by auth identity set only");
	let gInv = 0, zGet = 0, zSet = 0, fInv = 0, oGet = 0, oSet = 0, lGet = 0, dGet = 0; class TrustedZodLike {}
	const evil = {}, genuine = new TrustedZodLike(), hitInst = new TrustedZodLike(), spoof = Object.create(null);
	const allowExact = Object.create(null), allowHit = Object.create(null), lookalike = Object.create(null), fakeLog = Object.create(null), dbExact = Object.create(null);
	const defAcc = (o, k, get, set) => Object.defineProperty(o, k, { enumerable: false, configurable: true, get, set });
	const defData = (o, k, v) => Object.defineProperty(o, k, { value: v, writable: true, enumerable: true, configurable: true });
	Object.defineProperty(evil, "leak", { enumerable: true, configurable: true, get() { gInv++; return ca; } });
	defAcc(genuine, "~standard", () => { zGet++; return ca; }, () => { zSet++; }); defData(genuine, "publicOk", 1);
	defData(hitInst, "leaked", ca); defAcc(hitInst, "~standard", () => { zGet++; return {}; }, () => { zSet++; });
	Object.defineProperty(spoof, "_zod", { value: { def: true }, writable: false, enumerable: false, configurable: false });
	defAcc(spoof, "~standard", () => { fInv++; return ca; }, () => { fInv++; });
	defAcc(allowExact, "level", () => { oGet++; return "info"; }, () => { oSet++; });
	defData(allowHit, "leaked", ca); defAcc(allowHit, "level", () => { oGet++; return "info"; }, () => { oSet++; });
	Object.defineProperty(lookalike, Symbol.toStringTag, { value: "Module" });
	defAcc(lookalike, "accountSchema", () => { lGet++; return ca; }, () => { lGet++; });
	defAcc(fakeLog, "level", () => { lGet++; return "info"; }, () => { lGet++; });
	defAcc(dbExact, "smuggled", () => { dGet++; return ca; }, () => { dGet++; }); defData(dbExact, "publicOk", 1);
	const leaves = new Set([allowExact, allowHit, dbExact]), T = TrustedZodLike, acc = identityReachable(evil, [ca, cr], T), zodOk = identityReachable({ schema: genuine }, [ca, cr], T);
	const zodHit = identityReachable({ schema: hitInst }, [ca, cr], T), spoofAcc = identityReachable({ schema: spoof }, [ca, cr], T);
	const opClean = identityReachable({ logger: allowExact }, [ca, cr], null, leaves), opHit = identityReachable({ logger: allowHit }, [ca, cr], null, leaves);
	const opLike = identityReachable({ db_exports: lookalike }, [ca, cr], null, leaves), opFake = identityReachable({ logger: fakeLog }, [ca, cr], null, leaves);
	const dbSmug = identityReachable({ db_exports: dbExact }, [ca, cr], null, leaves, dbExact), dbLikeNo = identityReachable({ db_exports: lookalike }, [ca, cr], null, leaves, dbExact);
	check(gInv === 0 && !acc.hit && acc.overflow && acc.uncertainty === "own accessor descriptor", "identity accessor fail-closed without invoke");
	check(zGet === 0 && zSet === 0 && !zodOk.hit && !zodOk.overflow, "trusted ZodType opaque leaf clean without invoke");
	check(zodHit.hit && zGet === 0 && zSet === 0, "trusted ZodType direct canonical data property hit");
	check(fInv === 0 && !spoofAcc.hit && spoofAcc.overflow && spoofAcc.uncertainty === "own accessor descriptor", "lookalike non-trusted class accessor fail-closed without invoke");
	check(oGet === 0 && oSet === 0 && !opClean.hit && !opClean.overflow, "exact opaque leaf with accessors clean without invoke");
	check(opHit.hit && oGet === 0 && oSet === 0, "exact opaque leaf direct canonical data property hit");
	check(lGet === 0 && !opLike.hit && opLike.overflow && opLike.uncertainty === "own accessor descriptor", "distinct lookalike/Module tagged object fail-closed without invoke");
	check(lGet === 0 && !opFake.hit && opFake.overflow && opFake.uncertainty === "own accessor descriptor", "distinct logger-shaped object fail-closed without invoke");
	check(dGet === 1 && dbSmug.hit && String(dbSmug.path).endsWith(".smuggled"), "exact db_exports getter-smuggle caught");
	check(lGet === 0 && !dbLikeNo.hit && dbLikeNo.overflow, "lookalike Module getters uninvoked even when db_exports slot set");
	const srcMap = { "./widget": { import: "./dist/ok.mjs", source: "./src/widget.ts" } }, allSrc = exportTargets({ exports: srcMap }, "all"), execSrc = exportTargets({ exports: srcMap }, "executable");
	check(allSrc.some((e) => e.conds.includes("source") && e.target.includes("widget.ts")) && !execSrc.some((e) => e.conds.includes("source")), "ALL retains source target; executable omits it");
	const dSrc = deriveMemory(new Map([["/pkg/src/widget.ts", "export function migrateCredentialAuthorities(){}\nexport const ok = 1;\n"]]), "/pkg/src/widget.ts");
	check(!dSrc.ok && dSrc.bad.includes("migrateCredentialAuthorities"), "ALL static source-only forbidden export rejected");
	return { ok: errs.length === 0, errors: sorted(errs), count: n };
}
const reportMutationFailure = (mut) => { console.error(JSON.stringify({ ok: false, mode: "mutation-checks", mutationChecks: mut.count, errors: mut.errors }, null, 2)); process.exit(1); };
const WRAP = ["node scripts/verify-credential-authority-package-surface.mjs --self-test", "node scripts/verify-credential-authority-package-surface.mjs"];
if (process.argv.includes("--self-test")) {
	const mut = runMutationChecks(); if (!mut.ok) reportMutationFailure(mut);
	console.log(JSON.stringify({ ok: true, mode: "self-test", mutationChecks: mut.count, envBoundAllowlist: Object.keys(ENV_BOUND), recommendedWrapperCommands: WRAP }, null, 2));
} else {
	const mut = runMutationChecks(); if (!mut.ok) reportMutationFailure(mut);
	const rtDir = resolve(ROOT, "packages/runtime"), authDir = resolve(ROOT, "packages/clearance-auth");
	const rtDist = join(rtDir, "dist"), authDist = join(authDir, "dist"), authTypes = join(authDir, "types");
	for (const [p, k] of [[rtDist,"runtime dist"],[authDist,"auth dist"],[authTypes,"auth types"],[join(rtDir,"package.json"),"runtime package.json"],[join(authDir,"package.json"),"auth package.json"]])
		if (!existsSync(p)) fail(`Missing expected ${k}: ${rel(p)}`);
	if (errors.length) { console.error(JSON.stringify({ ok: false, errors: sorted(errors) }, null, 2)); process.exit(1); }
	const rtPkg = JSON.parse(readFileSync(join(rtDir, "package.json"), "utf8")), authPkg = JSON.parse(readFileSync(join(authDir, "package.json"), "utf8"));
	const rtAll = exportTargets(rtPkg, "all"), rtExec = exportTargets(rtPkg, "executable"), authAll = exportTargets(authPkg, "all"), authExec = exportTargets(authPkg, "executable");
	const conds = (es) => sorted(new Set(es.flatMap((e) => e.conds)));
	const pkgTrav = (all, exec) => ({ allTargets: all.length, executableTargets: exec.length, allConditions: conds(all), executableConditions: conds(exec) });
	const exportMapTraversal = {
		modeAllTraversesSourceOnlyConditions: true, sourceOnlyConditions: sorted(SOURCE_ONLY), runtime: pkgTrav(rtAll, rtExec), auth: pkgTrav(authAll, authExec),
		note: "source-only conditions omitted from dynamic execution remain visible in allConditions/private-surface checks",
	};
	for (const p of PRIVATE) {
		if (![join(rtDist, `${p}.mjs`), join(rtDist, `${p}.js`), join(rtDist, p, "index.mjs")].some(existsSync)) fail(`Expected private runtime artifact for ${p}`);
		const hits = mentionsPrivate(rtPkg.exports, p);
		if (hits.length) fail(`@clearance/runtime exports private path ${p}: ${hits.map((h) => `${h.key}->${h.target}[${h.conds.join(",")}]`).join("; ")}`);
	}
	const authJsExports = authExec.filter((e) => isJsTarget(e.target, e.conds)), declaredJs = new Set();
	for (const e of authJsExports) {
		const abs = resolveTarget(authDir, e.target); declaredJs.add(normalize(abs));
		if (!canonicalJs(e.key, e.target)) fail(`@clearance/auth export ${e.key}: non-canonical or hashed JS target ${JSON.stringify(e.target)}`);
		else if (!existsSync(abs)) fail(`@clearance/auth export ${e.key}: missing ${e.target}`);
	}
	const seeds = publicJs(authDir, authPkg).map((e) => e.abs), importedInternalChunks = new Set(), seen = new Set(), q = sorted(seeds);
	while (q.length) {
		const f = q.shift();
		if (!f || seen.has(f) || !existsSync(f) || relative(authDir, f).startsWith("..")) continue;
		seen.add(f); if (!isJs(f)) continue;
		for (const sp of specs(readFileSync(f, "utf8"))) {
			if (!sp.startsWith(".")) continue;
			const r = resolveMod(dirname(f), sp); if (!r || !isJs(r)) continue;
			if (hashedBase(r.split(sep).pop() || "")) importedInternalChunks.add(normalize(r));
			if (!seen.has(r)) q.push(r);
		}
		q.sort((a, b) => a.localeCompare(b));
	}
	for (const c of sorted(importedInternalChunks)) if (declaredJs.has(c)) fail(`@clearance/auth export target is imported internal chunk: ${rel(c)}`);
	const rtPublic = publicJs(rtDir, rtPkg), authPublic = publicJs(authDir, authPkg), rtRootPath = rootJs(rtDir, rtPkg), authRootPath = rootJs(authDir, authPkg), uniqueEntries = new Map();
	for (const e of rtPublic) uniqueEntries.set(`@clearance/runtime::${e.key}::${normalize(e.abs)}`, { pkg: "@clearance/runtime", ...e });
	for (const e of authPublic) uniqueEntries.set(`@clearance/auth::${e.key}::${normalize(e.abs)}`, { pkg: "@clearance/auth", ...e });
	const pubResults = [], environmentBoundStatic = []; let publicDynamicImports = 0;
	for (const e of sorted(uniqueEntries.keys()).map((k) => uniqueEntries.get(k))) {
		const r = await checkPublicEntry(e.pkg, e.key, e.abs, e.target); pubResults.push(r);
		if (r.mode === "environmentBoundStatic") environmentBoundStatic.push({ package: r.pkg, key: r.key, target: r.target, reason: r.reason, derivedNamespaceCount: r.namespaceCount });
		else publicDynamicImports++;
	}
	const rootFrom = (path, results) => results.find((r) => r.key === "." && r.entry && path && normalize(resolve(ROOT, r.entry)) === normalize(path));
	const rtRoot = rootFrom(rtRootPath, pubResults) ?? await checkPublicEntry("@clearance/runtime", ".", rtRootPath, null);
	const authRoot = rootFrom(authRootPath, pubResults) ?? await checkPublicEntry("@clearance/auth", ".", authRootPath, null);
	const pubEntries = [...rtPublic.map((e) => ({ pkg: "@clearance/runtime", dir: rtDir, ...e })), ...authPublic.map((e) => ({ pkg: "@clearance/auth", dir: authDir, ...e }))];
	for (const e of pubEntries) {
		const { forbidden: bad, errors: bindErrs } = hasForbiddenExport(e.abs, e.dir);
		if (bad.length) fail(`${e.pkg} export ${e.key}: forbidden exports ${bad.join(", ")}`);
		for (const be of bindErrs) fail(`${e.pkg} export ${e.key}: AST binding-flow ${be}`);
	}
	const allScan = [...allConditionScanTargets(rtDir, rtPkg).map((t) => ({ pkg: "@clearance/runtime", dir: rtDir, ...t })),
		...allConditionScanTargets(authDir, authPkg).map((t) => ({ pkg: "@clearance/auth", dir: authDir, ...t }))], allChecked = new Map();
	for (const t of allScan) {
		const k = `${t.pkg}::${normalize(t.abs)}`;
		if (allChecked.has(k)) { if (t.sourceOnly) allChecked.get(k).sourceOnly = true; continue; }
		allChecked.set(k, t);
	}
	let allConditionTargetsChecked = 0, sourceOnlyTargetsChecked = 0;
	for (const t of sorted(allChecked.keys()).map((k) => allChecked.get(k))) {
		allConditionTargetsChecked++; if (t.sourceOnly) sourceOnlyTargetsChecked++;
		const { forbidden: bad, errors: bindErrs } = hasForbiddenExport(t.abs, t.dir);
		if (bad.length) fail(`${t.pkg} ALL-condition target ${t.key} (${t.target}): forbidden exports ${bad.join(", ")}`);
		for (const be of bindErrs) fail(`${t.pkg} ALL-condition target ${t.key}: AST binding-flow ${be}`);
	}
	const allConditionStaticValidation = { targetsChecked: allConditionTargetsChecked, sourceOnlyTargetsChecked,
		mode: "generalExportReachability",
		note: "export-reachability AST for ALL-condition JS/source (source-only/development included); flags forbidden aliases, missing relative reexports, boundary escape; allows benign cycles and untraceable complex exports; never executes source-only targets" };
	const declFiles = new Map();
	for (const f of [...publicDecls(rtDir, rtPkg), ...publicDecls(authDir, authPkg), ...listFiles(authTypes).filter(isDecl)]) declFiles.set(rel(f), f);
	for (const f of sorted(declFiles.values())) {
		if (!existsSync(f)) { fail(`Missing declaration ${rel(f)}`); continue; }
		const hit = FORBIDDEN.filter((n) => new RegExp(String.raw`\b${n}\b`).test(stripComments(readFileSync(f, "utf8"))));
		if (hit.length) fail(`Forbidden name(s) in public declarations ${rel(f)}: ${hit.join(", ")}`);
	}
	const built = sorted(new Set([...listFiles(rtDist), ...listFiles(authDist), ...listFiles(authTypes)].filter((p) => isJs(p) || isDecl(p))));
	let specOff = 0;
	for (const f of built) for (const sp of sorted(new Set(specs(readFileSync(f, "utf8"))))) if (badSpec(sp)) { specOff++; fail(`built-surface: forbidden specifier ${JSON.stringify(sp)} in ${rel(f)}`); }
	const authJs = listFiles(authDist).filter(isJs), protos = authJs.flatMap((f) => findProtos(readFileSync(f, "utf8"), f));
	let resolvedCalls = 0; const valueIdentityHits = [];
	const identityChecks = {
		singleDefiningModule: protos.length === 1, secondStoreRejected: protos.length <= 1, semanticImportsResolvedToDefiner: true, semanticCallsitesResolved: true,
		runtimeValueIdentityChecked: false, runtimeValueIdentityClean: true, definerIdentitiesResolved: false, packageSpecificIdentities: true, accessorFailClosed: true,
		storeKindsScanned: ["WeakMap","Map","Object.create(null)|{}","split-decl/assign","block-scoped","full-AST-scope-identity"],
		scope: "bounded value-identity; package-specific definers; runtime opaque leaves + ZodType; exact db_exports getters once; export-reachability AST with structured origins + known-call eval (strict env-bound; general ALL/public); full-AST scope-identity store protocols",
	};
	let rtIdMeta = null, authIdMeta = null, rtEntriesChecked = 0, authEntriesChecked = 0, rtPair = null, authPair = null;
	const rtDefAbs = join(rtDist, "internal/credential-authority.mjs");
	if (!isFile(rtDefAbs)) fail(`@clearance/runtime: missing private definer ${rel(rtDefAbs)}`);
	else try {
		const resolved = resolveRuntimeDefinerIdentities(await import(pathToFileURL(rtDefAbs).href));
		if (resolved.error) fail(`@clearance/runtime: definer identity resolution: ${resolved.error}`);
		else { rtPair = { attachFn: resolved.attachFn, readFn: resolved.readFn }; rtIdMeta = { file: rel(rtDefAbs), attachExport: resolved.attachExport, readExport: resolved.readExport, resolved: true }; }
	} catch (e) { fail(`@clearance/runtime: failed to import private definer for value-identity: ${e.message}`); }
	if (protos.length !== 1) {
		fail(`@clearance/auth: expected exactly 1 credential-authority store definition; found ${protos.length}${protos.length ? ": " + protos.map((p) => rel(p.file) + "#" + p.map).join(", ") : ""}`);
	} else {
		const def = protos[0], defAbs = def.file;
		for (const f of authJs) {
			const code = stripComments(readFileSync(f, "utf8"));
			// One parse/scope-model build per file, reused for both site listing and protocol matching below.
			const model = buildScopeModel(parseSF(f, code)), sites = model.stores.map((s) => ({ name: s.name, index: s.index, id: s.id })), fileProtos = findProtos(code, f, model);
			for (const site of sites) {
				if (normalize(f) === normalize(defAbs) && def.mapId != null && site.id === def.mapId) continue;
				if (normalize(f) === normalize(defAbs) && def.mapId == null && site.name === def.map) continue;
				if (fileProtos.some((p) => p.mapId === site.id || (p.mapId == null && p.map === site.name))) {
					fail(`@clearance/auth: extra authority store ${rel(f)}#${site.name}`); identityChecks.secondStoreRejected = false;
				}
			}
		}
		const expRole = new Map(), aliases = exportAliases(readFileSync(defAbs, "utf8"));
		for (const [exp, loc] of aliases) {
			if (loc === def.attach || loc === ATTACH) expRole.set(exp, "attach");
			if (loc === def.read || loc === READ) expRole.set(exp, "read");
		}
		const roles = new Map(), addRole = (file, local, role) => { const k = normalize(file); if (!roles.has(k)) roles.set(k, new Map()); roles.get(k).set(local, role); };
		addRole(defAbs, def.attach, "attach"); addRole(defAbs, def.read, "read");
		for (const f of authJs) for (const imp of namedImports(readFileSync(f, "utf8"))) {
			if (!imp.spec.startsWith(".")) continue;
			const src = resolveMod(dirname(f), imp.spec);
			if (authorityWrongSource(imp, src, defAbs, def, expRole)) {
				identityChecks.semanticImportsResolvedToDefiner = false;
				fail(src ? `@clearance/auth: ${rel(f)} imports authority ${imp.local} from non-defining ${rel(src)}`
					: `@clearance/auth: ${rel(f)} imports authority ${imp.local} from unresolvable source ${JSON.stringify(imp.spec)}`);
			} else if (src && normalize(src) === normalize(defAbs) && expRole.has(imp.imported)) addRole(f, imp.local, expRole.get(imp.imported));
		}
		for (const f of authJs) {
			const locals = roles.get(normalize(f)) ?? new Map(), names = new Set([ATTACH, READ, def.attach, def.read, ...locals.keys()]);
			for (const name of calls(readFileSync(f, "utf8"), names)) {
				if (locals.has(name) || (normalize(f) === normalize(defAbs) && [def.attach, def.read, ATTACH, READ].includes(name))) { resolvedCalls++; continue; }
				if ([ATTACH, READ, def.attach, def.read].includes(name)) { identityChecks.semanticCallsitesResolved = false; fail(`@clearance/auth: unresolved semantic callsite ${name}( in ${rel(f)}`); }
			}
		}
		if (!resolvedCalls) { identityChecks.semanticCallsitesResolved = false; fail("@clearance/auth: no resolved attach/read callsites"); }
		try {
			const resolved = resolveDefinerIdentities(await import(pathToFileURL(defAbs).href), def, aliases);
			if (resolved.error) fail(`@clearance/auth: definer identity resolution: ${resolved.error}`);
			else {
				authPair = { attachFn: resolved.attachFn, readFn: resolved.readFn };
				authIdMeta = { file: rel(defAbs), attachExport: resolved.attachExport, readExport: resolved.readExport, resolved: true };
				identityChecks.definerIdentitiesResolved = true;
			}
		} catch (e) { fail(`@clearance/auth: failed to import definer for value-identity: ${e.message}`); }
	}
	if (!(rtPair && authPair)) identityChecks.packageSpecificIdentities = false;
	let trustedZodType = null; const zodIdx = join(rtDir, "node_modules/zod/index.js");
	if (!isFile(zodIdx)) fail(`@clearance/runtime: missing trusted Zod entry ${rel(zodIdx)}`);
	else try {
		const zodNs = await import(pathToFileURL(zodIdx).href);
		if (typeof zodNs.ZodType !== "function") fail("@clearance/runtime: trusted ZodType export is not a function");
		else trustedZodType = zodNs.ZodType;
	} catch (e) { fail(`@clearance/runtime: failed to import trusted ZodType: ${e.message}`); }
	let rtOpaqueLeaves = null, rtOpaqueMeta = null, rtDbExportsIdentity = null;
	const findRt = (key) => pubResults.find((r) => r.pkg === "@clearance/runtime" && r.key === key && r.mode === "dynamicImport");
	const rtRootNs = findRt(".")?.ns, dbExp = nsExportObject(findRt("./db")?.ns, "db_exports"), logObj = nsExportObject(rtRootNs, "logger"), envObj = nsExportObject(rtRootNs, "ENV");
	for (const [n, o] of [["db_exports", dbExp], ["logger", logObj], ["ENV", envObj]]) if (o.error) fail(`@clearance/runtime: opaque boundary ${n}: ${o.error}`);
	if (!dbExp.error && !logObj.error && !envObj.error) {
		rtOpaqueLeaves = new Set([dbExp.value, logObj.value, envObj.value]); rtDbExportsIdentity = dbExp.value;
		rtOpaqueMeta = { boundaries: [
			{ path: "@clearance/runtime::./db $.db_exports", rationale: "exact imported bundler namespace only; getters boundary-materialized once for attach/read comparison; lookalikes/Module spoofs never invoked" },
			{ path: "@clearance/runtime::. $.logger", rationale: "exact root logger; direct own data only; accessors never invoked" },
			{ path: "@clearance/runtime::. $.ENV", rationale: "environment facade; accessors never invoked; exact identity only" },
		], note: "runtime-only exact opaque leaves; only getters on exact imported db_exports identity are invoked; auth gets none" };
	}
	if (rtPair || authPair) {
		identityChecks.runtimeValueIdentityChecked = !!(rtPair && authPair);
		for (const r of pubResults) {
			if (r.mode !== "dynamicImport") continue;
			const isRt = r.pkg === "@clearance/runtime", pair = isRt ? rtPair : authPair, which = isRt ? "runtime" : "auth";
			if (!pair) { identityChecks.runtimeValueIdentityClean = false; fail(`${r.pkg} export ${r.key}: value-identity skipped; ${which} definer identities unavailable`); continue; }
			if (!r.ns) { identityChecks.runtimeValueIdentityClean = false; fail(`${r.pkg} export ${r.key}: value-identity skipped; dynamic namespace unavailable`); continue; }
			if (isRt) rtEntriesChecked++; else authEntriesChecked++;
			const hit = identityReachable(materializeNs(r.ns), [pair.attachFn, pair.readFn], isRt ? trustedZodType : null, isRt ? rtOpaqueLeaves : null, isRt ? rtDbExportsIdentity : null);
			if (hit.overflow) {
				identityChecks.runtimeValueIdentityClean = false;
				fail(hit.uncertainty === "own accessor descriptor"
					? `${r.pkg} export ${r.key}: value-identity own accessor at ${hit.path}; fail closed (getters never invoked)`
					: `${r.pkg} export ${r.key}: value-identity graph exceeded bounds (depth<=${MAX_ID_DEPTH}, nodes<=${MAX_ID_NODES}) at ${hit.path ?? "?"}; fail closed`);
			} else if (hit.hit) {
				identityChecks.runtimeValueIdentityClean = false; valueIdentityHits.push({ package: r.pkg, key: r.key, entry: r.entry, path: hit.path, identitySet: which });
				fail(`${r.pkg} export ${r.key}: canonical ${which} attach/read identity reachable at ${hit.path}`);
			}
		}
	}
	if (errors.length) {
		console.error(JSON.stringify({ ok: false, errorCount: sorted(new Set(errors)).length, mutationChecks: mut.count, errors: sorted(new Set(errors)) }, null, 2)); process.exit(1);
	}
	const def0 = protos[0];
	console.log(JSON.stringify({
		ok: true, mutationChecks: mut.count, packages: { runtime: rtPkg.name, auth: authPkg.name },
		rootEntries: { runtime: rtRoot.entry, auth: authRoot.entry }, exportMapTraversal, allConditionStaticValidation,
		forbiddenPublicExports: {
			rootDynamicImport: { runtime: rtRoot.bad, auth: authRoot.bad }, publicEntrypointsChecked: pubEntries.length, publicDynamicImports, environmentBoundStatic,
			modes: {
				runtimeValueIdentity: "dynamic imports; package-specific identities; runtime opaque leaves; only exact db_exports getters materialized once",
				environmentBoundStaticExhaustive: "strict export-reachability AST for exact @clearance/runtime::./lynx and @clearance/runtime::./test only; structured keyed/indexed origins; known-call value eval; unknown default/object/expression fail-closed",
				generalExportReachability: "named/default export roots only; known calls evaluated when module-evaluated or export-reachable in both modes; private imports inside non-exported impls ignored; benign cycles fixed-point empty; forbidden only when export-reachable",
			},
		},
		privateRuntimePathsNotExported: PRIVATE.slice(),
		authExportSurface: { jsExportTargetsChecked: authJsExports.length, importedInternalChunks: importedInternalChunks.size, importedInternalChunksNotExported: true },
		builtFilesScannedForSpecifiers: built.length, declarationFilesScanned: declFiles.size, specifierOffenders: specOff,
		credentialAuthorityIdentity: {
			definitions: protos.length, resolvedCallSites: resolvedCalls,
			definition: def0 ? { file: rel(def0.file), mapName: def0.map, attachName: def0.attach, readName: def0.read } : null,
			runtimeDefiner: rtIdMeta ?? { file: rel(rtDefAbs), resolved: false },
			authDefiner: authIdMeta ?? (def0 ? { file: rel(def0.file), resolved: false } : { resolved: false }),
			runtimePublicEntriesIdentityChecked: rtEntriesChecked, authPublicEntriesIdentityChecked: authEntriesChecked,
			runtimeOpaqueBoundaries: rtOpaqueMeta, valueIdentityHits, checks: identityChecks,
		}, recommendedWrapperCommands: WRAP,
	}, null, 2));
}
