#!/usr/bin/env node
// Evaluate one AUTOMATED validator against one evidence artifact, the way
// Paramify does.
//
// This exists because a validator cannot be reviewed by reading it: every
// failure mode here is silent. A validator that always passes is
// indistinguishable from one that works until the evidence it reads changes
// shape, and by then it is reporting a green check on nothing.
//
// It must run in Node, not Python: Paramify's engine is ECMAScript, and
// `(?<name>...)` does not compile under Python `re` at all.
//
// SEMANTICS, each established against a live tenant rather than assumed:
//   * the regex is compiled with `g` and `s`; `m` is never applied
//   * MATCH_COUNT  -> number of matches over the whole artifact
//   * MATCH_GROUP n-> capture group n of the FIRST match (a second occurrence
//                     of an anchor silently binds the group to whichever came
//                     first, which is why validators anchor on unique keys)
//   * rules combine with AND: every rule must hold for the validator to pass
//   * a read that finds nothing yields nothing, and nothing compared to
//     nothing HOLDS -> the rule passes vacuously. This is the silent false
//     pass, and detecting it is most of the point of this file.
//   * `disposition` is accepted by the REST API and then discarded, so today
//     every rule is a pass-requirement regardless of what it was authored as
//
// Two modes let one validator be judged against both realities:
//   --mode api-today    every rule is a pass-requirement (what ships today)
//   --mode as-designed  ERROR resolves first, then FAIL, then PASS
//
// Usage: node score.mjs <validator.json> <artifact.json> [--mode M] [--pretty]
// Emits one JSON object on stdout: verdict plus a per-rule trace.

import fs from "node:fs";

const args = process.argv.slice(2);
const files = args.filter((a) => !a.startsWith("--"));
const mi = args.indexOf("--mode");
const mode = mi !== -1 ? args[mi + 1] : "as-designed";
const pretty = args.includes("--pretty");

if (files.length < 2 || !["api-today", "as-designed"].includes(mode)) {
  console.error("usage: score.mjs <validator.json> <artifact.json> [--mode api-today|as-designed]");
  process.exit(2);
}

const validator = JSON.parse(fs.readFileSync(files[0], "utf8"));
const artifact = fs.readFileSync(files[1], "utf8");

const out = {
  key: validator.key ?? null,
  mode,
  compiles: true,
  compileError: null,
  matchCount: 0,
  firstGroups: null,
  rules: [],
  verdict: null,
  vacuous: false,
};

let re;
try {
  re = new RegExp(validator.regex, "gs");
} catch (e) {
  out.compiles = false;
  out.compileError = String(e.message);
  out.verdict = "COMPILE_ERROR";
  console.log(JSON.stringify(out, null, pretty ? 2 : 0));
  process.exit(0);
}

const matches = [];
let m;
let guard = 0;
while ((m = re.exec(artifact)) !== null) {
  if (m[0] === "") { re.lastIndex++; continue; }   // never spin on a zero-width match
  matches.push(m);
  if (++guard > 100000) break;
}
out.matchCount = matches.length;
out.firstGroups = matches.length ? (matches[0].groups ?? null) : null;

const first = matches[0];
// undefined models "the engine had nothing to read" -- the vacuous-pass case
const group = (n) => (first ? first[n] : undefined);

const asNumbers = (a, b) => {
  const x = Number(a), y = Number(b);
  return Number.isFinite(x) && Number.isFinite(y) &&
         String(a).trim() !== "" && String(b).trim() !== "" ? [x, y] : null;
};

const NEGATIVE = new Set(["NOT_EQUALS", "DOES_NOT_CONTAIN", "DOES_NOT_END_WITH", "DOES_NOT_START_WITH"]);

function compare(lhs, criteria, rhs) {
  // nothing vs nothing: reproduced faithfully, because this is the bug
  if (lhs === undefined && rhs === undefined) return !NEGATIVE.has(criteria);
  const L = lhs === undefined ? "" : String(lhs);
  const R = rhs === undefined ? "" : String(rhs);
  const n = asNumbers(L, R);
  switch (criteria) {
    case "EQUALS":                   return n ? n[0] === n[1] : L === R;
    case "NOT_EQUALS":               return n ? n[0] !== n[1] : L !== R;
    case "CONTAINS":                 return L.includes(R);
    case "DOES_NOT_CONTAIN":         return !L.includes(R);
    case "STARTS_WITH":              return L.startsWith(R);
    case "DOES_NOT_START_WITH":      return !L.startsWith(R);
    case "ENDS_WITH":                return L.endsWith(R);
    case "DOES_NOT_END_WITH":        return !L.endsWith(R);
    // NOTE: numeric-vs-lexicographic for the ordering operators is NOT verified
    // against Paramify. Encode numeric thresholds in the regex instead of
    // relying on these -- see docs/validators_design.md.
    case "GREATER_THAN":             return n ? n[0] >  n[1] : L >  R;
    case "GREATER_THAN_OR_EQUAL_TO": return n ? n[0] >= n[1] : L >= R;
    case "LESS_THAN":                return n ? n[0] <  n[1] : L <  R;
    case "LESS_THAN_OR_EQUAL_TO":    return n ? n[0] <= n[1] : L <= R;
    default: throw new Error("unknown criteria " + criteria);
  }
}

function operand(spec) {
  if (!spec || !spec.type) return undefined;
  if (spec.type === "CUSTOM_TEXT") return spec.customText;
  if (spec.type === "MATCH_COUNT") return matches.length;
  if (spec.type === "MATCH_GROUP") return group(spec.groupNumber);
  throw new Error("unknown value type " + spec.type);
}

for (const [i, rule] of (validator.validation_rules ?? []).entries()) {
  const op = rule.regexOperation ?? {};
  const lhs = op.type === "MATCH_COUNT" ? matches.length : group(op.groupNumber);
  const rhs = operand(rule.value);
  let held, error = null;
  try { held = compare(lhs, rule.criteria, rhs); }
  catch (e) { held = false; error = String(e.message); }
  out.rules.push({
    index: i + 1,
    operation: op.type === "MATCH_GROUP" ? `MATCH_GROUP[${op.groupNumber}]` : "MATCH_COUNT",
    criteria: rule.criteria,
    lhs: lhs === undefined ? null : lhs,
    rhs: rhs === undefined ? null : rhs,
    readNothing: lhs === undefined || (rhs === undefined && (rule.value ?? {}).type === "MATCH_GROUP"),
    disposition: rule.disposition ?? "PASS",
    held,
    error,
  });
}

if (mode === "api-today") {
  out.verdict = out.rules.every((r) => r.held) ? "PASS" : "FAIL";
} else {
  const fired = (d) => out.rules.some((r) => r.disposition === d && r.held);
  if (fired("ERROR")) out.verdict = "ERROR";
  else if (fired("FAIL")) out.verdict = "FAIL";
  else out.verdict = out.rules.filter((r) => r.disposition === "PASS").every((r) => r.held) ? "PASS" : "FAIL";
}

// A PASS reached with at least one rule having read nothing. NOT the same as
// "the regex did not match": an optional compliance half keeps the match count
// at 1 while its groups are absent, so a healthy-looking count hides it.
out.vacuous = out.verdict === "PASS" && out.rules.some((r) => r.held && r.readNothing);

console.log(JSON.stringify(out, null, pretty ? 2 : 0));
