# scanipy v1 — design notes (archive)

> Auto-generated input to [PLAN.md](../../PLAN.md), produced by the v1 design pass
> (1 prior-art researcher + 8 subsystem architects). PLAN.md is the curated, binding
> plan; this file is the detailed per-subsystem reference for implementation agents.
> Where this archive and PLAN.md disagree on module layout, **PLAN.md §3 wins**
> (notably: the shared IR lives at `src/scanipy/ir.py` and the matcher at
> `src/scanipy/engine/matcher.py`).

# PRIOR ART

## ir_design
"Build a normalized per-function IR from stdlib ast in PythonFrontend.parse, not a brand-new IR language -- annotate/wrap the ast rather than lowering to three-address code (keeps witness line/col fidelity for the Location model and avoids reinventing Python semantics). Components: (1) a per-module import table mapping local names to canonical dotted paths (resolves aliased imports before matching); (2) a function table (module-level + nested defs/lambdas, each with its own scope) used to build the intra-file call graph; (3) per-function def-use via a forward pass over statements where assignments create/kill access-path bindings. Represent taint state as a map from ACCESS PATH (base var + bounded .attr / constant-subscript suffix, depth cap 2-3) to a taint label set; each label carries provenance (source spec id + originating Location + ordered prior WitnessSteps) so the witness is reconstructable at the sink. Normalize the constructs that complicate def-use: Assign/AnnAssign, AugAssign (x += t taints x), tuple/star unpacking (a, b = pair), comprehension/lambda nested scopes, BoolOp/IfExp, f-strings (JoinedStr) and BinOp '+'/'%' as default string propagators, and call sites (Call) resolved through the import table to canonical dotted paths for pattern matching. This mirrors PyT (ast->CFG) and Semgrep (per-variable, field-sensitive, ignores aliasing) while staying within the frozen DSL pattern kinds (call/attribute/parameter/import) and flow vocab (any-arg/arg:N/self/return)."

## engine_design
"Flow-sensitive forward dataflow over a minimal per-function CFG (basic blocks + successor edges; PyT does exactly this). Decision: build a real CFG -- flow sensitivity with kills on reassignment needs control-flow ordering. Transfer function per statement: matched sources ADD taint labels to their target access path; assignments KILL the prior taint of the LHS access path then assign the RHS's taint (so re-binding a tainted var to a clean value untaints it); generic + per-spec propagators MOVE taint per the from/to flow; sanitizers REMOVE the matching label on the sanitized access path (one-sided -- only on the path where the sanitizer definitely runs). At CFG joins, taint is UNION, never intersection: tainted-on-one-branch (e.g. sanitized in the if but not the else) stays tainted -- this is the load-bearing P5 correctness rule. Loops: taint is monotone (only grows), so iterate a bounded worklist to fixpoint with a small iteration cap rather than unrolling. A finding is emitted when a sink pattern matches a call whose restricted argument(s) (Pattern.args) -- or any arg if unrestricted -- hold a taint label not removed by a sanitizer on that path, and the spec's when-constraints (e.g. shell=True) hold. The engine is class-agnostic: it knows nothing about CWEs; it only matches the active specs' patterns and moves labels. Witness: walk the surviving label's provenance chain to build the ordered source -> propagator(s) -> sink WitnessStep tuple, choosing the shortest deterministic path on ties."

## summaries_approach
"Two-phase TITO summaries for intra-file interprocedural (the Pysa model, scoped to one file -- this is precisely Semgrep's --pro-intrafile mode). Phase 1: build the intra-file call graph, condense into SCCs, and compute summaries in REVERSE-TOPOLOGICAL order (callees before callers) so each call site sees a ready summary. For an SCC with recursion/mutual recursion, run a bounded worklist fixpoint: start every member's summary at empty, re-analyze until summaries stop growing or a small iteration cap is hit (monotone, so it terminates). A function summary is a deterministic, sorted set of transfer flows over the Flow vocabulary: param_i -> return, param_i -> (internal sink S) [an interprocedural sink reachability fact], source_in_body -> return, source_in_body -> (internal sink S), and self/receiver variants. Each flow carries a compact internal sub-trace fragment for witness splicing. Phase 2 (the main intraprocedural pass) applies a callee's summary at each call site: map actual args to formal params, propagate per the summary's flows (taint actual arg label -> call's return access path; or, if param_i -> internal-sink, emit a finding immediately with the spliced witness arg -> param -> ... -> sink). Formal parameters are handled as symbolic internal taints -- engine-internal, requiring NO change to the 'planned' DSL parameter kind. Unanalyzable/external callees (no summary, e.g. stdlib) fall back to the spec's declared propagators or, absent one, the conservative default (taint passes through) -- documented as best-effort, not sound. Iterate the worklist and emit findings in sorted order for determinism (P3)."

## recommendations
- Adopt a two-phase architecture that slots into the existing contracts: (1) PythonFrontend.parse builds a normalized per-function IR + minimal CFG from stdlib ast; (2) TaintEngine.analyze runs a forward, flow-sensitive intraprocedural taint pass driven ENTIRELY by DetectorSpec sources/sinks/sanitizers/propagators (P4 -- no per-detector or per-CWE code in the engine). The engine's only built-in 'knowledge' is GENERIC propagation rules (assignment, +, f-strings, .format, container builds, str methods) that apply to all detectors equally.
- Make import/name resolution a FIRST-CLASS engine step, executed before matching. With stdlib ast and no types, you must canonicalize every Name/Attribute to a dotted path using the module's import table so that `from subprocess import run; run(x, shell=True)`, `import os.path as p; p.join(...)`, and `from os import system; system(x)` all match the dotted patterns `subprocess.run`, `os.path.join`, `os.system`. Without this, detectors silently fail on aliased imports. Resolve `import X`, `import X as Y`, `from M import N`, `from M import N as A`, and `import X.Y` forms into a name->canonical-dotted map per module.
- Key the taint environment by ACCESS PATHS, not bare variables: a base variable plus a bounded suffix of `.attr` and constant `[index]`/`['key']` steps (e.g. `x`, `x.a`, `x.a.b`, `data[0]`). This directly realizes the DSL's attribute patterns (`flask.request.*`) and lets attribute/container taint be tracked field-sensitively. Cap suffix depth at 2-3.
- At the access-path depth cap, OVER-APPROXIMATE: collapse to the bounded prefix and treat the whole sub-object as tainted (may taint sibling fields). This is the OPPOSITE of Semgrep's precision-favoring rule (where `x.a.b` tainted leaves `x` clean) and is a deliberate divergence: collapsing toward 'more tainted' biases to false positives, never false negatives, which is consistent with P5's safe direction. Document the divergence and rationale.
- Implement intra-file interprocedural analysis as TITO-style function summaries (like Pysa's taint-in-taint-out and PyT's blackbox_mapping), NOT call inlining -- inlining is exponential and breaks on recursion. A summary records, per function, the set of transfer flows: param_i->return, param_i->(sink S), source->return, source->(sink S), plus self/receiver flows. Apply summaries at call sites using the existing Flow vocabulary (arg:N, any-arg, self, return).
- The summary mechanism treats each FORMAL PARAMETER as a symbolic taint internally; this is pure engine machinery and does NOT require promoting the DSL `parameter` kind from 'planned' to 'supported'. v1 interprocedural taint works with the current DSL as-is. The `parameter` SOURCE kind (marking e.g. a Flask handler's params as tainted entrypoints) is a separate, optional DSL extension only needed if a detector wants entrypoint params as sources -- defer it without blocking v1.
- Construct witnesses as an ordered tuple of WitnessStep with roles source/propagator/sanitizer/sink (the existing model). For interprocedural hits, SPLICE the callee's internal sub-trace fragment into the caller trace so the witness reads source -> ... -> (arg enters callee param) -> ... -> sink. Store a compact sub-trace fragment in each summary flow so splicing needs no re-analysis.
- Guarantee determinism with a TOTAL order. Primary sort key (file, line, column, detector_id) can collide (one sink, two sources), so add a final tie-break on a stable witness fingerprint (hash of the ordered (role, file, line, col) tuples). For witness SELECTION when multiple source->sink paths exist, deterministically pick the shortest path, then the lexicographically smallest location tuple. Iterate specs, sources, sinks, and the summary worklist in sorted order; never rely on dict/set/filesystem iteration order (P3).
- Extend the DSL only where forced, and record it in docs/dsl-reference.md (it is explicitly draft/v0 that co-evolves with the engine). Likely additions beyond what os-command.yml already uses: kwarg-targeted args (taint in a named keyword arg, not just positional), a `from: arg:self`/`to: arg:N` by-side-effect propagator form for mutators like `list.append`/`dict.__setitem__` (Semgrep's by-side-effect), and eventually the `parameter`/`import` source kinds. Prefer DSL extension over engine special-casing every time.
- For the 6-8 core detectors, lean on the engine's generic propagation + per-detector YAML; the only engine features each needs are: sink arg-index restriction (already in Pattern.args) and the `when: {keyword: {...}}` constraint (already designed, used for shell=True). SQL injection ships NO string sanitizers -- the safe form is a bound-parameter call (a different, safe sink shape), matching the dsl-reference guidance. SSRF/path-traversal/deserialization are pure source/sink/sanitizer specs over the same engine.

## pitfalls
- Import/name resolution is mandatory and easy to forget: dotted patterns (os.system, subprocess.*, flask.request.*) will NOT match aliased imports (from subprocess import run; import os.path as p; from os import system) unless the engine canonicalizes Name/Attribute to dotted paths via a per-module import table BEFORE matching. Missing this causes silent false negatives.
- Aliasing / mutation-through-alias is a deliberate, DOCUMENTED UNSOUNDNESS, not a feature: like Semgrep, track taint per variable/access-path, not per object in memory, so b = a; sink(b) is caught but mutating a shared object through one alias and reading via another is missed. Be explicit (P7) that the analyzer is best-effort, not sound -- P5's one-sidedness covers SANITIZERS only and must not be read as overall soundness.
- Containers/collections: track only constant subscripts (a[0], d['k']); dynamic indices must conservatively taint/keep the whole container. Builds like [t], {..: t}, (t,) and comprehensions should taint the container; iterating a tainted container should taint the loop var. Mutators (list.append, dict[..]=, set.add) need by-side-effect propagators (a DSL extension) or a conservative default.
- Attribute taint needs an access-path depth cap (2-3) with OVER-APPROXIMATION at the cap (collapse to bounded prefix, may taint siblings -> FP not FN). This intentionally diverges from Semgrep's precise upward rule, trading precision for P5-safe direction. Without a cap, getter/setter chains can blow up the state space.
- Python-ast IR hazards a generic design misses: comprehensions and lambdas create NESTED SCOPES ([f(x) for x in tainted]); tuple/star unpacking (a, b = tainted_pair; first, *rest = t); augmented assignment (x += tainted taints x); f-strings (JoinedStr) and BinOp +/% must be default propagators; with/try/except/finally and BoolOp/IfExp create control-flow edges that the CFG must model for correct joins.
- Control-flow join semantics: taint MUST be union at joins (sanitized on one branch but not another => still tainted). Intersecting would silently suppress real vulns and violate P5. Loops are monotone -- fixpoint with a bound, never unroll.
- Determinism is fragile: (file, line, column, detector_id) is not a total order (one sink, two sources collide). Add a final tie-break on a stable witness fingerprint, and select witnesses by shortest-path-then-lexicographic-location. Sort all spec/source/sink iteration and the summary worklist; never depend on dict/set/filesystem order (P3).
- Implicit/control-dependence flows (if tainted: x = 'a' else: x = 'b') are explicitly OUT OF SCOPE -- tracking them explodes false positives. Track explicit data flow only and say so (P7).
- Performance: recursion and large SCCs need a bounded fixpoint iteration cap; an uncapped access-path lattice or unbounded summary growth can be quadratic-to-exponential. Cap path depth, cap fixpoint iterations, and memoize summaries.
- Sink arg-restriction and when-constraints must be respected precisely: os.system flags only arg 0; subprocess.* flags only when shell=True. Matching the call but ignoring args/when produces false positives and erodes trust.

## sources
- PyT / python-taint (github.com/python-security/pyt) -- stdlib ast -> CFG -> fixpoint dataflow, trigger words (sources/sinks/sanitizers), blackbox_mapping.json function summaries; the closest open analog (now unmaintained, recommends Pysa)
- Semgrep taint mode (semgrep.dev/docs/writing-rules/data-flow/taint-mode) -- first-class sources/sinks/sanitizers/propagators with from/to and by-side-effect, per-variable field-sensitive tracking that ignores aliasing, constant-index subscripts, taint labels with requires; --pro-intrafile is exactly the v1 intra-file interprocedural scope
- Meta Pysa / Pyre (pyre-check.org/docs/pysa-basics, pysa-implementation-details) -- whole-call-graph TITO (taint-in-taint-out) function summaries and source/sink models; the model for summaries, used here as the deliberately-narrowed (intra-file) and out-of-scope (cross-file/whole-program) contrast
- CodeQL taint tracking (codeql.github.com data-flow docs) -- access-path / (CFG node, context, taint) representation and unified isBarrier sanitizers; access-path concept informs attribute/container taint; whole-program IFDS/IDE engine is the out-of-scope contrast (and the proprietary internals CLAUDE.md forbids copying)
- Bandit (PyCQA) -- pattern-only ast visitors with NO dataflow; the contrast for what to avoid (higher false-positive rate, no witness/taint propagation)


# SUBSYSTEM SPECS (8)

==========================================================================================
## COMPONENT: DSL parser & validation

**Summary:** Implement `parse_spec(text, *, source_path)` in `src/scanipy/dsl/parser.py`: turn a detector's YAML text into a validated, frozen `DetectorSpec` (the single source of all detection logic, P4). It must validate every field shape, enum, and pattern/flow grammar; reject any unknown key or kind; and raise a `DSLError` that names the spec id, the offending field, and a 1-based source line/column. It also wires `registry.load_builtin_detectors()` to parse every bundled `*.yml` at boot in deterministic order (P3), and implements the `parameter` and `import` pattern kinds that the reference currently marks PLANNED. No new runtime deps: stdlib + the already-present `pyyaml`.

**Key files:** src/scanipy/dsl/parser.py (implement parse_spec, load_spec_file, DSLError; add internal node-walk helpers), src/scanipy/registry.py (implement load_builtin_detectors to parse all discover_spec_files() in sorted order), src/scanipy/dsl/patterns.py (no change to dataclasses; PatternKind already has CALL/ATTRIBUTE/PARAMETER/IMPORT), src/scanipy/dsl/spec.py (no change; DetectorSpec is the target type), docs/dsl-reference.md (promote parameter/import from PLANNED to supported; document DSLError format, when/args validity per kind, flow grammar, keyword-value coercion), tests/unit/test_dsl_parser.py (NEW — happy-path, every rejection, location precision, parameter/import kinds, determinism), tests/unit/test_registry.py (NEW — load_builtin_detectors parses all bundled specs, returns sorted unique ids), tests/fixtures/dsl/invalid/*.yml (NEW — corpus of malformed specs, one failure mode each), tests/fixtures/dsl/valid/*.yml (NEW — minimal valid specs incl. parameter/import kinds)

**Interfaces:**
```
Existing types consumed (unchanged):
- DetectorSpec(id:str, name:str, cwe:str, severity:Severity, languages:tuple[str,...], message:str, sources:tuple[Pattern,...], sinks:tuple[Pattern,...], sanitizers:tuple[Pattern,...]=(), propagators:tuple[Propagator,...]=(), metadata:Mapping[str,object]=...)  # src/scanipy/dsl/spec.py
- Pattern(kind:PatternKind, pattern:str, args:tuple[int,...]|None=None, when:Mapping[str,object]|None=None)  # frozen
- PatternKind: CALL="call" | ATTRIBUTE="attribute" | PARAMETER="parameter" | IMPORT="import"
- Flow(from_:str, to:str); Propagator(pattern:Pattern, flow:Flow)
- Severity.from_str(str)->Severity ; values low/medium/high/critical

New/changed signatures (this component):
# src/scanipy/dsl/parser.py
class DSLError(ValueError):
    def __init__(self, message: str, *, spec_id: str|None=None, field: str|None=None,
                 source_path: str|None=None, line: int|None=None, column: int|None=None) -> None: ...
    # attrs: .spec_id .field .source_path .line .column ; str(self) == formatted single line

def parse_spec(text: str, *, source_path: str|None = None) -> DetectorSpec: ...   # raises DSLError
def load_spec_file(path: str|Path) -> DetectorSpec: ...                            # unchanged sig

# internal (module-private), typed for mypy --strict:
@dataclass(frozen=True)
class _Ctx: spec_id: str|None; source_path: str|None
def _err(message:str, *, ctx:_Ctx, node:"yaml.nodes.Node|None"=None, field:str|None=None) -> DSLError: ...
def _as_mapping(node:"yaml.nodes.Node", *, ctx:_Ctx, field:str|None=None) -> "dict[str, yaml.nodes.Node]": ...
def _scalar_value(node:"yaml.nodes.ScalarNode") -> str|bool|int|None: ...
def _parse_pattern(node, field:str, idx:int, *, ctx:_Ctx) -> Pattern: ...
def _parse_when(node, field:str, *, ctx:_Ctx) -> "Mapping[str, object]": ...
def _parse_propagator(node, idx:int, *, ctx:_Ctx) -> Propagator: ...
def _validate_pattern_string(value:str, kind:PatternKind) -> None: ...
def _validate_flow_token(value:str) -> None: ...

# src/scanipy/registry.py
def load_builtin_detectors() -> tuple[DetectorSpec, ...]: ...  # parses all, sorted by id, unique ids

Constants:
_REQUIRED_TOP = ("id","name","cwe","severity","languages","message","sources","sinks")
_OPTIONAL_TOP = ("sanitizers","propagators","metadata")
_PATTERN_KEYS = {"kind","pattern","args","when"}
_PROP_KEYS = {"kind","pattern","args","when","flow"}
_FLOW_TOKENS = {"any-arg","self","return"}  # plus regex arg:\d+
_DOTTED_RE = re.compile(r"^(\*|[A-Za-z_][A-Za-z0-9_]*)(\.(\*|[A-Za-z_][A-Za-z0-9_]*))*$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_ARG_FLOW_RE = re.compile(r"^arg:\d+$")
```

**Design:**
ALGORITHM (parse_spec)

Phase 0 — YAML load with location tracking.
Do NOT call only yaml.safe_load (it discards positions). Instead compose the node tree once and walk it so every value carries its 1-based line / 0-based column for error reporting (verified empirically: yaml.compose(text) returns nodes whose .start_mark.line is 0-based and .column 0-based; add 1 to line for human output).
- root = yaml.compose(text). Catch yaml.YAMLError -> raise DSLError("not valid YAML: <msg>", location from exc.problem_mark if present else (1,0)). Never let a raw yaml exception escape.
- If root is None (empty doc) -> DSLError("empty spec", line 1). If root is not a MappingNode -> DSLError("top level must be a mapping", at root.start_mark).
- Build a small internal Node API: `_as_mapping(node) -> dict[str, Node]` converts a MappingNode to an ordered dict of str-key -> child node, raising DSLError on a non-string key or a duplicate key (using the key node's mark). Keep CHILD NODES (not plain values) so nested validators report precise locations. Provide `_as_list(node)`, `_as_str(node)`, `_as_bool(node)`, `_as_int(node)`, and `_scalar_value(node)` helpers that construct the python value via node-tag-aware conversion and raise DSLError("expected <type>, got <actual>") with the node's mark on mismatch.
- `_scalar_value(node)` switches on the resolved node.tag: tag:yaml.org,2002:str -> node.value (str); :bool -> YAML 1.1 truthy/falsy mapping; :int -> int(node.value, 0); :null -> None. This keeps full control of types so e.g. `severity: yes` (a YAML bool) does NOT silently pass as a string.

Phase 1 — top-level field validation.
- Parse `id` FIRST (required, str, non-empty/non-whitespace). Capture it into a `_Ctx` so EVERY subsequent DSLError carries spec_id. Convention <language>.<class>.<name> is recommended but only non-empty is ENFORCED.
- REQUIRED keys: id, name, cwe, severity, languages, message, sources, sinks. OPTIONAL: sanitizers (default ()), propagators (default ()), metadata (default {}).
- ALLOWED = required ∪ optional. Iterate the literal document keys IN ORDER; first key not in ALLOWED -> DSLError("unknown top-level field '<k>'", field=k, at that key's mark) (first offending = lowest line = deterministic, P3). Any missing required key -> DSLError("missing required field '<k>'", field=k, at root mark).
- name/message: non-empty str. cwe: str matching ^CWE-\d+$ -> else DSLError("cwe must look like 'CWE-79', got '<v>'"). severity: str; validate against the 4 lowercase values then Severity.from_str(v); on failure DSLError("severity must be one of low|medium|high|critical, got '<v>'"); store the Severity enum. languages: non-empty list of str where every element == "python" (P7 honest scope) else DSLError("unsupported language '<v>'; v1 supports: python"); store tuple. metadata: optional mapping, free-form nested scalars/lists/maps via full safe construction of that subtree; wrap result in types.MappingProxyType (DetectorSpec.metadata is typed Mapping); preserve YAML document order (do NOT sort).

Phase 2 — pattern lists.
- sources, sinks: non-empty lists (else DSLError "<field> must have at least one pattern"). sanitizers: list, may be [] (P5 — a missing sanitizer must never raise). For each element call _parse_pattern(node, field, idx, ctx). propagators: list, may be empty; each via _parse_propagator.

_parse_pattern(node, field, idx, ctx) -> Pattern:
- node must be a mapping. ALLOWED_PATTERN_KEYS = {kind, pattern, args, when}; any unknown key -> DSLError("unknown pattern field '<k>' in <field>[<idx>]").
- kind: required str -> PatternKind(value); else DSLError("unknown pattern kind '<v>'; valid: call, attribute, parameter, import", field=f"{field}[{idx}].kind").
- pattern: required non-empty str; validate via _validate_pattern_string(value, kind).
- args: optional; valid ONLY on kind==call (restricts positional argument indices). On attribute/import/parameter -> DSLError("'args' is only valid on kind: call"). Value: non-empty list of ints each >= 0 ("args must list at least one index"); duplicates collapsed deterministically (sorted, unique); store tuple[int,...]; default None.
- when: optional; valid ONLY on kind==call. On other kinds -> DSLError. Validate via _parse_when. Store Mapping|None.
- Construct Pattern(kind, pattern, args, when) (frozen; args tuple|None, when MappingProxyType|None).

_validate_pattern_string(value, kind):
- Dotted grammar for call/attribute/import/parameter: one or more '.'-separated segments, each either '*' (wildcard) or a Python-identifier token. _DOTTED_RE = ^(\*|[A-Za-z_][A-Za-z0-9_]*)(\.(\*|[A-Za-z_][A-Za-z0-9_]*))*$. Reject empty/leading/trailing/double dots, spaces, parens, brackets.
- kind==parameter: same dotted grammar; a bare name (request) or a function-scoped selector (handler.request) both validate (engine semantics out of scope here; we validate SHAPE only).
- kind==import: dotted module path possibly ending in '*' (os, subprocess.run, flask.*). Same grammar.
- On violation -> DSLError("invalid pattern '<v>': <reason>", field=f"{field}[{idx}].pattern").

_parse_when(node, field, ctx) -> Mapping:
- when must be a mapping with exactly ONE top key: keyword. Any other key -> DSLError("unknown 'when' condition '<k>'; v1 supports: keyword").
- when.keyword is a mapping of {arg-name: required-value}. arg-name: non-empty valid python identifier (else reject). value: a scalar (bool/int/str/None) via _scalar_value; nested maps/lists -> DSLError("when.keyword values must be scalars"). Build {"keyword": {name: value}} preserving the canonical nested shape the engine reads (os-command uses when:{keyword:{shell:true}} -> {"keyword":{"shell":True}}). Wrap nested in MappingProxyType.

_parse_propagator(node, idx, ctx) -> Propagator:
- node mapping; ALLOWED = {kind, pattern, args, when, flow}; flow REQUIRED. Reuse _parse_pattern on the {kind,pattern,args,when} subset; restrict propagator kind to call (else DSLError "propagators must be kind: call"). flow REQUIRED mapping with exactly {from, to} (YAML key 'from' maps to dataclass field from_).
- from/to each via _validate_flow_token: allowed = {any-arg, self, return} or ^arg:\d+$ (arg:N, 0-based). Bad token -> DSLError("invalid flow token '<v>'; valid: any-arg, arg:N, self, return", field=f"propagators[{idx}].flow.from").
- Construct Flow(from_=<from>, to=<to>) then Propagator(pattern, flow).

Phase 3 — assemble + return.
- sources/sinks non-empty (re-confirmed); sanitizers/propagators optional. Return DetectorSpec(id, name, cwe, severity, languages, message, sources=tuple, sinks=tuple, sanitizers=tuple, propagators=tuple, metadata=MappingProxyType). The only hard closure rules are >=1 source and >=1 sink; never require a sanitizer (P5).

DSLError DESIGN (extend the existing `class DSLError(ValueError)`):
- __init__(self, message, *, spec_id=None, field=None, source_path=None, line=None, column=None). Compose the super() message as one human line: f"{source_path or '<spec>'}:{line}:{column}: [{spec_id or '?'}] {field+': ' if field else ''}{message}". Keep raw fields as attributes for programmatic use (CLI rules validate + tests assert on them). Keeps DSLError('msg') call sites working. The message is a pure function of inputs (P3).
- A private _err(message, *, ctx, node=None, field=None) centralizes construction: pulls spec_id/source_path from the threaded _Ctx and line/column from node.start_mark (line+1, column) when given, else (1,0). EVERY raise goes through _err so format is uniform.

ERROR-REPORTING ORDER (P3): validate top-level keys in DOCUMENT order (first offending key wins); validate list elements in index order. Never iterate Python sets for validation order. Same text -> same first error.

load_spec_file(path): unchanged signature; read UTF-8 text and call parse_spec(text, source_path=str(p)). Let OS errors (FileNotFoundError) propagate.

registry.load_builtin_detectors():
- specs = [load_spec_file(p) for p in discover_spec_files()] (already sorted Paths -> deterministic).
- Enforce GLOBAL id uniqueness: build id->path; duplicate -> DSLError("duplicate detector id '<id>' in <path> (already defined in <other>)") to protect the engine from nondeterministic detector selection.
- Return tuple(specs) sorted by spec.id (P3). functools.cache over immutable package data is acceptable; if used, expose cache_clear for test isolation.

MYPY/RUFF: mypy --strict — annotate every helper; yaml.compose returns yaml.nodes.Node|None; narrow via isinstance against MappingNode/SequenceNode/ScalarNode from yaml.nodes (types-PyYAML is a dev dep). ruff S (bandit) is on for src — use only SafeLoader paths (yaml.compose, yaml.safe_load); never yaml.load with a full Loader (avoids S506). Double quotes, line-length 100, SPDX header on every file.

**Tasks:**
- (S) DSL_PARSER_1: DSLError carries spec id + field + source location
    Extend DSLError.__init__ in src/scanipy/dsl/parser.py with keyword-only spec_id/field/source_path/line/column attributes; format a single deterministic human line for super().__init__; keep it a ValueError subclass and keep the bare DSLError('msg') form working. Add the private _Ctx dataclass and _err() helper that builds DSLError from a node mark (line+1, 0-based column) and the threaded context. SPDX header preserved.
- (M) DSL_PARSER_2: YAML node-tree loader with location tracking [deps: DSL_PARSER_1]
    Implement Phase 0: yaml.compose(text) wrapped in try/except yaml.YAMLError->DSLError (use exc.problem_mark when present). Implement _as_mapping (string keys only, no duplicates), _as_list, _scalar_value(ScalarNode) switching on node.tag for str/bool/int/null per YAML 1.1, and isinstance narrowing against yaml.nodes.MappingNode/SequenceNode/ScalarNode for mypy --strict. Reject empty doc and non-mapping root.
- (M) DSL_PARSER_3: Top-level field validation (required/optional/unknown/enums) [deps: DSL_PARSER_2]
    Implement Phase 1: parse id first into _Ctx; enforce required set, optional defaults, reject unknown top-level keys in document order; validate name/message non-empty, cwe via _CWE_RE, severity via the 4-value check + Severity.from_str, languages non-empty list of 'python' only (P7), metadata free-form mapping via safe construction wrapped in MappingProxyType (order preserved).
- (L) DSL_PARSER_4: Pattern parsing + dotted/wildcard grammar + args + when [deps: DSL_PARSER_3]
    Implement _parse_pattern, _validate_pattern_string (_DOTTED_RE; kind-specific rules), args (call-only, non-neg int list, sorted-unique tuple), and _parse_when (only 'keyword'; scalar values only). Reject unknown pattern keys and args/when on kinds where they are invalid. Build Pattern with frozen tuple/MappingProxyType values.
- (M) DSL_PARSER_5: Implement parameter & import pattern kinds (lift from PLANNED) [deps: DSL_PARSER_4]
    Within _parse_pattern accept kind: parameter and kind: import and validate their pattern strings per grammar (parameter: bare name or dotted selector; import: dotted module path with optional trailing *). Update docs/dsl-reference.md kind table to mark both supported and document their pattern shapes and that args/when do not apply. This component validates SHAPE only; engine semantics are separate.
- (M) DSL_PARSER_6: Propagator parsing + flow vocabulary [deps: DSL_PARSER_4]
    Implement _parse_propagator and _validate_flow_token. flow required, exactly {from,to}, tokens in {any-arg,self,return} or arg:N; map YAML 'from' to Flow.from_. Reuse _parse_pattern for the {kind,pattern,args,when} subset; restrict propagator kind to call. Reject unknown propagator/flow keys.
- (M) DSL_PARSER_7: Assemble + return DetectorSpec; finalize parse_spec/load_spec_file [deps: DSL_PARSER_3, DSL_PARSER_4, DSL_PARSER_5, DSL_PARSER_6]
    Wire Phases 0-3 together in parse_spec: build sources/sinks (non-empty), sanitizers/propagators (optional), return DetectorSpec with frozen tuples and MappingProxyType metadata. Confirm load_spec_file unchanged. Remove the NotImplementedError. Ensure mypy --strict + ruff (incl. S, line-length 100, double quotes) pass.
- (S) DSL_PARSER_8: Wire registry.load_builtin_detectors [deps: DSL_PARSER_7]
    Implement load_builtin_detectors(): parse every discover_spec_files() path via load_spec_file in sorted order, enforce global id uniqueness (DSLError on duplicate naming both paths), return tuple sorted by spec.id (P3). Optional functools.cache over immutable package data with cache_clear for tests.
- (S) DSL_PARSER_9: Validate bundled specs parse + reconcile DSL surface [deps: DSL_PARSER_8]
    Run load_builtin_detectors against os-command.yml and sql.yml; confirm they parse to the expected DetectorSpec (kinds, args:[0], when:{keyword:{shell:true}}, propagators flow any-arg->return). If the engine component requires new DSL surface (kwarg-targeted args, by-side-effect flow), ensure it is reflected here OR explicitly deferred; do not silently special-case (P4).
- (L) DSL_PARSER_10: Test suite: parser happy-path + every rejection + locations [deps: DSL_PARSER_7]
    Add tests/unit/test_dsl_parser.py and tests/fixtures/dsl/{valid,invalid}/*.yml covering: full valid spec roundtrip; each required-field-missing; unknown top-level key; unknown pattern kind; bad severity/cwe/language; empty sources/sinks; bad dotted pattern; args on non-call; args non-int/negative; when unknown condition / non-scalar value; bad flow token; parameter+import valid; duplicate keys; non-mapping root; empty doc; invalid YAML; DSLError.spec_id/field/line assertions; determinism (same text -> identical DetectorSpec; first-error stability).
- (M) DSL_PARSER_11: Test suite: registry loader + bundled-pack invariants [deps: DSL_PARSER_8]
    Add tests/unit/test_registry.py: load_builtin_detectors() parses all bundled specs, ids unique and sorted, count matches discover_spec_files(), every spec has >=1 source and >=1 sink; duplicate-id fixture raises DSLError (tmp detectors dir or monkeypatch discover_spec_files + cache_clear).
- (S) DSL_PARSER_12: Docs: dsl-reference + CHANGELOG for parser landing [deps: DSL_PARSER_5, DSL_PARSER_7]
    Update docs/dsl-reference.md: promote parameter/import to supported, document DSLError format (path:line:col: [id] field: message), the validity matrix of args/when per kind, the flow grammar, and language=python-only v1 scope. Add a CHANGELOG entry. Version bump and CI are handled by the release/merge milestone, not here.

**acceptance_criteria:**
- parse_spec(valid_text) returns a fully-populated frozen DetectorSpec; os-command.yml and sql.yml both parse and round-trip to the expected Pattern/Propagator/Flow values (call/attribute kinds, args:[0], when:{keyword:{shell:true}}, flow any-arg->return).
- Every malformed spec raises DSLError (never NotImplementedError, bare ValueError, KeyError, or a leaking yaml exception); the DSLError str is path:line:col: [spec_id] field: message and the .spec_id/.field/.line attributes are set whenever derivable.
- All four pattern kinds validate: call/attribute/import/parameter; docs/dsl-reference.md no longer marks parameter/import as PLANNED.
- Unknown top-level keys, unknown pattern keys, unknown 'when' conditions, unknown flow keys, and unknown kinds are each rejected with a precise field-named DSLError.
- args is accepted only on kind: call (non-negative int list, sorted-unique); when is accepted only on kind: call; both rejected elsewhere. when supports exactly {keyword: {name: scalar}}.
- Flow tokens are limited to any-arg | self | return | arg:N (N a non-negative int); YAML 'from' maps to Flow.from_.
- sources and sinks are required and non-empty; sanitizers/propagators optional and default to empty tuples; a missing sanitizer never raises (P5).
- registry.load_builtin_detectors() parses every bundled *.yml in deterministic order, enforces globally-unique ids, and returns a tuple sorted by id (P3). Existing test_bundled_specs_are_discoverable still passes.
- Determinism (P3): parsing the same text twice yields equal DetectorSpec objects; when multiple errors exist, the reported one is stable (first offending key in document order / lowest list index).
- Declarative (P4): parser/registry contain zero per-detector or per-CWE logic; all detection knowledge stays in YAML. No new runtime dependency beyond pyyaml.
- ruff (line-length 100, double quotes, incl. S bandit rules), mypy --strict on src/, and pytest all pass; SPDX header present on every new/changed .py file.

**tests:**
- test_parse_minimal_valid_spec: smallest legal spec (id/name/cwe/severity/languages/message + 1 source + 1 sink) -> DetectorSpec with correct enum/tuple types.
- test_parse_bundled_os_command: load_spec_file(os-command.yml) -> sources include attribute flask.request.*; sinks include call os.system args=(0,) and subprocess.* when={'keyword':{'shell':True}}; sanitizer shlex.quote; propagators flow any-arg->return.
- test_parse_bundled_sql: sql.yml -> empty sanitizers tuple, sinks *.cursor.execute args=(0,).
- test_missing_required_field (parametrized over id/name/cwe/severity/languages/message/sources/sinks): raises DSLError with .field set.
- test_unknown_top_level_key_rejected: extra key -> DSLError naming the key; line points at the key.
- test_unknown_pattern_kind_rejected and test_unknown_pattern_field_rejected.
- test_bad_severity / test_bad_cwe / test_unsupported_language: precise DSLError messages.
- test_empty_sources_rejected / test_empty_sinks_rejected; test_empty_sanitizers_ok ([] allowed).
- test_dotted_pattern_grammar (parametrized): accepts os.system, subprocess.*, *.cursor.execute, flask.request.*; rejects '', 'os..system', '.os', 'os.', 'os system', 'os.sys(tem)'.
- test_args_only_on_call: args on attribute/import/parameter -> DSLError; args non-int / negative / empty -> DSLError; args sorted+deduped to tuple.
- test_when_only_on_call and test_when_keyword_only: unknown 'when' key rejected; when keyword non-scalar value rejected; shell:true -> {'keyword':{'shell':True}}; shell:'true' stays str.
- test_flow_vocabulary (parametrized): any-arg/self/return/arg:0 accepted; arg:x, returns, '' rejected; 'from' maps to Flow.from_.
- test_parameter_kind_valid and test_import_kind_valid: bare name + dotted forms accepted.
- test_duplicate_top_level_key_rejected / test_non_mapping_root_rejected / test_empty_document_rejected / test_invalid_yaml_rejected (all DSLError; none leak yaml errors).
- test_dslerror_str_format: contains source_path, 1-based line, spec id, and field.
- test_determinism: parse same text twice -> equal DetectorSpec; first-error stability when two errors present.
- test_load_builtin_detectors: returns tuple sorted by id; all ids unique; count matches discover_spec_files(); each spec has >=1 source and >=1 sink.
- test_load_builtin_duplicate_id_rejected: two fixture specs sharing an id -> DSLError (tmp detectors dir or monkeypatch discover_spec_files + cache_clear).
- fixtures: tests/fixtures/dsl/valid/*.yml (incl. parameter+import samples) and tests/fixtures/dsl/invalid/*.yml (one failure mode per file) — DSL DATA mirroring the tests/fixtures lint-exclude convention.

**risks:**
- YAML location fidelity: error line/column comes from a node .start_mark; for inline flow-style maps or anchors the mark may point at the container rather than the exact scalar. Mitigation: always pass the most specific available node to _err; assert location loosely (line only) in tests.
- Scalar typing traps (YAML 1.1): bare yes/no/on/off resolve to bools and null to None; severity: yes must NOT become a string True. Mitigation: _scalar_value switches on the resolved node.tag and severity/cwe/etc demand tag:str; add explicit tests.
- when.keyword value coercion: shell: true (bool) vs shell: 'true' (str) must stay distinguishable for the engine's shell=True check. Mitigation: preserve the YAML-resolved scalar type exactly; document and test both.
- parameter/import shape vs engine semantics: this component validates shape only; the engine must agree on the pattern meaning. Risk of drift. Mitigation: document the agreed grammar in dsl-reference.md and coordinate via DSL_PARSER_9 before the engine relies on these kinds.
- DSL may need to grow for the engine (kwarg-targeted args, by-side-effect from:self->arg:N) per prior-art; later additions risk churn. Mitigation: centralize _PATTERN_KEYS/_PROP_KEYS and flow grammar as constants so an extension is one localized change; reject-unknown-now keeps old specs valid.
- mypy --strict + types-PyYAML: yaml.nodes typings can be loose; narrowing may need isinstance plus typed locals. Mitigation: prefer isinstance narrowing; scope any unavoidable type: ignore tightly (warn_unused_ignores is on).
- Metadata determinism: free-form metadata ordering must be stable for future fingerprinting. Mitigation: preserve YAML document order (insertion-ordered dict), wrap in MappingProxyType, do not sort.
- functools.cache on load_builtin_detectors can break test isolation when discover_spec_files is monkeypatched. Mitigation: skip the cache or expose cache_clear and call it in the duplicate-id test.

**open_questions:**
- parameter-kind pattern grammar: canonical form a bare param name (request), a function-scoped selector (handler.request), or both? Needs engine sign-off so validation matches engine resolution. Spec assumes both, same dotted grammar, for v1.
- import-kind semantics: does pattern name the imported module path (subprocess.run) or the local bound name? Shape validation is identical either way; the reference should state the intended meaning to avoid detector-author confusion.
- Language enforcement hard (reject non-python now, per P7) or soft (accept and ignore)? Spec assumes HARD reject for honesty; confirm this won't block a future in-tree multi-language spec.
- id format: strict <language>.<class>.<name> regex or just non-empty + globally-unique? Spec assumes non-empty + unique (convention recommended, not enforced); confirm.
- Multi-document YAML (--- separated) per file or exactly one detector per file? Spec assumes exactly one (yaml.compose, single root); confirm bundled-pack convention.
- Does the engine need by-side-effect propagator flow (from: self -> to: arg:N) or kwarg-targeted args in v1? If yes, add to flow/args grammar now; if deferred, keep rejected. Cross-component decision with the engine spec.

==========================================================================================
## COMPONENT: Python frontend & IR (AST→IR for taint analysis)

**Summary:** PythonFrontend.parse turns one .py file into a normalized, detector-agnostic, frozen-dataclass IR built from stdlib `ast`: a per-module import/alias table, a module-as-scope plus a function table (def/async def/lambda, nested scopes linked to parents), per-function statement lists with a simple basic-block CFG, and normalized expression/statement nodes (Call with canonical-dotted callee + ordered positional args + keyword args with preserved literal values + receiver expr, Attribute chains, Name refs, literals, assignments with full binder coverage, returns, imports). Import/alias resolution canonicalizes every Name/Attribute to a dotted path so `import os`, `from os import system`, `import os as o`, and `import os.path as p` all match the dotted DSL patterns. Every IR node carries a `models.Location` so the engine can build witness steps without ever touching raw `ast`. Syntax/decoding errors are handled gracefully (file skipped, no crash). This layer holds zero taint/detector knowledge (P4): the engine owns all taint logic and consumes this IR + the CFG defined here.

**Key files:** src/scanipy/frontends/ir.py (NEW — frozen-dataclass IR: IRModule, IRScope/IRFunction, IRParam, IRBlock, statements, expressions, ImportTable), src/scanipy/frontends/resolver.py (NEW — import/alias resolution: build ImportTable from ast, canonicalize Name/Attribute to dotted paths), src/scanipy/frontends/python_frontend.py (REWRITE stub — PythonFrontend.parse: read+ast.parse, lower to IRModule, return None on failure), src/scanipy/frontends/base.py (EDIT — narrow Frontend.parse return annotation from `object` to `IRModule | None`), src/scanipy/frontends/__init__.py (EDIT — export PythonFrontend and the IR public types), tests/unit/test_frontend_ir.py (NEW — IR-construction + resolver + error-handling unit tests), tests/fixtures/python/ir/ (NEW — small .py inputs used only by frontend unit tests, analysis DATA), docs/ir-reference.md (NEW — documents the IR contract + CFG + documented unsoundness/out-of-scope, P7)

**Interfaces:**
```
All under src/scanipy/frontends/. Reuse scanipy.models.Location verbatim.

# base.py (narrowed)
class Frontend(ABC):
    language: str
    @abstractmethod
    def parse(self, path: Path) -> "IRModule | None": ...

# python_frontend.py
class PythonFrontend(Frontend):
    language = "python"
    def parse(self, path: Path) -> IRModule | None: ...   # None = skipped (syntax/decode/IO error)

# ir.py (frozen dataclasses)
@dataclass(frozen=True)
class ImportEntry:
    local_name: str; canonical: str; kind: str  # "module" | "name"
    asname: str | None; location: Location
@dataclass(frozen=True)
class ImportTable:
    entries: tuple[ImportEntry, ...]
    def resolve(self, local_name: str) -> ImportEntry | None: ...

@dataclass(frozen=True)
class IRParam:
    name: str; index: int; kind: str; location: Location; has_default: bool = False
@dataclass(frozen=True)
class IRFunction:
    name: str; qualname: str; params: tuple[IRParam, ...]
    body_blocks: tuple["IRBlock", ...]; entry_block_index: int
    parent_index: int | None; is_lambda: bool; is_async: bool
    location: Location; local_imports: ImportTable
@dataclass(frozen=True)
class IRBlock:
    index: int; statements: tuple["Stmt", ...]; successors: tuple[int, ...]
@dataclass(frozen=True)
class IRModule:
    path: str; imports: ImportTable
    module_scope: IRFunction; functions: tuple[IRFunction, ...]

# Expr / Stmt / Target are typing.Union aliases over the frozen dataclasses below.
@dataclass(frozen=True)
class IRCall:
    callee: "Expr"; callee_path: str | None; receiver: "Expr | None"
    args: tuple["Expr", ...]; kwargs: tuple["IRKeyword", ...]; location: Location
@dataclass(frozen=True)
class IRKeyword:
    name: str | None; value: "Expr"; location: Location
@dataclass(frozen=True)
class IRName:
    name: str; canonical: str | None; location: Location
@dataclass(frozen=True)
class IRAttribute:
    value: "Expr"; attr: str; canonical: str | None; location: Location
@dataclass(frozen=True)
class IRLiteral:
    value: object; is_constant: bool; location: Location
@dataclass(frozen=True)
class IRAssign:
    targets: tuple["Target", ...]; value: "Expr"; is_aug: bool; location: Location
@dataclass(frozen=True)
class IRReturn:
    value: "Expr | None"; location: Location
# plus: IRBinOp, IRBoolOp, IRIfExp, IRJoinedStr, IRFormattedValue, IRContainer,
#       IRComprehension, IRSubscript(is_const_index,const_index), IRStarred,
#       IRLambda, IRUnknown(raw_repr); targets IRNameTarget/IRAttrTarget/
#       IRSubscriptTarget/IRTupleTarget/IRStarTarget; stmt IRExprStmt/IRImportStmt.

# resolver.py
def build_import_table(nodes: Iterable[ast.stmt]) -> ImportTable: ...
def canonical_dotted(expr: ast.expr, table: ImportTable) -> str | None: ...

# __init__.py exports: PythonFrontend, IRModule, IRFunction, IRBlock, IRCall,
#   IRName, IRAttribute, IRLiteral, IRParam, ImportTable, ImportEntry, Expr, Stmt, Target.
```

**Design:**
 

**Tasks:**
- (M) FRONTEND_IR_1: Define the IR dataclasses (ir.py)
    Create src/scanipy/frontends/ir.py with SPDX header. Define all frozen dataclasses: ImportEntry, ImportTable(.resolve), IRParam, IRFunction, IRBlock, IRModule, the Expr union members (IRName, IRAttribute, IRCall, IRKeyword, IRLiteral, IRBinOp, IRBoolOp, IRIfExp, IRJoinedStr, IRFormattedValue, IRContainer, IRComprehension, IRSubscript, IRStarred, IRLambda, IRUnknown), the Stmt union members (IRAssign, IRExprStmt, IRReturn, IRImportStmt, IRDelete), and Target members (IRNameTarget, IRAttrTarget, IRSubscriptTarget, IRTupleTarget, IRStarTarget). Define Expr/Stmt/Target as typing.Union aliases. Every node carries scanipy.models.Location. Full type hints; mypy --strict clean. No ast import here.
- (M) FRONTEND_IR_2: Import/alias resolution (resolver.py) [deps: FRONTEND_IR_1]
    Create src/scanipy/frontends/resolver.py. build_import_table(nodes) handles ast.Import (incl. dotted `import os.path`, `as`), ast.ImportFrom (incl. `as`, relative dots recorded but unresolved, star-import wildcard marker). canonical_dotted(expr, table) maps ast.Name/ast.Attribute to a dotted string: imported names rewritten to canonical prefix; local vars left bare; non-name/attr callees -> None. Deterministic: emit ImportTable.entries in source order. Unit-testable in isolation.
- (L) FRONTEND_IR_3: Expression lowering (ast.expr -> Expr) [deps: FRONTEND_IR_1, FRONTEND_IR_2]
    Add an expression lowerer (in python_frontend.py or a lower.py) that converts every ast.expr to the IR Expr, attaching Location (lineno/col_offset/end_lineno/end_col_offset) and, for Name/Attribute/Call, the resolver-computed canonical/callee_path. Calls: split callee_path, receiver (callee.value when Attribute), positional args (ordered), kwargs (IRKeyword with preserved IRLiteral values; name=None for **). Preserve constant values for literals. Map BinOp/BoolOp/IfExp/JoinedStr/FormattedValue/container/subscript(const-index detection)/Starred/Lambda. Unknown node types -> IRUnknown. Pass the active scope's chained ImportTable for resolution.
- (M) FRONTEND_IR_4: Binder/target lowering (full inventory) [deps: FRONTEND_IR_1, FRONTEND_IR_3]
    Lower assignment targets and all binding constructs: Assign, AnnAssign(with value), AugAssign(is_aug, reads+writes LHS), tuple/star unpack (IRTupleTarget/IRStarTarget), attribute target (IRAttrTarget), subscript target (IRSubscriptTarget), for-target, with...as, except...as, walrus NamedExpr (synthetic IRAssign), comprehension targets (in nested scope). Verify none of these are dropped.
- (L) FRONTEND_IR_5: Statement lowering + minimal CFG builder [deps: FRONTEND_IR_1, FRONTEND_IR_3, FRONTEND_IR_4]
    Lower ast.stmt sequences into IRBlocks with successor edges. Split blocks at If/For/While/With/Try boundaries; create join blocks (>1 predecessor) for the engine to union at. Emit test/iter/context-manager exprs as IRExprStmt so calls inside conditions/loops are seen. For/While back-edges to the loop header (engine fixpoints; no unrolling). Try/except: edges from the try body to each handler and to finally. Return/break/continue end a block. Linear straight-line code = a single block. Numbered in creation order (determinism).
- (M) FRONTEND_IR_6: Scope/function table + module-as-scope [deps: FRONTEND_IR_2, FRONTEND_IR_4, FRONTEND_IR_5]
    Walk the module pre-order: build the synthetic module_scope '<module>' (top-level statements), then every FunctionDef/AsyncFunctionDef/Lambda/comprehension-implied scope as its own IRFunction with params (IRParam incl. posonly/kwonly/vararg/kwarg + has_default), parent_index closure link, and per-scope local_imports chained to parents->module. Emit IRModule.functions in deterministic source order.
- (S) FRONTEND_IR_7: PythonFrontend.parse wiring + graceful errors [deps: FRONTEND_IR_6]
    Rewrite python_frontend.py PythonFrontend.parse: read via tokenize.open (PEP-263), ast.parse(filename=str(path)); on SyntaxError/UnicodeDecodeError/OSError/ValueError return None (no raise); else lower to IRModule. Narrow Frontend.parse annotation in base.py to `IRModule | None`. Update frontends/__init__.py exports. Confirm engine never needs to import ast.
- (S) FRONTEND_IR_8: IR contract docs (docs/ir-reference.md) [deps: FRONTEND_IR_7]
    Document the IR contract: node inventory, CFG semantics (blocks/edges/joins, who owns it = frontend, engine consumes), Location semantics, canonicalization rules with the four import styles + value-rooted suffixes, the error/skip contract, and the documented unsoundness/out-of-scope items (aliasing, implicit flows, closures, dynamic/star imports) for P7. Link from CLAUDE.md repo map and docs index.
- (M) FRONTEND_IR_9: Frontend/IR unit tests [deps: FRONTEND_IR_7]
    Create tests/unit/test_frontend_ir.py and small inputs under tests/fixtures/python/ir/. Cover the test list in `tests`. These are IR-construction tests, NOT detector TP/TN fixtures (those belong to detector-author).

**acceptance_criteria:**
- PythonFrontend.parse(path) returns an IRModule for valid Python and None (no exception) for files with SyntaxError, UnicodeDecodeError, OSError, or null bytes.
- All four import styles resolve to the same canonical callee_path: `import os; os.system(x)`, `from os import system; system(x)`, `import os as o; o.system(x)`, and (for run) `from subprocess import run; run(...)` -> 'subprocess.run'. `import os.path as p; p.join(x)` -> 'os.path.join'.
- Value-rooted attribute chains are preserved: `conn.cursor.execute(sql)` yields IRCall.callee_path == 'conn.cursor.execute' so `*.cursor.execute` and `*.execute` patterns can match; base local var is NOT rewritten.
- IRCall separates callee_path, ordered positional args (index-addressable for args:[0]), keyword args with PRESERVED literal values (shell=True is IRLiteral(value=True, is_constant=True)), and receiver expr for method calls.
- Module top-level code is modeled as the synthetic '<module>' IRFunction; flows outside any def are captured.
- Params are first-class IRParam entities (incl. posonly/kwonly/vararg/kwarg) with Locations, independent of the deferred DSL `parameter` kind.
- Full binder inventory is lowered: Assign/AnnAssign/AugAssign, tuple+star unpack, attribute/subscript targets, for/with-as/except-as, walrus NamedExpr, comprehension targets, params, import bindings.
- Every IR expression and statement carries a correct models.Location (1-based line, 0-based column, end positions) sufficient for the engine to build a witness step without re-walking ast.
- The per-function CFG (IRBlock + successors) is emitted by the frontend; join blocks have >1 predecessor; loops produce back-edges (no unrolling). Documented that the engine consumes and does not rebuild it.
- IR construction is deterministic: functions/statements/blocks/import entries are emitted in source order; no dict/set iteration order leaks into IR ordering.
- No taint/detector/CWE vocabulary appears anywhere in frontends/ (P4). The engine can match every pattern in os-command.yml and sql.yml from IR fields alone.
- ruff (line-length 100, double quotes), mypy --strict, and SPDX headers pass on every new/edited .py file; pytest green.

**tests:**
- test_import_resolution_all_styles: `import os`/`from os import system`/`import os as o`/`from os import system as s` all yield callee_path 'os.system'; `from subprocess import run; run(...)` -> 'subprocess.run'; `import os.path as p; p.join` -> 'os.path.join'.
- test_value_rooted_method_chain: `conn.cursor.execute(sql)` -> callee_path 'conn.cursor.execute', receiver is IRAttribute(conn.cursor), args[0] is IRName 'sql'.
- test_keyword_literal_preserved: `subprocess.run(x, shell=True)` -> kwargs contains IRKeyword('shell', IRLiteral(True, is_constant=True)); `shell=flag` (var) -> IRLiteral.is_constant is False.
- test_positional_vs_keyword_capture: positional args index-addressable; **kwargs -> IRKeyword(name=None).
- test_module_scope_captures_toplevel: a top-level `os.system(input())` (no def) appears in IRModule.module_scope.
- test_params_first_class: def with posonly/kwonly/*args/**kwargs yields correctly-kinded IRParam with Locations and indices.
- test_binders_tuple_star_walrus_with_except: `a,b = t`, `first,*rest = t`, `(y := f())`, `with open() as fh:`, `except E as e:`, `x.a = t`, `x[0] = t` all produce the right Target/binding nodes.
- test_nested_scope_comprehension_lambda: `[f(x) for x in items]` and `lambda a: g(a)` create child IRFunctions linked via parent_index; comprehension target bound in the nested scope.
- test_fstring_and_binop_exprs: f-strings -> IRJoinedStr; `'a' + name` -> IRBinOp('+'); `'%s' % name` -> IRBinOp('%') (engine uses these as default propagators).
- test_const_vs_dynamic_subscript: `d['k']`/`a[0]` -> IRSubscript.is_const_index True with const_index; `a[i]` -> is_const_index False.
- test_locations_precise: a known call's Location matches ast lineno/col_offset/end positions (1-based line, 0-based column).
- test_syntax_error_returns_none: file with a syntax error -> parse returns None, no exception.
- test_decode_error_returns_none: file with invalid/odd encoding or null bytes -> parse returns None.
- test_unknown_node_is_opaque: an unmodeled construct lowers to IRUnknown rather than crashing.
- test_determinism_stable: parsing the same source twice yields structurally identical IR (same ordering of functions/blocks/statements/import entries).
- test_relative_and_star_import_recorded: `from . import x` and `from m import *` are recorded (dot marker / wildcard) without crashing and without false canonicalization.

**risks:**
- CFG-ownership collision: the prior-art engine_design says the engine builds the CFG, but this spec puts it in the frontend. If the master plan hands a CFG task to BOTH subsystems, there will be duplication/divergence. Mitigation: the engine spec must reference IRBlock and explicitly not rebuild a CFG (flagged in open_questions).
- Over/under-modeling the CFG: too coarse (everything one block) loses flow-sensitive kills the engine needs; too fine (per-statement blocks) bloats and slows the engine. Risk of getting try/except/finally and loop back-edges subtly wrong, which would corrupt the engine's join/union semantics.
- ast version drift: end_lineno/end_col_offset are reliable at py>=3.10 but typed Optional; pattern-matching node attributes (e.g. posonly args, match statements 3.10+) must be handled or fall to IRUnknown to avoid crashes on newer syntax.
- Resolver shadowing/scope-chaining bugs: a function-local import or a local variable that shadows an imported name must win in the right scope; getting the chain wrong causes silent mis-canonicalization (false negatives or wrong witnesses).
- mypy --strict over a large Union of frozen dataclasses can be verbose; exhaustive isinstance dispatch in lowering may need careful typing (possibly typing.assert_never) to stay strict-clean.
- Scope creep into engine territory: it is tempting to start tagging sources/sinks during lowering; that would violate P4. Must keep frontends/ taint-free.
- Relative/dynamic/star imports are genuinely unresolvable intra-file; over-promising resolution would create wrong canonical paths. Mitigation: record-only + document (P7).

**open_questions:**
- CFG OWNERSHIP (must be resolved in the master plan): this spec assigns the per-function basic-block CFG to the frontend (IRBlock + successors), overriding the prior-art engine_design phrasing. Confirm the engine spec consumes IRBlock and does NOT build its own CFG. If the orchestrator prefers the engine to own CFG, move FRONTEND_IR_5 to the engine and have the frontend emit only ordered statement lists per scope.
- Access-path representation: the engine keys taint by bounded access paths (base + .attr/[const] suffix, depth cap 2-3). Should the FRONTEND pre-compute a normalized access-path string for each Name/Attribute/Subscript target+load, or leave that purely to the engine? Recommend leaving it to the engine (it owns the cap policy) but the IR must expose enough structure (it does). Confirm with the engine spec author.
- Skip logging owner: parse returns None on failure; which subsystem emits the 'skipped file: <path> (<reason>)' message — the scan driver in cli-ux, or does the frontend return a typed reason? Recommend frontend returns None and the scan driver logs; confirm the reason does not need to be surfaced to the user as a finding.
- Receiver vs callee_path for `self`/by-side-effect flows: the IR exposes both receiver and callee_path. Confirm the engine's planned by-side-effect propagators (DSL extension for list.append/dict.__setitem__) and `self` flow need nothing more from the IR (e.g. a stable identity for the receiver access path).
- match statement (3.10+) and async constructs (async for/with): lower to CFG edges now, or fall to IRUnknown for v1? Recommend minimal CFG support for async (treated like sync) and IRUnknown for match-case bodies' patterns initially; confirm acceptable for the target corpus.

==========================================================================================
## COMPONENT: Pattern matcher

**Summary:** A pure, deterministic module that decides whether a single DSL Pattern matches a single already-resolved IR node, and reports which positional arguments are in scope for taint. It is the one place that interprets the DSL's dotted-path + `*` wildcard grammar and the `args` / `when{keyword{...}}` constraints. The matcher never touches `ast`, never consults taint state, and never builds witnesses — the frontend resolves nodes to canonical dotted names upstream, and the engine drives taint/witness logic downstream. This module is the concrete realization of P4 (declarative): the engine asks "does this spec's pattern match here?" and gets a structural yes/no plus arg indices, with zero per-detector code.

**Key files:** src/scanipy/engine/matcher.py (NEW — the matcher, MatchResult, match() public API), src/scanipy/engine/ir.py (NEW — ResolvedNode Protocol + supporting structural types the matcher consumes; shared with frontend/engine), src/scanipy/engine/__init__.py (export match, MatchResult, ResolvedNode), tests/unit/test_matcher.py (NEW — matcher unit tests with fake ResolvedNodes), docs/dsl-reference.md (UPDATE — pin wildcard semantics: trailing-single vs leading-greedy; promote call/attribute/import/parameter status; document positional-only args + literal-only when, and their known gaps), src/scanipy/dsl/patterns.py (READ-ONLY — Pattern/PatternKind/Flow/Propagator are the inputs; do not change shapes)

**Interfaces:**
```
### src/scanipy/engine/ir.py (NEW)
```python
from typing import Protocol, runtime_checkable
from collections.abc import Mapping, Sequence
from scanipy.dsl.patterns import PatternKind
from scanipy.models import Location

@runtime_checkable
class KeywordValue(Protocol):
    is_literal: bool
    literal_value: object  # meaningful only when is_literal is True

@runtime_checkable
class ResolvedNode(Protocol):
    kind: PatternKind
    dotted_name: str | None          # canonical dotted path, or None if unresolvable
    arg_count: int                   # written positional args; excludes receiver/keywords
    keywords: Mapping[str, KeywordValue]
    location: Location
```

### src/scanipy/engine/matcher.py (NEW)
```python
from dataclasses import dataclass
from scanipy.dsl.patterns import Pattern   # (kind, pattern, args, when)
from scanipy.engine.ir import ResolvedNode

@dataclass(frozen=True)
class MatchResult:
    dotted_name: str            # concrete resolved name that matched (witness desc)
    arg_indices: tuple[int, ...]  # sorted, deduped, in-scope positional indices

def match(pattern: Pattern, node: ResolvedNode) -> MatchResult | None: ...
def matches(pattern: Pattern, node: ResolvedNode) -> bool: ...

# internal, pure helpers (module-private):
def _match_dotted(pattern: str, name: str) -> bool: ...
def _resolve_arg_indices(spec_args: tuple[int, ...] | None, arg_count: int) -> tuple[int, ...]: ...
def _match_when(when: Mapping[str, object], node: ResolvedNode) -> bool: ...
```

### Inputs (existing, unchanged — src/scanipy/dsl/patterns.py)
```python
Pattern(kind: PatternKind, pattern: str, args: tuple[int,...] | None, when: Mapping[str, object] | None)
PatternKind = CALL | ATTRIBUTE | PARAMETER | IMPORT
```
### Output building blocks (existing — src/scanipy/models.py): Location(file, line, column, end_line, end_column).

### How the engine calls it (illustrative, NOT part of this component):
```python
for sink in spec.sinks:
    if (m := match(sink, node)) is not None:
        for i in m.arg_indices:           # check taint on these arg exprs
            ...
```
```

**Design:**
PURITY & PLACEMENT
The matcher lives in a new module `src/scanipy/engine/matcher.py`. It is a pure function library: deterministic, no I/O, no `import ast` use of node objects beyond the structural Protocol, no global/mutable state, no taint state. Given the same (Pattern, ResolvedNode) it always returns the same MatchResult. It does NOT: track taint, parse or resolve ast, build witnesses, interpret a Propagator's Flow (it only matches the Propagator's `.pattern`), or read the filesystem.

INPUT CONTRACT — ResolvedNode (defined in src/scanipy/engine/ir.py)
The matcher consumes nodes the frontend has already resolved. Define a structural `typing.Protocol` named `ResolvedNode` with (at minimum):
  - `kind: PatternKind`  — what syntactic site this is (call / attribute / import / parameter).
  - `dotted_name: str | None` — the canonicalized dotted path after import/alias resolution (e.g. `os.system`, `subprocess.run`, `flask.request.args`, `self.db.cursor.execute`). `None` when the node's callee/target is a complex expression that cannot be resolved to a dotted path (e.g. `foo()()`, a subscript callee). A `None` name MUST yield no-match, never an exception.
  - `arg_count: int` — number of WRITTEN positional arguments (excludes the receiver; excludes keywords; excludes `*args` splats — splats are handled conservatively, see below).
  - `keywords: Mapping[str, KeywordValue]` — written keyword name → a small value descriptor that exposes `is_literal: bool` and `literal_value: object` (only meaningful when `is_literal`). Non-literal kwargs (variables, calls) have `is_literal=False`.
  - `location: Location` — the existing scanipy Location, passed through for witness use by the engine (the matcher itself does not build witnesses but the engine reads node.location).
The matcher unit-tests against simple fakes implementing this Protocol; it has NO hard dependency on the frontend's concrete classes. The frontend/IR component produces objects satisfying ResolvedNode (cross-component seam — see depends_on).

PUBLIC API the engine consumes
  `def match(pattern: Pattern, node: ResolvedNode) -> MatchResult | None`
Returns `None` for no-match; a `MatchResult` for a match. (Returning Optional rather than a bool keeps the arg-index payload colocated with the positive answer and is mypy-clean.)
  `@dataclass(frozen=True) class MatchResult:`
    - `dotted_name: str`  — the concrete resolved name that matched (good P2 witness description; e.g. `subprocess.run`).
    - `arg_indices: tuple[int, ...]` — sorted, de-duplicated, in-scope positional indices the engine must check for taint at a sink/sanitizer (and the relevant ones for propagator flows). See ARGS below. Empty tuple is legal and meaningful (a call with a restriction whose indices are all out of range still "matched the call shape"? No — see ARGS: out-of-range restriction => no-match). For sources/attributes/imports with no arg semantics, `arg_indices=()`.
Convenience wrapper for the engine's hot path: `def matches(pattern, node) -> bool: return match(pattern, node) is not None`.

ALGORITHM (top-level, in `match`)
1. KIND GATE: if `pattern.kind != node.kind` → return None. (A `call` pattern never matches an `attribute` node and vice versa.)
2. NAME GATE: if `node.dotted_name is None` → return None. Else run `_match_dotted(pattern.pattern, node.dotted_name)`; if False → return None.
3. CONSTRAINTS (only for `kind == CALL`; `args`/`when` are ignored on non-call kinds, and the parser SHOULD reject them on non-call kinds — see depends_on PARSER):
   a. `when`: if `pattern.when` is not None → evaluate `_match_when(pattern.when, node)`; if False → return None.
   b. `args`: compute `arg_indices` via `_resolve_arg_indices(pattern.args, node.arg_count)`. If `pattern.args` is not None and the intersection is empty → return None (the restriction names only out-of-range indices, so this site cannot carry the targeted taint).
4. Return `MatchResult(dotted_name=node.dotted_name, arg_indices=...)`. For non-call kinds, `arg_indices=()`.

WILDCARD GRAMMAR — `_match_dotted(pattern: str, name: str) -> bool` (DETERMINISTIC, segment-wise, NEVER regex/glob over the raw string)
Split both on `"."` into segment lists `P` and `N`. Three modes, dispatched by where `*` appears (v1 supports exactly the forms the dsl-reference uses; reject other `*` placements at parse time):
  - EXACT (no `*` in P): match iff `P == N`. Covers `os.system`, and bare one-segment builtins `input`, `eval`, `exec`, `compile` (P=["input"], matches N=["input"] only).
  - TRAILING-SINGLE (`*` is the last segment, no other `*`): the literal prefix `P[:-1]` must equal `N[:len(P)-1]` AND `len(N) == len(P)` (the `*` consumes EXACTLY ONE segment). So `subprocess.*` matches `subprocess.run` but NOT `subprocess.run.foo`; `flask.request.*` matches `flask.request.args` but NOT `flask.request.args.get`.
  - LEADING-GREEDY (`*` is the FIRST segment, no other `*`): the literal suffix `P[1:]` must equal the TAIL of `N` (`N[-len(P[1:]):] == P[1:]`) AND `len(N) > len(P)-1` (the `*` consumes ONE-OR-MORE segments). So `*.execute` matches `db.execute`, `conn.cursor().execute`→resolved tail `...execute`, and crucially `self.db.cursor.execute`; `*.cursor.execute` matches `self.db.cursor.execute`. The receiver prefix is UNCONSTRAINED and MAY be opaque — this is the safety-net behavior for method sinks on arbitrarily-deep/aliased receivers. (Requirement on frontend: for a call whose receiver is opaque but whose tail attribute is known, it should still emit a `dotted_name` ending in the known tail so `*.execute` can fire; document this as the matcher's expectation of the resolver.)
Determinism: pure list comparison, no dict/set iteration. Adopt GREEDY-LEADING because real code writes `self.db.cursor.execute(...)` and trailing-single-everywhere would silently miss it (false negative on idiomatic ORM/DBAPI code).

ARGS — `_resolve_arg_indices(spec_args: tuple[int,...] | None, arg_count: int) -> tuple[int,...]`
  - `spec_args is None` → ALL written positional indices: `tuple(range(arg_count))`.
  - else → sorted unique intersection of `spec_args` with `range(arg_count)` (drop negatives and out-of-range). The engine maps each returned index → the node's actual arg expression → its taint label.
  - Positional indices are 0-based and EXCLUDE the receiver. The receiver is addressed as `self` in the Flow vocabulary; `args:[0]` on `*.execute` means the FIRST WRITTEN argument (the SQL string), not the receiver. This convention is load-bearing for every method-call sink — state it in docs.
  - KNOWN GAP (document as risk + dsl-reference note, do not silently swallow): `args` is positional-only. `subprocess.run(args=cmd, shell=True)` passes the command as a KEYWORD, so a positional `args` restriction will not flag it. This is the "kwarg-targeted args" DSL extension (prior-art rec #9) — deferred from v1; flagged as a limitation. (Mitigation in the os-command spec: the `subprocess.*` sink is gated by `when shell=True`, not by `args`, so it still fires; the gap bites only detectors that rely on a positional `args` restriction for a function that also accepts the dangerous value by keyword.)
  - SPLAT conservatism: if the node has a `*args` splat in positional position, the frontend should set a flag the engine reads; the MATCHER treats `arg_count` as written positionals only. (Whether to over-approximate splats is an engine decision, not the matcher's — note as open question, keep matcher simple.)

WHEN — `_match_when(when: Mapping[str, object], node: ResolvedNode) -> bool`
v1 supports exactly one key: `keyword`. Algorithm:
  - Iterate `when` keys in SORTED order (determinism). For each key:
    - `keyword`: value must be a Mapping[str, <literal>] (parser-validated). For EACH (kw_name, expected) pair, the node must have a written keyword `kw_name` whose `is_literal` is True and whose `literal_value == expected`. ALL pairs must hold (AND semantics). Missing kwarg, non-literal kwarg, or unequal literal → False.
    - any other key → the parser should have rejected it; the matcher treats unknown keys conservatively as NON-matching (return False) so a malformed/unsupported constraint can never silently widen matches. (Document; parser is the real gate.)
  - LITERAL-ONLY semantics (committed decision): `shell=True` matches only `ast.Constant(True)` → `is_literal=True, literal_value=True`. `shell=False`, absent, or `shell=some_var` do NOT satisfy. The false negative on `shell=<truthy variable>` is niche — listed as an open question, but literal-equality is the correct pure/deterministic default.
  - mypy --strict: `when` is `Mapping[str, object]`; narrow with `isinstance(v, Mapping)` before indexing, and treat the inner values as `object` compared by `==`. No `cast` without a guard.

PER-KIND SUMMARY
  - CALL: name gate + when + args; returns arg_indices.
  - ATTRIBUTE: name gate only; `when`/`args` ignored (and parser-rejected); arg_indices=(). Used for sources like `flask.request.*`.
  - IMPORT: name gate against the imported canonical dotted name; arg_indices=(). (Engine decides what an import match means for taint; matcher only answers "is this the imported name?")
  - PARAMETER: UNDERSPECIFIED in dsl-reference. v1 default: match `pattern` against the PARAMETER NAME using the same wildcard grammar (node.dotted_name = the bare parameter name). arg_indices=(). No bundled detector uses it; implement the kind structurally but do not over-build (open question on exact semantics — function-qualified vs bare name).

CONSTRAINT/PARSER SEAM
Cleanest contract: the DSL PARSER validates the SHAPE of `args` (list of non-negative ints) and `when` (only `keyword`, mapping of name→scalar-literal), and that `args`/`when` appear only on `kind: call`, raising `DSLError` early. The matcher then TRUSTS the shape and only narrows types for mypy. (depends_on PARSER.) If the parser cannot guarantee this in v1, the matcher must degrade safely (treat malformed when as non-matching), but the spec's preference is parser-validates.

**Tasks:**
- (S) PATTERN_MATCHER_1: Define ResolvedNode / KeywordValue Protocols in engine/ir.py
    Create src/scanipy/engine/ir.py with the runtime_checkable Protocols ResolvedNode (kind, dotted_name: str|None, arg_count: int, keywords: Mapping[str, KeywordValue], location: Location) and KeywordValue (is_literal, literal_value). SPDX header, `from __future__ import annotations`, full docstrings stating this is the matcher's input contract and that the frontend produces conforming objects. mypy --strict clean. This is the cross-component seam with the frontend/IR — coordinate field names exactly.
- (M) PATTERN_MATCHER_2: Implement segment-wise wildcard matcher _match_dotted
    Implement the three modes (EXACT, TRAILING-SINGLE = exactly-one-segment, LEADING-GREEDY = one-or-more-segments) by splitting on '.'. No regex/glob on the raw string. Reject (raise/return False is fine; real rejection happens in parser) malformed multi-`*` patterns. Pure, deterministic. Cover bare single-segment builtins (input/eval/exec/compile).
- (S) PATTERN_MATCHER_3: Implement _resolve_arg_indices (positional, receiver-excluded)
    spec_args None -> range(arg_count); else sorted-unique intersection with range(arg_count), dropping negatives/out-of-range. Document receiver exclusion (args:[0] == first written arg). Return tuple[int,...].
- (M) PATTERN_MATCHER_4: Implement _match_when (keyword literal-equality, AND, sorted) [deps: PATTERN_MATCHER_1]
    Support only when.keyword: Mapping[name->literal]. Each pair requires a written literal kwarg equal to the expected value. Missing/non-literal/unequal -> False. Unknown top-level when keys -> False (conservative). Iterate keys sorted. mypy-narrow the Mapping[str, object] with isinstance guards (no bare cast).
- (M) PATTERN_MATCHER_5: Implement public match()/matches() + MatchResult in engine/matcher.py [deps: PATTERN_MATCHER_1, PATTERN_MATCHER_2, PATTERN_MATCHER_3, PATTERN_MATCHER_4]
    Wire kind gate -> name gate -> (call-only) when -> args, per the algorithm. Return None on any failure incl. dotted_name is None and empty-intersection out-of-range restriction. Frozen MatchResult(dotted_name, arg_indices). matches() convenience. SPDX header, docstrings, mypy --strict, ruff (line-length 100, double quotes) clean.
- (S) PATTERN_MATCHER_6: Export matcher API from engine/__init__.py [deps: PATTERN_MATCHER_5]
    Add match, matches, MatchResult, ResolvedNode (and KeywordValue) to src/scanipy/engine/__init__.py __all__ and imports without creating import cycles (ir.py imports only dsl.patterns + models; matcher imports ir + dsl.patterns).
- (M) PATTERN_MATCHER_7: Write tests/unit/test_matcher.py with fake ResolvedNodes [deps: PATTERN_MATCHER_5]
    Implement a tiny FakeNode dataclass conforming to ResolvedNode + FakeKw. Cover the full test list in `tests` below: wildcard table, kind discrimination, args intersection/out-of-range, when literal True/False/absent/non-literal, dotted_name=None no-crash, determinism. Mark @pytest.mark.unit. No I/O.
- (S) PATTERN_MATCHER_8: Update docs/dsl-reference.md: pin wildcard + constraint semantics and gaps [deps: PATTERN_MATCHER_5]
    Document: trailing-single (exactly one segment) vs leading-greedy (one-or-more, receiver unconstrained, matches self.db.cursor.execute); args is positional-only & receiver-excluded with the kwarg-targeting known gap; when.keyword is literal-equality-only with the non-literal-value FN; promote call/attribute to supported and note import/parameter v1 status + parameter underspecification. Keep it the single source of truth.
- (S) PATTERN_MATCHER_9: (Coordination) Confirm parser validates args/when shape & placement [deps: PATTERN_MATCHER_2, PATTERN_MATCHER_4]
    Align with the DSL parser component so it raises DSLError for: args not list[non-neg int]; when with keys other than keyword; keyword values that are non-scalar; args/when on non-call kinds; bad `*` placement (multiple `*`, mid-segment). The matcher trusts validated shapes. If parser can't guarantee in v1, matcher degrades safely (already specified).

**acceptance_criteria:**
- match() is a pure function: no I/O, no ast import-of-nodes, no taint state, no mutable global state; identical (Pattern, ResolvedNode) inputs always produce an equal MatchResult/None (P3).
- Kind gate: a CALL pattern never matches an ATTRIBUTE/IMPORT/PARAMETER node and vice versa; mismatched kind returns None.
- EXACT: `os.system` matches only `os.system`; bare `input` matches only `input` (not `mymod.input`).
- TRAILING-SINGLE: `subprocess.*` matches `subprocess.run`, does NOT match `subprocess.run.foo` or bare `subprocess`; `flask.request.*` matches `flask.request.args` but not `flask.request.args.get`.
- LEADING-GREEDY: `*.execute` matches `db.execute` and `self.db.cursor.execute`; `*.cursor.execute` matches `self.db.cursor.execute`; neither matches a name lacking the literal suffix.
- dotted_name is None returns None and never raises.
- args=None yields arg_indices == all written positional indices; args=[0] on a 2-arg call yields (0,); args=[5] on a 2-arg call yields None (out-of-range restriction = no-match); negative indices dropped; result sorted & deduped.
- args indices exclude the receiver (args:[0] == first written argument on `*.execute`).
- when shell=True matches only a literal True kwarg; shell=False, absent shell, or shell=<non-literal> do NOT match; multiple keyword pairs are ANDed; when keys iterated in sorted order.
- when/args on non-call kinds are ignored by the matcher (and rejected by the parser per PATTERN_MATCHER_9).
- Unknown when top-level key returns False (never widens matches).
- ruff (line-length 100, double quotes), mypy --strict on src/, and pytest all green; SPDX header on every new .py; `when` Mapping narrowed via isinstance with no unguarded cast.
- MatchResult.dotted_name is the concrete resolved name (usable as a P2 witness description), and arg_indices is a sorted tuple.

**tests:**
- test_exact_match: `os.system` vs node os.system -> match; vs os.popen -> None; bare `input` vs input -> match; vs pkg.input -> None.
- test_trailing_single_positive: `subprocess.*` vs subprocess.run -> match (dotted_name reported).
- test_trailing_single_negative_too_deep: `subprocess.*` vs subprocess.run.foo -> None; vs bare subprocess -> None.
- test_attribute_trailing_single: `flask.request.*` vs flask.request.args -> match; vs flask.request.args.get -> None.
- test_leading_greedy_positive: `*.execute` vs db.execute -> match; vs self.db.cursor.execute -> match (the load-bearing ORM case).
- test_leading_greedy_specific_tail: `*.cursor.execute` vs self.db.cursor.execute -> match; vs self.db.execute -> None.
- test_leading_greedy_negative: `*.execute` vs db.executemany -> None (segment-wise, not substring).
- test_kind_gate: call pattern vs attribute node -> None; attribute pattern vs call node -> None.
- test_dotted_name_none_no_crash: any pattern vs node with dotted_name=None -> None, no exception.
- test_args_none_all_indices: sink with args=None on a 3-arg call -> arg_indices == (0,1,2).
- test_args_restrict_in_range: args=(0,) on 2-arg call -> (0,); args=(1,0) -> (0,1) (sorted).
- test_args_out_of_range_is_no_match: args=(5,) on 2-arg call -> None; args=(-1,) dropped.
- test_args_receiver_excluded: `*.execute` args=(0,) on conn.cursor().execute(sql) (1 written arg) -> (0,) targeting sql, not the receiver.
- test_when_shell_true_literal: `subprocess.*` when keyword shell True vs node with shell=Constant(True) -> match.
- test_when_shell_false_or_absent: same pattern vs shell=False -> None; vs no shell kwarg -> None.
- test_when_shell_nonliteral: vs shell=<variable> (is_literal False) -> None.
- test_when_multiple_pairs_anded: two keyword constraints, only one satisfied -> None; both -> match.
- test_when_unknown_key_rejected: when with a non-`keyword` top key -> None.
- test_determinism: build two structurally-identical pattern/node pairs, assert match() outputs are equal; assert arg_indices is sorted for an unsorted args tuple.
- test_matches_wrapper: matches() returns the bool equivalent of (match() is not None).

**risks:**
- Frontend dotted_name format coupling: the matcher's correctness depends entirely on the resolver producing canonical dotted paths (aliases resolved, receiver tail exposed for `*.execute`). If the frontend emits a different convention (e.g. keeps aliases, or omits the tail when the receiver is opaque), `*.execute`-style sinks silently miss. Mitigate with a precise ResolvedNode contract (PATTERN_MATCHER_1) and a shared integration test owned by the frontend component.
- Kwarg-targeting gap (positional-only args): `subprocess.run(args=cmd, shell=True)` and similar where the dangerous value is passed by keyword are not covered by a positional `args` restriction. Deferred DSL feature; documented as a v1 limitation. Net effect is a false negative, acceptable under honest-scope (P7) but must be written down.
- Non-literal `when` value (shell=truthy_var) yields a false negative under literal-only semantics. Niche but real; documented (P7).
- parameter / import kinds are underspecified in dsl-reference; implementing a default could diverge from the eventual real semantics, causing churn. Mitigated by keeping them structural-only and unused by bundled detectors in v1.
- mypy --strict on `when: Mapping[str, object]` requires careful isinstance narrowing; sloppy handling tempts an unguarded cast (lint/type debt). Acceptance criteria forbid it.
- Wildcard mode dispatch must reject malformed `*` placements (multiple `*`, mid-segment like `os.sys*`) — if neither parser nor matcher guards this, behavior is undefined. Covered by the parser-validates seam (PATTERN_MATCHER_9) plus matcher defensiveness.
- Greedy-leading divergence from trailing-single could surprise detector authors if not clearly documented; the dsl-reference update (PATTERN_MATCHER_8) is load-bearing for usability.

**open_questions:**
- parameter-kind pattern semantics: match against bare parameter name, or function-qualified (enclosing_func.param)? v1 proposes bare-name + wildcard; needs confirmation if/when a detector uses parameter sources (deferred per prior-art rec #6).
- Splat handling: when a call has `*args`/`**kwargs`, should the engine over-approximate (treat as possibly-tainted in any restricted slot)? The matcher exposes only written arg_count; the over-approximation decision belongs to the engine — confirm the division and whether ResolvedNode needs a `has_star_args` flag.
- Should leading-greedy also allow the `*` to match ZERO segments (so `*.execute` matches a module-level bare `execute`)? Current spec requires one-or-more; zero-segment would blur into bare-name matching. Default: one-or-more; revisit if a detector needs it.
- Does the parser or the matcher own validation of `*` placement and args/when shape? Spec prefers parser-validates (PATTERN_MATCHER_9); needs the parser component to commit so the matcher can trust shapes and drop defensive branches (affects test surface).
- Should `when` eventually support non-keyword constraints (e.g. arg-value literals, arity)? Out of v1 scope; only `keyword` supported now — note for DSL co-evolution.
- Case/normalization: dotted names are matched case-sensitively and assumed already normalized by the frontend (no `os.path` vs `posixpath` aliasing). Confirm the resolver canonicalizes std-lib re-exports or accept the FN.

==========================================================================================
## COMPONENT: Taint engine (intra-file): TaintEngine.analyze + function-summary interprocedural layer

**Summary:** The class-agnostic taint engine that consumes the normalized per-function IR produced by PythonFrontend.parse and the active DetectorSpec pack, runs a flow-sensitive forward intraprocedural taint pass (seed at sources, propagate through assignments + generic/DSL propagators, kill at sanitizers one-sidedly, emit a Finding with an ordered source->...->sink witness when tainted data reaches a restricted sink arg under its when-constraints), and adds intra-file interprocedural reach via TITO function summaries computed to a bounded fixpoint over the within-file call graph. All detection knowledge stays in YAML (P4); the engine knows no CWEs. Output is a deterministic, stably-sorted list[Finding] with stable fingerprints (P3) and full witnesses (P2). This spec covers the engine algorithm; it consumes an IR contract owned by the sibling Python-frontend component and defines exactly what that IR must expose.

**Key files:** src/scanipy/engine/taint.py (implement TaintEngine.analyze; main intraprocedural pass + finding emission), src/scanipy/engine/ir.py (NEW: shared IR contract dataclasses the engine consumes — ModuleIR, FunctionIR, basic blocks/CFG, statement/expr wrappers, ImportTable, AccessPath; produced by PythonFrontend, owned jointly but defined here so the engine compiles against a concrete type), src/scanipy/engine/matching.py (NEW: pattern matcher — canonical dotted-path resolution via ImportTable + Pattern matching incl. wildcards, args restriction, when:{keyword} constraints; pure, class-agnostic), src/scanipy/engine/taint_state.py (NEW: TaintLabel, TaintProvenance, the access-path-keyed taint environment, lattice union/kill/sanitize ops), src/scanipy/engine/summaries.py (NEW: FunctionSummary, TransferFlow, summary computation to a bounded fixpoint over the call graph, summary application at call sites, witness splicing), src/scanipy/engine/witness.py (NEW: build ordered tuple[WitnessStep,...] from provenance, deterministic shortest-path selection, witness fingerprint, Finding.fingerprint), src/scanipy/engine/propagation.py (NEW: generic built-in propagators — assignment, BinOp +/%, JoinedStr f-strings, str methods, container build/iterate — applied to ALL detectors equally), tests/unit/test_taint_intraprocedural.py (NEW), tests/unit/test_taint_interprocedural.py (NEW), tests/unit/test_taint_determinism.py (NEW), tests/unit/test_matching.py (NEW), tests/integration/test_end_to_end.py (NEW: drive PythonFrontend.parse + load_builtin_detectors + TaintEngine.analyze over fixtures)

**Interfaces:**
```

# src/scanipy/engine/ir.py  (consumed by engine; produced by PythonFrontend)
from enum import Enum
from dataclasses import dataclass
from collections.abc import Mapping
from scanipy.models import Location

class ExprKind(str, Enum):
    NAME="name"; ATTRIBUTE="attribute"; SUBSCRIPT="subscript"; CALL="call"
    BINOP="binop"; JOINEDSTR="joinedstr"; CONST="const"; CONTAINER="container"
    COMPREHENSION="comprehension"; BOOLOP="boolop"; IFEXP="ifexp"; ITER_ELEM="iter_elem"; OTHER="other"

@dataclass(frozen=True)
class AccessStep:  # ("attr", "a") or ("index", "0") / ("index", "'k'")
    kind: str       # "attr" | "index"
    value: str

@dataclass(frozen=True)
class AccessPath:
    base: str
    steps: tuple[AccessStep, ...] = ()
    def prefix(self, n: int) -> "AccessPath": ...
    def is_prefix_of(self, other: "AccessPath") -> bool: ...

@dataclass(frozen=True)
class ExprRef:
    kind: ExprKind
    location: Location
    access_path: AccessPath | None = None
    dotted: str | None = None
    positional: tuple["ExprRef", ...] = ()
    keywords: tuple[tuple[str, "ExprRef"], ...] = ()
    receiver: "ExprRef | None" = None
    subexprs: tuple["ExprRef", ...] = ()
    const_value: object | None = None          # set when kind==CONST
    callee_qualname: str | None = None          # in-file FunctionIR.qualname if resolved

@dataclass(frozen=True)
class AssignTarget:
    access_path: AccessPath | None
    unpack: tuple["AssignTarget", ...] | None = None
    star: bool = False

# StmtIR is a tagged union; implement as a frozen base + subclasses, or a single
# frozen dataclass with a `kind` + optional fields. Subclass form:
@dataclass(frozen=True)
class AssignStmt:
    targets: tuple[AssignTarget, ...]; value: ExprRef; augmented: bool = False
@dataclass(frozen=True)
class ExprStmt:
    value: ExprRef
@dataclass(frozen=True)
class ReturnStmt:
    value: ExprRef | None
StmtIR = AssignStmt | ExprStmt | ReturnStmt

class ParamKind(str, Enum):
    POSITIONAL="positional"; KEYWORD_ONLY="keyword_only"; VARARG="vararg"; KWARG="kwarg"
@dataclass(frozen=True)
class ParamSpec:
    name: str; index: int | None; kind: ParamKind

@dataclass(frozen=True)
class BasicBlock:
    id: int; stmts: tuple[StmtIR, ...]; succ: tuple[int, ...]

@dataclass(frozen=True)
class CallSite:
    expr: ExprRef; callee_qualname: str | None

@dataclass(frozen=True)
class FunctionIR:
    qualname: str
    params: tuple[ParamSpec, ...]
    self_param: str | None
    entry_block: int
    blocks: tuple[BasicBlock, ...]
    calls: tuple[CallSite, ...]
    location: Location

@dataclass(frozen=True)
class ModuleIR:
    path: str
    import_table: Mapping[str, str]
    functions: tuple[FunctionIR, ...]   # includes synthetic "<module>" for top-level

# src/scanipy/engine/taint_state.py
@dataclass(frozen=True)
class TaintProvenance:
    spec_id: str
    chain: tuple[WitnessStep, ...]      # from scanipy.models
@dataclass(frozen=True)
class TaintLabel:
    spec_id: str
    provenance: TaintProvenance
class TaintEnv:                          # immutable; ops return new TaintEnv
    def get(self, ap: AccessPath) -> frozenset[TaintLabel]: ...
    def assign(self, ap: AccessPath, labels: frozenset[TaintLabel]) -> "TaintEnv": ...
    def kill(self, ap: AccessPath) -> "TaintEnv": ...
    def sanitize(self, ap: AccessPath, spec_id: str) -> "TaintEnv": ...
    def join(self, other: "TaintEnv") -> "TaintEnv": ...

# src/scanipy/engine/summaries.py
class FlowEnd(str, Enum):
    PARAM="param"; SELF="self"; RETURN="return"; SINK="sink"; SOURCE="source"
@dataclass(frozen=True)
class FlowEndpoint:
    kind: FlowEnd
    index: int | None = None              # for PARAM
    spec_id: str | None = None            # for SINK/SOURCE
    location: Location | None = None      # for SINK/SOURCE
@dataclass(frozen=True)
class TransferFlow:
    src: FlowEndpoint; dst: FlowEndpoint; fragment: tuple[WitnessStep, ...] = ()
@dataclass(frozen=True)
class FunctionSummary:
    qualname: str; flows: tuple[TransferFlow, ...]
def compute_summaries(module: ModuleIR, specs: Sequence[DetectorSpec]) -> dict[str, FunctionSummary]: ...

# src/scanipy/engine/matching.py
def match_dotted(pattern: str, dotted: str) -> bool: ...
def match_pattern(p: Pattern, expr: ExprRef) -> bool: ...
def matched_arg_indices(p: Pattern, expr: ExprRef) -> tuple[int, ...]: ...
def when_satisfied(p: Pattern, expr: ExprRef) -> bool: ...

# src/scanipy/engine/witness.py
def witness_fingerprint(steps: tuple[WitnessStep, ...]) -> str: ...
def finding_fingerprint(detector_id: str, cwe: str, sink: Location, steps: tuple[WitnessStep, ...]) -> str: ...
def better_chain(a: tuple[WitnessStep,...], b: tuple[WitnessStep,...]) -> tuple[WitnessStep,...]: ...  # shortest then lexicographically smallest

# src/scanipy/engine/taint.py (existing signature preserved)
class TaintEngine:
    def __init__(self, specs: Sequence[DetectorSpec]) -> None: ...
    @property
    def specs(self) -> tuple[DetectorSpec, ...]: ...
    def analyze(self, module: object) -> list[Finding]: ...   # narrows to ModuleIR

```

**Design:**

OVERVIEW
========
Two phases per file, both deterministic:
  Phase 0 (frontend, sibling component): PythonFrontend.parse(path) -> ModuleIR. The engine consumes ModuleIR; it does NOT touch ast directly. The IR contract is defined in src/scanipy/engine/ir.py (below) so the engine type-checks against a concrete shape under mypy --strict.
  Phase 1 (engine, summaries.py): compute a FunctionSummary per function in reverse-topological order of the intra-file call graph; cyclic SCCs solved by a bounded monotone worklist fixpoint.
  Phase 2 (engine, taint.py): for every function, run the intraprocedural taint pass with summaries available at call sites; collect findings; sort + dedup + fingerprint; return list[Finding].

The engine is class-agnostic (P4): it iterates self._specs and only does generic operations (resolve dotted name, match Pattern, move/kill/seed labels). No CWE/detector string appears in engine code.

----------------------------------------------------------------------
IR CONTRACT (src/scanipy/engine/ir.py) — what the frontend must hand the engine
----------------------------------------------------------------------
The engine wraps/annotates ast rather than lowering to TAC, to keep Location line/col fidelity. Concrete dataclasses (frozen where possible):

  AccessPath: base: str ; steps: tuple[AccessStep, ...]  (AccessStep = ("attr", name) | ("index", const_repr)). Depth cap STEPS_CAP=2. Equality/hash/order by (base, steps). Helper .prefix(n), .is_prefix_of(other).

  ExprRef: a thin wrapper over an ast expression node carrying: .location (scanipy.models.Location built from node.lineno/col_offset/end_lineno/end_col_offset, file from module), and a classification the engine needs WITHOUT re-walking ast deeply. Specifically ExprRef exposes:
     - kind: one of NAME, ATTRIBUTE, SUBSCRIPT, CALL, BINOP, JOINEDSTR(f-string), CONST, CONTAINER(list/tuple/set/dict build), COMPREHENSION, BOOLOP, IFEXP, OTHER
     - access_path: AccessPath | None  (set for NAME/ATTRIBUTE/SUBSCRIPT that reduce to a bounded access path; None if dynamic/over-cap)
     - dotted: str | None  (for CALL/ATTRIBUTE: the resolved canonical dotted callee path, e.g. "os.system", "subprocess.run", "flask.request.args"; resolution done by frontend using ImportTable; None if unresolvable)
     - positional: tuple[ExprRef, ...]   (call positional args)
     - keywords: tuple[tuple[str, ExprRef], ...]  (call kw args: (name, value); name="" for **kwargs)
     - receiver: ExprRef | None  (for method calls a.b(...), the ExprRef of `a` — used for `self` flows and *.method patterns)
     - subexprs: tuple[ExprRef, ...]  (operands for BINOP/BOOLOP/IFEXP/CONTAINER/JOINEDSTR/COMPREHENSION; iterable source for comprehension is subexprs[-1] by convention, documented)
  Rationale: the engine reads structured ExprRef fields, never raw ast attributes, so swapping the frontend or adding a language cannot break the engine.

  StmtIR: a normalized statement, one of:
     - AssignStmt(targets: tuple[AssignTarget,...], value: ExprRef)   # Assign/AnnAssign; AugAssign normalized to target += value with augmented=True flag
     - ExprStmt(value: ExprRef)                                       # bare expression (e.g. a call used for side effects)
     - ReturnStmt(value: ExprRef | None)
     - branch/merge are encoded by the CFG, not as statements (if/while/for/with/try lowered to blocks+edges by frontend)
     AssignTarget: access_path: AccessPath | None ; unpack: tuple[AssignTarget,...] | None ; star: bool  # supports a,b = t and first,*rest = t
     For `for v in it:` the loop header contributes a synthetic AssignStmt(target=v, value=ITER_ELEM(it)) where ExprRef.kind marks element-of-iterable so the engine taints v if `it` is tainted (container-iterate rule).

  BasicBlock: id: int ; stmts: tuple[StmtIR,...] ; succ: tuple[int,...]   (successor block ids; sorted)
  FunctionIR:
     - qualname: str (module-relative, e.g. "Outer.method", "f.<locals>.g"); used as call-graph node key
     - params: tuple[ParamSpec,...]  where ParamSpec=(name:str, index:int|None, kind: POSITIONAL|KEYWORD_ONLY|VARARG|KWARG)  (index is positional index for positional params; None for *args/**kwargs/kw-only)
     - self_param: str | None  (name of receiver param for methods; the first positional of a method, decided by frontend; "self" flows bind here)
     - entry_block: int ; blocks: tuple[BasicBlock,...] (sorted by id)
     - calls: tuple[CallSite,...]  (every call in the function, for call-graph building) where CallSite=(expr: ExprRef, callee_qualname: str | None)  # callee_qualname set when the dotted/name resolves to a same-file FunctionIR.qualname, else None (external)
     - location: Location (the def site)
  ModuleIR:
     - path: str
     - import_table: ImportTable  (maps local name -> canonical dotted path; resolves `import X`, `import X as Y`, `from M import N`, `from M import N as A`, `import X.Y`; frontend builds it)
     - functions: tuple[FunctionIR,...]  (module-level + nested defs + lambdas-as-functions, sorted by qualname)
     - module_block: BasicBlock-graph for module top-level code (treated as a synthetic function "<module>" with no params)
     - call_graph: Mapping[str, tuple[str,...]] (qualname -> sorted callee qualnames within file; frontend may precompute or engine derives from FunctionIR.calls — engine derives to keep frontend simple)

  NOTE on ownership: ir.py is delivered by this engine spec (so the engine has a concrete type), but PythonFrontend.parse is the PRODUCER (sibling FRONTEND component). The CallSite.callee_qualname and import_table resolution are frontend responsibilities; the engine treats them as given. analyze(module: object) does `assert isinstance(module, ModuleIR)` style narrowing (cast + runtime check) at the boundary.

----------------------------------------------------------------------
PATTERN MATCHING (src/scanipy/engine/matching.py)
----------------------------------------------------------------------
Pure functions, no detector knowledge:
  resolve_dotted(expr: ExprRef) -> str | None : returns expr.dotted (already canonicalized by frontend via ImportTable). matching.py just consumes it; canonicalization itself lives in the frontend but the dotted-glob match lives here.
  match_dotted(pattern: str, dotted: str) -> bool : segment-wise match; `*` matches exactly one segment; a TRAILING `subprocess.*` matches one trailing segment; leading `*.cursor.execute` matches any first segment(s)? -> SPEC DECISION: `*` is a single-segment wildcard; for `*.cursor.execute` the leading `*` matches exactly one leading segment AND we additionally allow it to match the *last* segment of the resolved dotted suffix by right-anchoring method patterns. Concretely: a pattern with a leading `*` is right-anchored (suffix match on the remaining literal segments); a pattern with a trailing `*` is left-anchored (prefix match). A pattern with neither is exact. (Document in dsl-reference.md; covers `os.system`, `subprocess.*`, `*.cursor.execute`, `*.execute`, `flask.request.*`.)
  match_pattern(p: Pattern, expr: ExprRef) -> MatchResult|None :
     - kind CALL: expr.kind==CALL and match_dotted(p.pattern, expr.dotted)
     - kind ATTRIBUTE: expr.kind in {ATTRIBUTE,NAME,SUBSCRIPT} and match_dotted(p.pattern, expr.dotted) (attribute sources like flask.request.* match an attribute READ resolved to that dotted path)
     - kind PARAMETER / IMPORT: out of scope for v1 sources/sinks in the core pack; engine returns None (parser may reject or warn). Engine MUST not crash on them.
     - when constraint: evaluate p.when. v1 supports when={"keyword": {name: value}} -> True iff the call has keyword `name` with a CONSTANT value equal to `value` (e.g. shell=True). Constant equality uses ExprRef.kind==CONST and the literal value; non-constant kw value => constraint NOT satisfied (conservative for sinks gated by when; document: a dynamic shell=var is NOT flagged by the shell=True sink — honest limitation P7).
  matched_arg_indices(p: Pattern, expr: ExprRef) -> tuple[int,...] : if p.args is None -> all positional indices present (and a sentinel for kw-targeted later); else intersect p.args with present positional indices. (DSL extension kwarg-targeted args is an OPEN ITEM; engine reads p.args positional only in v1, matching current YAML.)

----------------------------------------------------------------------
TAINT STATE (src/scanipy/engine/taint_state.py)
----------------------------------------------------------------------
  TaintProvenance (frozen): spec_id: str ; chain: tuple[WitnessStep,...]  (ordered SOURCE..PROPAGATOR.. steps already accumulated; the SINK step is appended at emission). Carries the source Location. Chains are kept SHORT (the witness path), not the whole history; on join we keep, per (spec_id) label, the deterministically-smallest chain (see determinism).
  TaintLabel (frozen): spec_id: str ; provenance: TaintProvenance . Two labels are "the same vulnerability class" iff same spec_id. The env may hold multiple provenances for one spec_id on one path; we keep the single best (shortest, then lexicographically smallest start Location) per (access_path, spec_id) to bound state and guarantee deterministic witness selection.
  TaintEnv: Mapping[AccessPath, frozenset[TaintLabel]] modeled as an immutable dict-like with ops:
     - seed(ap, label) -> add label at ap
     - get(ap) -> labels at ap PLUS labels at any bounded prefix of ap that is marked collapsed (over-approx) — see access-path rules
     - kill(ap) -> remove all labels whose key is ap OR a proper extension of ap (reassigning x clears x.a etc.)
     - assign(target_ap, rhs_labels) -> kill(target_ap) then seed each rhs label
     - sanitize(ap, spec_id) -> remove labels with that spec_id at ap (and at extensions of ap), ONE-SIDED (only on the path where the sanitizer call demonstrably feeds that ap)
     - join(other) -> per access-path UNION of label sets; for each (ap, spec_id) keep the best provenance by the deterministic rule. UNION never intersects (P5 load-bearing).
  ACCESS-PATH RULES:
     - taint is keyed by AccessPath (base var + <=STEPS_CAP attr/const-index steps).
     - At the depth cap, OVER-APPROXIMATE: an assignment to x.a.b.c collapses to prefix x.a.b (cap=2) and marks it collapsed=tainted, so reads of any sibling x.a.b.* see taint (FP-biased, never FN — deliberate divergence from Semgrep, documented P5-safe).
     - dynamic subscript x[i] (non-constant i): reading taints conservatively if base container x is tainted; writing x[i]=t taints the whole container x (collapse to base). constant subscripts x[0]/x['k'] tracked as steps.

----------------------------------------------------------------------
GENERIC PROPAGATION (src/scanipy/engine/propagation.py) — applies to ALL detectors (P4: not per-detector)
----------------------------------------------------------------------
expr_taint(expr: ExprRef, env: TaintEnv, summaries, specs) -> set[TaintLabel]: computes the labels flowing OUT of evaluating expr, plus appends a PROPAGATOR WitnessStep to each label's chain when it passes through a propagating construct. Rules (built-in, library-agnostic):
  - NAME/ATTRIBUTE/SUBSCRIPT with access_path: env.get(access_path)
  - CONST: {}
  - BINOP (+, %, also * for str repeat): union of operand taints (string concat / %-format carry taint)
  - JOINEDSTR (f-string): union of embedded subexpr taints
  - CONTAINER build [t], (t,), {k:t}, {t}: union of element taints, tracked at base when assigned (container becomes tainted)
  - COMPREHENSION [f(x) for x in it]: bind x to element-taint of it in a NESTED scope env, then union of element-expression taints (nested-scope handling; the comp var does not leak out)
  - BOOLOP (a and b)/IFEXP (a if c else b): union of branch value taints (NOT the condition — implicit/control-dependence flow is out of scope, P7)
  - CALL: see call handling below.
  - str methods on tainted receiver (".strip()", ".format()", ".join()", ".replace()", etc.): generic default = taint passes self->return and any-arg->return. Implemented as a built-in default propagator list (str method names) PLUS spec propagators. Spec propagators (DetectorSpec.propagators) are applied identically via their Flow.
CALL handling in expr_taint:
  1. If callee matches a SANITIZER pattern of spec S and the sanitized arg is tainted for S: the call's RETURN is clean of S (return-value sanitization). Record nothing as tainted-for-S in the return.
  2. Else evaluate flows from: (a) matching spec PROPAGATORS, (b) built-in default propagators, (c) the callee's FunctionSummary if callee_qualname is in-file (interprocedural), (d) fallback default for unknown external callees: taint passes through (any-arg -> return) — documented best-effort, not sound. Flow application maps from_/to tokens (any-arg/arg:N/self/return) to ExprRef positions; appends a PROPAGATOR WitnessStep at the call Location.

----------------------------------------------------------------------
INTRAPROCEDURAL PASS (src/scanipy/engine/taint.py)
----------------------------------------------------------------------
analyze_function(fn: FunctionIR, module, summaries) -> list[Finding]:
  Forward, flow-sensitive dataflow over fn's CFG to a fixpoint:
   - state: in_env[block_id], out_env[block_id]. in_env[entry] = seed PARAMS as symbolic taints? NO for intraprocedural-only findings; param symbolic taints are used only for summary computation (phase 1). For phase-2 finding emission, in_env[entry] starts empty EXCEPT that any param flagged tainted-by-summary-context is not relevant here (we emit findings within the function from real sources). Module-level sources (e.g. flask.request.* read, input() call) seed taint where they appear.
   - worklist over blocks in ascending id order; for block b: env = join(out_env[p] for p in preds(b)); run transfer over b.stmts; if out changed, enqueue succs. Cap iterations at FIXPOINT_CAP * len(blocks) (monotone lattice ⇒ terminates; cap is a safety net, log if hit).
   - transfer(stmt, env):
       * SOURCE detection: for each spec S, for each source Pattern, if a sub-expression in stmt matches it, that expression yields a label for S seeded at its target access path (on assignment) or directly checked (if it flows straight into a sink in same stmt). A source CALL like input() taints the RHS value; an attribute source flask.request.* taints the read value.
       * AssignStmt: rhs_labels = expr_taint(value, env, summaries, specs); for each target access path env.assign(ap, rhs_labels) (unpack distributes labels to each unpacked target — conservative: each target gets the union; documented). AugAssign: env.assign(ap, env.get(ap) ∪ rhs_labels).
       * SANITIZER: if a stmt assigns y = shlex.quote(x) and x is tainted-for-S, y is clean-for-S (handled in expr_taint call rule 1). One-sided: only this path.
       * SINK detection: for each spec S, each sink Pattern, if a CALL expr matches AND (matched_arg_indices yields an index whose ExprRef expr_taint contains a label for S) AND when-constraints hold AND that label is not sanitized on this path: EMIT a finding. The witness = label.provenance.chain + final SINK WitnessStep(role=SINK, location=call.location, description=spec sink pattern). Choose the surviving label with the deterministically-best (shortest, then smallest-start-location) provenance.
   - A sink reached inside a loop body emits once per textual sink site (dedup by (spec_id, sink Location, source start Location) — see dedup).

----------------------------------------------------------------------
FUNCTION SUMMARIES (src/scanipy/engine/summaries.py) — intra-file interprocedural
----------------------------------------------------------------------
  TransferFlow (frozen): src: FlowEndpoint ; dst: FlowEndpoint ; fragment: tuple[WitnessStep,...]
     FlowEndpoint ∈ { PARAM(index|name), SELF, RETURN, SINK(spec_id, sink_location), SOURCE(spec_id, source_location) }
  FunctionSummary (frozen): qualname: str ; flows: tuple[TransferFlow,...] (sorted) ; the summary answers:
     - which PARAM_i (or SELF, or in-body SOURCE) taints RETURN
     - which PARAM_i (or SELF, or in-body SOURCE) reaches which SINK (interprocedural sink-reachability fact)
  COMPUTE (phase 1):
     1. Build intra-file call graph from FunctionIR.calls/callee_qualname (engine derives Mapping qualname->callees, sorted).
     2. Condense to SCCs (Tarjan, deterministic: iterate nodes in sorted qualname order). Process SCCs in reverse-topological order (callees before callers).
     3. For a singleton non-recursive SCC: analyze the function ONCE with each formal param seeded as a SYMBOLIC taint label (a distinct spec-agnostic "param marker" label, separate namespace from real spec labels) at the param's access path in in_env[entry]; ALSO seed real in-body sources. Run the same intraprocedural dataflow. After fixpoint: read RETURN labels (from ReturnStmt values) -> any param-marker reaching return => PARAM_i->RETURN flow; any source label reaching return => SOURCE->RETURN. Record every sink hit reached by a param-marker => PARAM_i->SINK flow (with witness fragment = the chain from the param-entry step to the sink). Also self_param marker => SELF flows.
     4. For a cyclic SCC (recursion / mutual recursion): bounded monotone worklist fixpoint — initialize every member summary to empty; re-analyze members (in sorted order) applying current summaries at intra-SCC call sites; repeat until no summary grows or SUMMARY_FIXPOINT_CAP iterations reached. Monotone (flows only added) ⇒ terminates.
     5. External/stdlib callees (no in-file summary): no summary; intraprocedural pass uses spec/default propagators (see fallback).
  APPLY at a call site (phase 2 and during phase-1 of callers):
     given CallSite with callee summary and actual args:
       - for each PARAM_i->RETURN flow: if actual arg i carries label L, add L to the call's return labels (witness: append the flow.fragment spliced — see witness splicing).
       - for SELF->RETURN: if receiver carries L, add L to return labels.
       - for SOURCE->RETURN: the callee internally introduces a source; add the corresponding spec label to the return (witness fragment starts at the callee source).
       - for PARAM_i->SINK(spec_id) (or SELF->SINK, SOURCE->SINK): if actual arg i (or receiver) carries a spec_id label L (or for SOURCE-originated, unconditionally): EMIT a finding at the call site. Witness = caller-side chain of L (source -> ... -> arg) + SPLICED fragment (arg enters param -> ... -> sink inside callee). The spliced fragment is stored in the TransferFlow so no re-analysis is needed.
  WITNESS SPLICING: caller builds witness = [caller chain up to the call's arg WitnessStep (PROPAGATOR describing "arg N -> param of callee")] + [flow.fragment internal steps] ; final SINK step is the last fragment element (already a SINK role) for param->sink, or for param->return the labels continue propagating in the caller.

----------------------------------------------------------------------
DETERMINISM (P3) — src/scanipy/engine/witness.py + global discipline
----------------------------------------------------------------------
  - Iterate specs sorted by spec.id; sources/sinks/sanitizers/propagators in declared (tuple) order (tuples are ordered already); blocks by ascending id; functions by qualname; SCC members by qualname; summary flows sorted by a total key.
  - Never iterate dict/set without sorting; TaintEnv stores frozenset but all OUTPUT iteration sorts. No reliance on filesystem order (registry already sorts).
  - WITNESS SELECTION when multiple source->sink paths exist for one (spec, sink): pick the SHORTEST chain; tie-break by the lexicographically smallest tuple of (role.value, file, line, column) over the chain. This is enforced by keeping only the best provenance per (access_path, spec_id) at every join (so by emission there is one canonical chain).
  - FINDING DEDUP: dedup key = (detector_id, spec_id sink Location (file,line,col,end), source start Location). Keep one Finding per key (a sink reached by the same source via different control paths -> one finding with the canonical shortest witness).
  - FINGERPRINT (Finding.fingerprint): deterministic hash, stable across runs and machines. fingerprint = hex sha256 of a canonical string: detector_id || "\n" || cwe || "\n" || sink "file:line:col:end_line:end_col" || "\n" || witness_fp, where witness_fp = sha256 over the ordered list of "role|file|line|col|end_line|end_col" for each WitnessStep (this is the "stable witness fingerprint" tie-breaker too). Path normalization: use the path EXACTLY as it appears in Location.file (the engine receives a path string from the frontend; the caller/CLI decides relative vs absolute — engine is path-policy-agnostic, but MUST be consistent: document that fingerprints are stable for a fixed input path representation).
  - FINAL SORT of returned list[Finding]: key = (location.file, location.line, location.column, location.end_line or -1, location.end_column or -1, detector_id, fingerprint). The fingerprint final tie-break makes the order a TOTAL order even when one sink has two sources (P3 pitfall directly addressed).

----------------------------------------------------------------------
BOUNDS / PERFORMANCE (per-file isolation)
----------------------------------------------------------------------
  Constants (module-level, documented): STEPS_CAP=2 (access-path depth), FIXPOINT_CAP=8 (per-block re-visits multiplier), SUMMARY_FIXPOINT_CAP=8 (SCC iterations), MAX_LABELS_PER_PATH small (keep best provenance only). Each file analyzed independently; no global state between files (P1/per-file isolation). Monotone lattices + caps guarantee termination and near-linear behavior on typical code.

----------------------------------------------------------------------
ENGINE PUBLIC CONTRACT (unchanged signature)
----------------------------------------------------------------------
  TaintEngine(specs).analyze(module: object) -> list[Finding]. analyze narrows module to ModuleIR, runs phase 1 then phase 2, returns the sorted deduped findings. Findings respect spec.severity/cwe/message/id copied from the matched DetectorSpec (engine copies, does not invent). NO network, NO file writes (P1).


**Tasks:**
- (M) TAINT_ENGINE_1: Define IR contract module (engine/ir.py)
    Create src/scanipy/engine/ir.py with the frozen dataclasses/enums above (ExprKind, AccessStep, AccessPath with prefix/is_prefix_of, ExprRef, AssignTarget, AssignStmt/ExprStmt/ReturnStmt + StmtIR union, ParamKind/ParamSpec, BasicBlock, CallSite, FunctionIR, ModuleIR). SPDX header. mypy --strict clean. This is the shared contract between the FRONTEND component (producer) and engine (consumer). Document field semantics (esp. subexprs ordering, ITER_ELEM, self_param) in docstrings.
- (M) TAINT_ENGINE_2: Pattern matching + dotted-glob + when-constraints (engine/matching.py) [deps: TAINT_ENGINE_1]
    Implement match_dotted (single-segment `*`; left-anchored trailing `*`, right-anchored leading `*`, exact otherwise — covers os.system, subprocess.*, *.cursor.execute, *.execute, flask.request.*), match_pattern over ExprRef for CALL/ATTRIBUTE kinds, matched_arg_indices (p.args positional intersect present args, else all), when_satisfied for when={keyword:{name:value}} using ExprRef CONST equality (non-constant => False). PARAMETER/IMPORT kinds return False without crashing. Pure, class-agnostic. Update docs/dsl-reference.md wildcard semantics section.
- (L) TAINT_ENGINE_3: Taint state lattice (engine/taint_state.py) [deps: TAINT_ENGINE_1]
    Implement TaintProvenance, TaintLabel, TaintEnv (immutable) with get (incl. collapsed-prefix over-approx), assign (kill-then-seed), kill (ap + extensions), sanitize (one-sided, spec-scoped, ap + extensions), join (per-path UNION never intersect; keep best provenance per (ap,spec_id) via witness.better_chain). Enforce STEPS_CAP=2 collapse-to-prefix over-approximation. mypy --strict.
- (M) TAINT_ENGINE_4: Witness construction, selection, fingerprints (engine/witness.py) [deps: TAINT_ENGINE_1]
    Implement better_chain (shortest, then lexicographic over (role.value,file,line,column,end_line,end_column)), witness_fingerprint (sha256 over ordered step tuples), finding_fingerprint (sha256 over detector_id|cwe|sink-loc|witness_fp). Build the final SINK WitnessStep and assemble tuple[WitnessStep,...]. Deterministic, no randomness, stable across machines (no id()/hash() of objects — only field values).
- (L) TAINT_ENGINE_5: Generic built-in propagation (engine/propagation.py) [deps: TAINT_ENGINE_2, TAINT_ENGINE_3, TAINT_ENGINE_4]
    Implement expr_taint(expr, env, summaries, specs) with generic rules (NAME/ATTR/SUBSCRIPT lookup; BINOP +/%/* ; JOINEDSTR; CONTAINER build; COMPREHENSION nested scope; BOOLOP/IFEXP value-union; built-in str-method default propagators self/any-arg->return) and the CALL rule dispatch (sanitizer return-cleaning, spec propagators, built-in propagators, in-file summary application, external fallback any-arg->return). Append PROPAGATOR WitnessStep at each hop. Class-agnostic: applies to every spec equally (P4).
- (L) TAINT_ENGINE_6: Intraprocedural CFG dataflow + source seeding + sink emission (engine/taint.py: analyze_function) [deps: TAINT_ENGINE_5]
    Implement the per-function forward flow-sensitive worklist over BasicBlock CFG with join=union, in/out envs, FIXPOINT_CAP bound. transfer(): source detection seeds labels; AssignStmt (incl. unpack distribution + AugAssign) updates env; sanitizers clean one-sided; sink detection emits Finding when a restricted/any sink arg carries an unsanitized label for the spec and when-constraints hold. Copy id/cwe/severity/message from the matched DetectorSpec. Build witness via witness.py.
- (L) TAINT_ENGINE_7: Function summaries: compute to fixpoint over call graph (engine/summaries.py) [deps: TAINT_ENGINE_6]
    Build intra-file call graph from FunctionIR.calls; Tarjan SCC (deterministic, sorted nodes); reverse-topo order; singleton functions analyzed once with param-marker symbolic taints + in-body sources to derive PARAM->RETURN / PARAM->SINK / SOURCE->RETURN / SOURCE->SINK / SELF-* flows with witness fragments; cyclic SCC via bounded monotone worklist (SUMMARY_FIXPOINT_CAP). Reuse analyze_function machinery with a 'summary mode' flag (seed param markers, harvest flows instead of emitting). Sorted, deterministic output dict.
- (M) TAINT_ENGINE_8: Summary application + witness splicing at call sites (engine/summaries.py + propagation.py) [deps: TAINT_ENGINE_7]
    apply_summary(call_expr, summary, env, ...) maps actual args->formals, propagates PARAM/SELF/SOURCE->RETURN into call return labels and emits findings for *->SINK flows with spliced witnesses (caller chain + stored fragment + final sink step). Integrate into expr_taint CALL rule (return-value flows) and into analyze_function (interprocedural sink findings). Dedup interprocedural findings by the global dedup key.
- (M) TAINT_ENGINE_9: Wire TaintEngine.analyze: phases, dedup, sort, fingerprints [deps: TAINT_ENGINE_6, TAINT_ENGINE_8]
    Implement analyze(module): runtime-narrow to ModuleIR, compute_summaries (phase 1), analyze every FunctionIR incl. synthetic <module> (phase 2), collect findings, apply global DEDUP (key = detector_id, sink Location, source start Location), assign fingerprints, FINAL SORT by total key incl. fingerprint tie-break. Replace NotImplementedError. mypy --strict, ruff clean, SPDX headers.
- (M) TAINT_ENGINE_10: Unit tests: matching [deps: TAINT_ENGINE_2]
    tests/unit/test_matching.py: match_dotted cases (exact, trailing *, leading *, *.cursor.execute, flask.request.*, negatives); when_satisfied shell=True constant vs dynamic; matched_arg_indices with/without p.args. Build ExprRef fixtures directly (no frontend dependency).
- (L) TAINT_ENGINE_11: Unit tests: intraprocedural taint (TP/TN) using hand-built IR [deps: TAINT_ENGINE_6]
    tests/unit/test_taint_intraprocedural.py: source->sink direct; via assignment; via BinOp/+/f-string/str.format propagator; sanitizer (shlex.quote) clears taint (TN); reassignment kills taint; if/else join keeps taint sanitized-on-one-branch (P5); sink arg-index restriction (os.system arg0 only); when shell=True gating; attribute source flask.request.*. Assert exact witness role sequence and Locations.
- (L) TAINT_ENGINE_12: Unit tests: interprocedural summaries + splicing + recursion [deps: TAINT_ENGINE_7, TAINT_ENGINE_8]
    tests/unit/test_taint_interprocedural.py: param->return wrapper taints caller; param->sink helper emits finding at caller with spliced witness (source->arg->param->sink role order); SELF flows; recursion/mutual recursion terminates and produces correct summary; external-callee fallback (taint passes through). Hand-built FunctionIR call graph.
- (M) TAINT_ENGINE_13: Unit tests: determinism + fingerprints [deps: TAINT_ENGINE_9]
    tests/unit/test_taint_determinism.py: same IR + same specs => identical findings list (order, fingerprints) across repeated runs and shuffled spec input order (engine sorts internally); one sink two sources => total order stable, two distinct findings (or canonical dedup) deterministic; witness selection picks shortest path; fingerprint stable string (golden value).
- (M) TAINT_ENGINE_14: End-to-end integration test over real fixtures [deps: TAINT_ENGINE_9]
    tests/integration/test_end_to_end.py: PythonFrontend.parse(os-command vulnerable) + load_builtin_detectors + TaintEngine.analyze => exactly one CWE-78 finding with input()->os.system witness; safe fixture => zero findings; sql vulnerable/safe likewise. Depends on FRONTEND component and DSL parser landing.
- (M) TAINT_ENGINE_15: Docs: engine + DSL semantics + honest scope [deps: TAINT_ENGINE_9]
    Update docs/dsl-reference.md (wildcard anchoring rules, when:{keyword} constant-only, by-side-effect/kwarg-arg as future) and add docs/architecture/taint-engine.md documenting: access-path over-approx divergence from Semgrep (P5), union-at-join, one-sided sanitizers, aliasing/implicit-flow out-of-scope (P7), external-callee fallback, bound constants. Update CHANGELOG. No PyPI publish.

**acceptance_criteria:**
- TaintEngine.analyze(module) no longer raises NotImplementedError; returns list[Finding] for a ModuleIR; raises a clear TypeError if handed a non-ModuleIR object.
- Engine contains ZERO per-detector / per-CWE branching: grep for 'CWE', 'os.system', 'sql', 'flask', 'pickle' etc. in src/scanipy/engine/*.py returns nothing except in comments/docstrings; all detection comes from self._specs (P4).
- Intraprocedural: os-command vulnerable fixture yields exactly one CWE-78 finding whose witness is SOURCE(input, line9)->...->SINK(os.system,line10); safe fixture (shlex.quote + shell-less subprocess.run list) yields zero findings (P5 TN).
- SQL: vulnerable cursor.execute(format/concat) flagged CWE-89; bound-parameter execute(sql, params) NOT flagged (no string sanitizer needed — different sink shape).
- Sink arg-restriction respected: a tainted value in a non-listed arg of os.system does not trigger; subprocess.* only triggers under when shell=True with a constant True.
- Sanitizers are one-sided: tainted-on-one-branch (sanitized in `if`, not in `else`) still produces a finding (union-at-join, P5).
- Interprocedural: a tainted value passed to an in-file helper that forwards it to a sink produces a finding at the appropriate site with a spliced witness reading source -> arg-enters-param -> ... -> sink; recursion/mutual recursion terminate within SUMMARY_FIXPOINT_CAP.
- Import aliasing resolved (engine matches dotted patterns via ExprRef.dotted populated by frontend); `from os import system; system(x)` matches os.system (verified via frontend-produced IR in integration test, and via hand-built ExprRef.dotted in unit tests).
- Determinism (P3): two runs on identical input produce byte-identical Finding lists incl. fingerprints; shuffling the input spec order does not change output; final ordering is a TOTAL order (fingerprint tie-break) even with one sink / two sources.
- Finding.fingerprint is a stable hex sha256 derived only from field values (detector_id, cwe, sink Location, ordered witness step tuples) — no object id()/PYTHONHASHSEED dependence.
- Every core detector ships a TP and TN fixture under tests/fixtures/python/{vulnerable,safe}/ and the engine classifies them correctly (P5).
- Quality gates green: ruff (line-length 100, double quotes), mypy --strict on src/, pytest all pass; SPDX header on every new .py file.
- No network and no file writes anywhere in analyze() (P1); each file analyzed in isolation with no cross-file/global mutable state.

**tests:**
- test_matching.match_dotted: exact ('os.system'~'os.system' True, ~'os.popen' False); trailing wildcard ('subprocess.*'~'subprocess.run' True, ~'subprocess' False, ~'subprocess.a.b' decision-documented); leading wildcard ('*.cursor.execute'~'db.cursor.execute' True, '*.execute'~'cur.execute' True, ~'execute' boundary); attribute ('flask.request.*'~'flask.request.args' True).
- test_matching.when_satisfied: shell=True constant -> True; shell=False -> False; shell=var (non-const) -> False; missing keyword -> False.
- test_matching.matched_arg_indices: p.args=(0,) restricts to index 0; p.args=None returns all present positional indices.
- test_taint_intraprocedural: direct source->sink; through one assignment; through BinOp '+'; through f-string; through str.format propagator; through os.path.join propagator; sanitizer shlex.quote removes taint (TN); reassignment to constant kills taint (TN); AugAssign x+=tainted taints x (TP).
- test_taint_intraprocedural.join_union: sanitized only in `if` branch -> still flagged (P5); sanitized in BOTH branches -> not flagged.
- test_taint_intraprocedural.sink_constraints: os.system non-arg0 taint -> no finding; subprocess.run(..., shell=True) tainted -> finding; subprocess.run(list, shell omitted) -> no finding.
- test_taint_intraprocedural.access_path: x.a tainted, sink(x.a) flagged; depth-cap over-approx collapses x.a.b.c and taints sibling read (FP-biased, asserted as intended behavior).
- test_taint_intraprocedural.witness_exact: assert the full ordered (role, line, col) witness tuple for a multi-hop flow.
- test_taint_interprocedural.param_to_return: helper returns its tainted arg; caller sinks the result -> finding with spliced witness.
- test_taint_interprocedural.param_to_sink: helper sinks its arg; caller passes tainted value -> finding at the helper-internal sink with witness source->arg->param->sink.
- test_taint_interprocedural.self_flow: method self/receiver taint flow.
- test_taint_interprocedural.recursion: self-recursive and mutually-recursive helpers terminate and yield correct summaries.
- test_taint_interprocedural.external_fallback: unknown stdlib-ish callee passes taint through (any-arg->return) — documented best-effort.
- test_taint_determinism.repeatable: analyze twice -> identical lists incl. fingerprints.
- test_taint_determinism.spec_order_invariant: shuffle specs input -> identical output.
- test_taint_determinism.total_order: one sink fed by two sources -> deterministic stable order (fingerprint tie-break) and deterministic dedup.
- test_taint_determinism.fingerprint_golden: a fixed finding -> exact expected sha256 hex (guards against accidental format changes).
- test_end_to_end: real PythonFrontend + load_builtin_detectors over os-command and sql vulnerable/safe fixtures -> expected TP/TN counts, CWE, and witness shape (depends on FRONTEND + DSL parser components).

**risks:**
- Component boundary: the engine depends on a concrete IR + on ExprRef.dotted/callee_qualname being correctly populated by the PythonFrontend component (import resolution, CFG construction, qualname assignment). If the frontend lags or its IR diverges, engine integration tests (TAINT_ENGINE_14) block. Mitigation: ir.py is delivered with the engine as the frozen contract; engine unit tests build IR by hand so the algorithm is testable without the frontend; only end-to-end tests depend on the frontend landing.
- Defining ir.py here vs. in the frontend component could cause ownership conflict / duplicate definitions across the two PRs. Mitigation: declare ir.py as engine-owned in the master plan; frontend imports from scanipy.engine.ir.
- Access-path over-approximation at the depth cap can produce false positives on deep attribute chains; this is intentional (P5-safe) but may surprise users. Mitigation: document clearly; keep STEPS_CAP=2 to limit blast radius.
- External-callee fallback (taint passes through) can over-taint and create FPs on benign wrapper calls; alternatively a too-narrow fallback risks FNs. Spec chooses pass-through (FP-biased, P5-safe) and documents it (P7). Tunable later via DSL propagators.
- Summary fixpoint on large/cyclic SCCs could hit SUMMARY_FIXPOINT_CAP and under-approximate (miss some flows) on pathological recursion. Monotone + capped guarantees termination but the cap is a soundness/perf tradeoff; log when hit; pick cap=8.
- when:{keyword} only evaluates CONSTANT values; shell=some_var won't trigger the shell=True sink -> potential FN. Documented as honest limitation (P7); acceptable for v1.
- Witness chain length grows with propagation depth; keeping only the best provenance per (ap,spec_id) bounds it but could occasionally drop an alternative (equally valid) witness — deterministic shortest is chosen by design.
- kwarg-targeted sink args and by-side-effect (list.append/dict[..]=) mutators are NOT in v1 (engine reads positional p.args only); detectors needing them (rare in the core 6-8) could miss flows. Flagged as DSL extension, deferred.
- fingerprint stability depends on Location.file representation chosen by the CLI/caller (relative vs absolute). If the caller changes path normalization, fingerprints change. Mitigation: document; recommend the CLI pass repo-relative paths consistently.

**open_questions:**
- Exact wildcard semantics for multi-segment: should 'subprocess.*' match 'subprocess.a.b' (deep) or only one trailing segment? Spec proposes single-segment trailing match (subprocess.run yes, subprocess.a.b no); confirm against intended detector coverage and lock in dsl-reference.md.
- For unpacking `a, b = func()` where the summary says PARAM->RETURN, do we distribute taint to both a and b (conservative union) or attempt tuple-element precision? Spec proposes conservative union to all targets; confirm acceptable FP level.
- Should the synthetic '<module>' top-level scope be analyzed for findings (module-level scripts) — yes per spec; confirm fixtures include a function-wrapped case so both paths are covered.
- Path representation for Location.file / fingerprint stability: should the engine normalize (e.g. as-given) or should the CLI guarantee repo-relative? Recommend CLI owns normalization; confirm with the cli-ux component owner.
- Is the DSL `parameter` SOURCE kind needed by any of the 6-8 core detectors (e.g. a Flask route handler param as an entrypoint source)? If yes it becomes a blocking DSL extension; if the core pack uses flask.request.* attribute sources instead, it stays deferred. Confirm with the detector-author component.
- Severity threshold / fail-on filtering: does the engine apply ScanConfig.severity_threshold, or is filtering the CLI's job? Spec assumes the engine returns ALL findings and the CLI filters; confirm ownership.
- Do we need a per-finding dedup that merges multiple sources into one finding with multiple witnesses, or emit one finding per (source,sink) pair? Spec emits one per (detector,sink,source-start) — confirm desired UX.

==========================================================================================
## COMPONENT: Detector catalog + fixtures (v1 core 6 + 2 stretch)

**Summary:** Specifies the v1 detector catalog as declarative taint-DSL YAML specs plus their paired true-positive/true-negative fixtures (P5). All detection knowledge lives in the YAML (P4); this subsystem authors data only — no engine code. It delivers the 6 locked core detectors (os-command exists, sql exists, code-injection, path-traversal, ssrf, unsafe-deserialization) and 2 stretch detectors (xxe, tls-verify-disabled), each grounded in real Python/framework APIs expressible against the frozen Pattern/Flow surface. Its load-bearing output beyond the specs is an explicit DSL gap list handed to the dsl-parser and taint-engine subsystems, including two real architectural gaps (sourceless tls-verify-disabled and when-negation for yaml SafeLoader).

**Key files:** src/scanipy/detectors/injection/os-command.yml (exists — verify/keep), src/scanipy/detectors/injection/sql.yml (exists — verify/keep), src/scanipy/detectors/injection/code-injection.yml (new), src/scanipy/detectors/traversal/path-traversal.yml (new), src/scanipy/detectors/ssrf/ssrf.yml (new), src/scanipy/detectors/deserialization/unsafe-deserialization.yml (new), src/scanipy/detectors/xxe/xxe.yml (new, stretch), src/scanipy/detectors/tls/tls-verify-disabled.yml (new, stretch — gated on engine presence-sink feature), tests/fixtures/python/vulnerable/os-command.py (exists), tests/fixtures/python/safe/os-command.py (exists), tests/fixtures/python/vulnerable/sql.py (new), tests/fixtures/python/safe/sql.py (new), tests/fixtures/python/vulnerable/code-injection.py (new), tests/fixtures/python/safe/code-injection.py (new), tests/fixtures/python/vulnerable/path-traversal.py (new), tests/fixtures/python/safe/path-traversal.py (new), tests/fixtures/python/vulnerable/ssrf.py (new), tests/fixtures/python/safe/ssrf.py (new), tests/fixtures/python/vulnerable/unsafe-deserialization.py (new), tests/fixtures/python/safe/unsafe-deserialization.py (new), tests/fixtures/python/vulnerable/xxe.py (new), tests/fixtures/python/safe/xxe.py (new), tests/fixtures/python/vulnerable/tls-verify-disabled.py (new, stretch), tests/fixtures/python/safe/tls-verify-disabled.py (new, stretch), tests/fixtures/python/vulnerable/interprocedural.py (new — exercises intra-file summaries), tests/fixtures/python/safe/interprocedural.py (new), tests/integration/test_detectors.py (new — per-detector TP/TN matrix), docs/dsl-reference.md (update — record forced DSL extensions and gaps), docs/writing-detectors.md (referenced by dsl-reference; ensure catalog conventions documented)

**Interfaces:**
```
Specs are pure YAML conforming to docs/dsl-reference.md and parsed into the REAL frozen types (no new types introduced by this subsystem):\n\n# scanipy/dsl/spec.py (existing, frozen)\nDetectorSpec(id: str, name: str, cwe: str, severity: Severity, languages: tuple[str,...], message: str, sources: tuple[Pattern,...], sinks: tuple[Pattern,...], sanitizers: tuple[Pattern,...]=(), propagators: tuple[Propagator,...]=(), metadata: Mapping[str,object]=...)\n\n# scanipy/dsl/patterns.py (existing, frozen)\nPatternKind: CALL='call' | ATTRIBUTE='attribute' | PARAMETER='parameter' | IMPORT='import'\nPattern(kind: PatternKind, pattern: str, args: tuple[int,...]|None=None, when: Mapping[str,object]|None=None)\nFlow(from_: str, to: str)  # vocab: 'any-arg' | 'arg:N' | 'self' | 'return'\nPropagator(pattern: Pattern, flow: Flow)\n\n# YAML surface every spec uses (mapping to the above):\n# sources/sinks/sanitizers: list of {kind, pattern, args?, when?}\n# propagators: list of {kind, pattern, flow: {from, to}}\n# when: {keyword: {name: value}}  (only positive-equality supported in v1)\n\n# Findings produced when an engine runs these specs (scanipy/models.py, frozen) — what tests assert against:\nFinding(detector_id: str, cwe: str, severity: Severity, message: str, location: Location, witness: tuple[WitnessStep,...]=(), fingerprint: str|None=None)\nWitnessStep(role: WitnessRole, location: Location, description: str='')  # roles SOURCE/PROPAGATOR/SANITIZER/SINK\nLocation(file: str, line: int, column: int=0, end_line: int|None=None, end_column: int|None=None)\n\n# Discovery/loading entry points this subsystem depends on (other subsystems own the impl):\nregistry.discover_spec_files() -> tuple[Path,...]   # WORKS: rglob('*.yml') sorted\nregistry.load_builtin_detectors() -> tuple[DetectorSpec,...]  # STUB -> must parse all specs (registry/parser subsystem)\ndsl.parse_spec(text: str, *, source_path: str|None=None) -> DetectorSpec  # STUB (parser subsystem)\ndsl.load_spec_file(path: str|Path) -> DetectorSpec\nengine.taint.TaintEngine(specs: Sequence[DetectorSpec]); .analyze(module) -> list[Finding]  # STUB (engine subsystem)\nfrontends.python_frontend.PythonFrontend(language='python').parse(path: Path) -> object  # STUB (frontend subsystem)\n\n# Fixture contract (data files, no runtime interface): each tests/fixtures/python/{vulnerable,safe}/<name>.py starts with\n#   # SPDX-License-Identifier: Apache-2.0\n#   # <TP|TN> fixture for detector <id>. Expected: <N findings | NO finding>. <one-line rationale>\n# Files are extend-excluded from ruff and outside mypy src; they are parsed by the analyzer but never imported/executed.
```

**Design:**
Detailed in the design field above; tasks below.

**Tasks:**
- (S) DETECTOR_CATALOG_1: Confirm/validate existing os-command and sql specs against finished schema [deps: DSL_PARSER_1]
    Re-read injection/os-command.yml and injection/sql.yml; confirm they validate cleanly under the implemented parse_spec and match the dsl-reference. No content change expected for os-command. For sql, confirm the no-sanitizers-by-design decision is preserved. This task is the parse-conformance smoke for the two seed specs.
- (S) DETECTOR_CATALOG_2: Author sql TP/TN fixtures (missing today)
    Create tests/fixtures/python/vulnerable/sql.py (cursor.execute string-concat with input()) and tests/fixtures/python/safe/sql.py (route the SAME tainted value into the bound-parameter form cursor.execute(sql, (name,)) so taint is in arg[1], not the args:[0] sink). SPDX header + expected-outcome comment on each. Files must be valid Python AST but are never executed.
- (M) DETECTOR_CATALOG_3: Author code-injection spec (CWE-94, critical) + TP/TN fixtures
    Create detectors/injection/code-injection.yml: sources input + flask.request.*; sinks eval/exec/compile args:[0] (bare builtin names); no sanitizers; str.format propagator. TP fixture: eval(input()). TN fixture: ast.literal_eval(input()) (tainted into a safe sink with a different name). Verify bare-builtin matching is on the parser/engine gap list (GAP-D).
- (M) DETECTOR_CATALOG_4: Author path-traversal spec (CWE-22, high) + TP/TN fixtures
    Create detectors/traversal/path-traversal.yml: sources input + flask.request.*; sinks open/io.open/os.remove/os.unlink/shutil.copy(args 0,1)/shutil.move(args 0,1)/pathlib.Path args:[0]; sanitizers os.path.basename + werkzeug.utils.secure_filename; propagators os.path.join + str.format. TP: open(os.path.join('/data', flask.request.args['f'])). TN: route through secure_filename then open. Document the pathlib.Path().open() chain limitation in the spec comment.
- (M) DETECTOR_CATALOG_5: Author ssrf spec (CWE-918, high) + TP/TN fixtures
    Create detectors/ssrf/ssrf.yml: sources input + flask.request.*; sinks requests.{get,post,put,delete,head,patch} args:[0], requests.request args:[1], requests.Session.* args:[0], urllib.request.urlopen/Request args:[0], httpx.{get,post} args:[0]; no sanitizers (none expressible). TP: requests.get('http://'+flask.request.args['host']). TN: requests.get(constant URL) — honest-scope: TN tests untainted-arg, not a sanitizer; state this in the fixture comment. Add the requests.Session.* precision caveat to GAP-C and the kwarg-url blind spot to GAP-E.
- (M) DETECTOR_CATALOG_6: Author unsafe-deserialization spec (CWE-502, critical) + TP/TN fixtures
    Create detectors/deserialization/unsafe-deserialization.yml: sources input + flask.request.*; sinks pickle.loads/load, cPickle.loads, yaml.load/full_load/unsafe_load, marshal.loads, dill.loads, jsonpickle.decode (all args:[0]); no sanitizers. TP: pickle.loads(flask.request.data). TN: yaml.safe_load(flask.request.data) (tainted into safe sink, different name). Record GAP-B (yaml.load(...,Loader=SafeLoader) false positive, no when-negation) as a known limitation in the spec comment + dsl-reference.
- (M) DETECTOR_CATALOG_7: Author xxe stretch spec (CWE-611, high) + TP/TN fixtures
    Create detectors/xxe/xxe.yml: sources input + flask.request.*; sinks xml.etree.ElementTree.{fromstring,parse,XML}, xml.dom.minidom.{parseString,parse}, xml.sax.parseString, lxml.etree.{fromstring,parse,XML} (args:[0]); no sanitizers. TP: lxml.etree.fromstring(flask.request.data). TN: defusedxml.ElementTree.fromstring(flask.request.data) (tainted into safe module, different dotted path). Document the stdlib-ElementTree-safe-by-default conservative-stance nuance in the spec comment.
- (M) DETECTOR_CATALOG_8: Author tls-verify-disabled stretch spec (CWE-295) — GATED on engine presence-sink feature [deps: TAINT_ENGINE_PRESENCE_SINK]
    BLOCKED design task. Write detectors/tls/tls-verify-disabled.yml ONLY IF the engine subsystem adopts a sourceless/presence-sink mode (GAP-A). Intended sinks: requests.* / requests.Session.* when verify=False, httpx.Client when verify=False, ssl._create_unverified_context, urllib3.disable_warnings. TP: requests.get(url, verify=False). TN: requests.get(url, verify=True)/default. If presence-sinks are NOT adopted in v1, DEFER this detector and record the deferral in docs (do not ship a spec that silently never fires). Decision recorded as an open question resolved by the engine subsystem.
- (M) DETECTOR_CATALOG_9: Author interprocedural TP/TN fixtures (exercise intra-file summaries)
    Create tests/fixtures/python/{vulnerable,safe}/interprocedural.py. Vulnerable: helper run_cmd(c) calls os.system(c); handler calls run_cmd(input()) — expects ONE os-command finding with a spliced witness (source -> arg-enters-param -> sink). Safe: helper uses subprocess.run([c]) with no shell; handler passes input — no finding. Owned as data here; verification depends on the engine summary feature.
- (L) DETECTOR_CATALOG_10: Write per-detector TP/TN integration test matrix [deps: DETECTOR_CATALOG_1, DETECTOR_CATALOG_2, DETECTOR_CATALOG_3, DETECTOR_CATALOG_4, DETECTOR_CATALOG_5, DETECTOR_CATALOG_6, DETECTOR_CATALOG_7, DETECTOR_CATALOG_9, DSL_PARSER_1, TAINT_ENGINE_1, PYTHON_FRONTEND_1]
    Create tests/integration/test_detectors.py: parametrized over each detector id, load its spec (load_builtin_detectors / load_spec_file), run TaintEngine over the matching vulnerable + safe fixture via PythonFrontend, assert (a) the vulnerable fixture yields >=1 finding whose detector_id == the detector under test, with correct cwe/severity and a non-empty witness ending in a SINK step; (b) the safe fixture yields ZERO findings FOR THAT detector_id; (c) cross-trip guard: no fixture trips a DIFFERENT detector unexpectedly (assert the full finding set per fixture is exactly the expected id set). Also assert determinism: running analyze twice on the same fixture yields byte-identical reporter output (P3). Use plain assert (matches existing harness). Mark @pytest.mark.integration.
- (S) DETECTOR_CATALOG_11: Update docs/dsl-reference.md with v1 known-limitations + forced DSL extensions [deps: TAINT_ENGINE_1, DSL_PARSER_1]
    Add a 'v1 known limitations / honest scope (P7)' section documenting GAP-A..GAP-F: sourceless/presence-sink need (tls), no when-negation (yaml SafeLoader FP), method-name/wildcard matching semantics, bare-builtin matching, positional-only args (kwarg-url blind spot), and parameter/import kinds untested (Django out of scope). Where the engine forces a DSL extension (kwarg-targeted args, by-side-effect propagators), record it here since this file co-evolves with the engine. Cross-link from each affected spec's header comment.
- (S) DETECTOR_CATALOG_12: Wire catalog into rules list/show, scan, and CHANGELOG/version [deps: DETECTOR_CATALOG_10, DETECTOR_CATALOG_11]
    Confirm the new specs appear in `scanipy rules list` and render in `rules show <id>` (engine/CLI subsystem owns the commands; this task verifies the catalog is discovered by discover_spec_files via the new subdirs and adds a row per detector). Add a CHANGELOG entry enumerating the v1 catalog and bump the version per the release task. Update README detector table to list all v1 detectors with CWE/severity. No PyPI publish.

**acceptance_criteria:**
- All 6 core detector specs (os-command, sql, code-injection, path-traversal, ssrf, unsafe-deserialization) exist under src/scanipy/detectors/<class>/<name>.yml, parse without error via dsl.parse_spec, and are returned by registry.load_builtin_detectors() in sorted, deterministic order.
- Every spec uses ONLY the frozen DSL surface: PatternKind in {call, attribute}; Flow vocab in {any-arg, arg:N, self, return}; when limited to {keyword: {name: value}}; no construct outside docs/dsl-reference.md (P4). No engine/parser code is written by this subsystem.
- Each of the 8 detectors (6 core + up to 2 stretch that are actually shipped) has BOTH a vulnerable and a safe fixture under tests/fixtures/python/{vulnerable,safe}/<name>.py, each carrying an SPDX header and an expected-outcome comment (P5).
- Every safe (TN) fixture that has a real expressible sanitizer/safe-API routes the SAME tainted value into the safe form (secure_filename, ast.literal_eval, bound params, yaml.safe_load, defusedxml) — testing sink/sanitizer discrimination, not mere absence of taint. No fabricated sanitizers are introduced to fill a TN slot (P5 one-sidedness preserved).
- SSRF's TN is explicitly documented as the no-expressible-sanitizer case (constant/untainted URL), called out honestly in the fixture comment and docs (P7).
- Per-detector integration test (tests/integration/test_detectors.py) passes: each vulnerable fixture yields >=1 finding with the correct detector_id/cwe/severity and a non-empty witness ending in a SINK step; each safe fixture yields zero findings for its detector; no fixture cross-trips an unexpected detector.
- Determinism (P3): running the engine twice over the same fixture produces byte-identical reporter output; findings are stably sorted.
- tls-verify-disabled is EITHER shipped with an engine presence-sink feature and passing TP/TN, OR explicitly deferred with the reason recorded — never shipped as a source->sink spec that silently never fires.
- yaml unsafe-deserialization TN uses yaml.safe_load (not yaml.load(...,Loader=SafeLoader)); the SafeLoader false-positive is recorded as a known limitation in docs/dsl-reference.md.
- docs/dsl-reference.md gains a v1 known-limitations section covering GAP-A..GAP-F; README detector table and CHANGELOG enumerate the v1 catalog; version bumped (P7, definition-of-done).
- ruff (line-length 100, double quotes), mypy --strict, and pytest all stay green; fixtures remain under the ruff extend-exclude and outside mypy src (only SPDX header required on each fixture).
- scanipy rules list shows every shipped detector and scan works end-to-end on the fixture corpus (definition-of-done).

**tests:**
- tests/integration/test_detectors.py: parametrized per detector id — vulnerable fixture yields >=1 finding with matching detector_id, correct cwe (e.g. CWE-94 for code-injection) and severity, and witness[-1].role == WitnessRole.SINK with non-empty witness.
- tests/integration/test_detectors.py: parametrized per detector id — safe fixture yields ZERO findings for that detector_id.
- tests/integration/test_detectors.py: cross-trip guard — for each fixture, the set of detector_ids in the findings equals the expected set (vulnerable: exactly {its id}; safe: empty), so e.g. the path-traversal vulnerable fixture does not also trip os-command.
- tests/integration/test_detectors.py: SQL TN discrimination — cursor.execute(sql, (name,)) (taint in arg[1]) produces no sql finding while the concat form does (validates args:[0] restriction).
- tests/integration/test_detectors.py: code-injection — eval(input()) flagged; ast.literal_eval(input()) not flagged (safe-API discrimination with tainted data).
- tests/integration/test_detectors.py: path-traversal — secure_filename / os.path.basename sanitizer removes taint on its path; the unsanitized open(os.path.join(...)) fires.
- tests/integration/test_detectors.py: deserialization — pickle.loads(tainted) flagged; yaml.safe_load(tainted) not flagged; (documented) note that yaml.load(x,Loader=SafeLoader) currently DOES flag (xfail/known-limitation test or doc reference).
- tests/integration/test_detectors.py: ssrf — tainted-host requests.get flagged; constant-URL requests.get not flagged.
- tests/integration/test_detectors.py: xxe — lxml.etree.fromstring(tainted) flagged; defusedxml.ElementTree.fromstring(tainted) not flagged.
- tests/integration/test_detectors.py: interprocedural — run_cmd(input()) -> os.system(c) yields one finding with a spliced witness whose ordered roles read SOURCE ... SINK and traverse the callee param; the subprocess-list safe variant yields none.
- tests/integration/test_detectors.py: determinism — engine.analyze() run twice on the same fixture yields findings with identical fingerprints/order and byte-identical JsonReporter output (P3).
- tests/integration/test_detectors.py: import-aliasing — a fixture variant using `from subprocess import run; run(x, shell=True)` and `from os import system; system(x)` is still flagged by os-command (validates engine canonicalization the catalog relies on; coordinate with engine tests).
- tests/unit (extend existing test_core.py style): assert load_builtin_detectors() returns one DetectorSpec per shipped spec file with unique ids and that every id matches the <language>.<class>.<name> convention.
- Aliased/edge-case TN: a safe fixture using yaml.safe_load and one using ast.literal_eval confirm no over-firing when a safe API shares a module with an unsafe one (yaml.load vs yaml.safe_load).

**risks:**
- tls-verify-disabled does not fit the source->sink taint architecture (sourceless). If the engine does not add a presence-sink mode, the detector must be deferred; shipping it naively would yield a detector that silently never fires, violating P7 and the definition-of-done.
- yaml.load(x, Loader=yaml.SafeLoader) will be a false positive under the bare-yaml.load sink because the DSL lacks when-negation. P5 makes this an acceptable FP, but it can erode user trust; mitigated by documenting it and choosing yaml.safe_load (not the SafeLoader form) for the TN.
- Wildcard/method-name matching is underspecified: *.execute, *.cursor.execute, requests.Session.*, str.format match without types. requests.Session.* likely will NOT fire on s = requests.Session(); s.get(url) without type inference, leaving a coverage gap that the baseline requests.get/post sinks only partially cover.
- Positional-only args (args:[0]/args:[1]) miss keyword-passed sinks like requests.get(url=tainted) and yaml.load(stream=tainted); without kwarg-targeted args this is a real blind spot (false negative) the catalog cannot close alone.
- Overlapping sinks within a detector (e.g. *.execute and *.cursor.execute both matching cursor.execute) can double-report unless the engine de-dupes by (detector_id, sink location); this is an engine dependency the catalog must flag.
- All non-trivial fixtures depend on engine + parser + frontend being complete; the verification tests cannot pass until those land, so catalog 'done' is gated on cross-component tasks and the dependency-ordered PR flow must sequence them.
- Conservative XXE stance (flagging stdlib ElementTree which is XXE-safe by default in modern Python) produces false positives; mitigated by P5 (FP over FN) and documentation, but may surprise users on modern stdlib.
- Fixtures reference third-party APIs (requests, lxml, yaml, werkzeug, defusedxml, httpx, dill, jsonpickle) that are NOT runtime deps; since fixtures are parsed-not-executed and lint-excluded this is fine, but a reviewer might mistake them for missing dependencies — call out that fixtures are analysis data.
- Django/request.GET-POST and any parameter-source-based detector are out of scope without the parameter kind, leaving a common framework under-covered; honest-scope risk if users expect Django coverage in v1.
- Determinism can break if two sources reach one sink (collision on file,line,column,detector_id); the catalog must not assume the engine handles this — flagged so the engine adds a witness-fingerprint tie-break (P3).

**open_questions:**
- Does the taint-engine subsystem adopt a sourceless 'presence-sink' / config-flag detector mode in v1 (GAP-A)? This is the gate for shipping vs deferring tls-verify-disabled.
- Will the DSL add when-negation / keyword-not-equal / keyword-absent (GAP-B)? Needed to make yaml.load(...,Loader=SafeLoader) safe and to precisely express subprocess.* shell=False. v1 default is to live with the FP.
- Exact wildcard and method-name matching semantics (GAP-C): does leading-* match exactly one receiver expression or any chain? Can the engine match requests.Session.* on an instance obtained from requests.Session() without type inference? This determines real SSRF coverage.
- Should args support keyword-targeted taint (e.g. args includes a named kwarg) so requests.get(url=...) and yaml.load(stream=...) are covered (GAP-E)? Prior art recommends it; decide whether v1 ships it or documents the positional-only blind spot.
- Do we exercise PatternKind.parameter / .import in v1 at all (GAP-F)? If no detector uses them they ship untested — either add a Django/parameter-source detector or descope those kinds to PLANNED. The repo note says v1 should implement them; reconcile with the catalog reality.
- How does the engine de-duplicate overlapping sinks within one detector (e.g. *.execute vs *.cursor.execute) so a single dangerous call is reported once with a stable witness?
- Final placement convention: confirm detectors/<class>/<name>.yml subdirectories (traversal/, ssrf/, deserialization/, xxe/, tls/) are acceptable and that discover_spec_files' rglob picks them up (it does today) — versus flattening everything under injection/ or a single dir.
- Are the two stretch slots best spent on xxe + tls-verify-disabled, or should the second stretch slot go to a detector that DOES fit taint cleanly (e.g. template/Jinja2 SSTI or insecure-temp-file) if tls-verify-disabled is deferred for lack of presence-sink support?

==========================================================================================
## COMPONENT: CLI scan pipeline, config, file discovery, reporting integration

**Summary:** This subsystem turns the wired-but-stubbed CLI into a working end-to-end scanner: a thin `cli.py` delegates to a new orchestrator module `scanner.py` that discovers target `.py` files, loads the active detector specs via the registry, runs `PythonFrontend.parse` + `TaintEngine.analyze` per file, aggregates/filters/sorts/dedups findings deterministically, renders via `get_reporter`, and computes the exit code. It also implements `rules list/show/validate` over the registry + `parse_spec`, and a layered config loader (`.scanipy.yml` and `[tool.scanipy]` in `pyproject.toml`) with CLI > file > defaults precedence while keeping zero-config (P6) working. The engine/frontend/parser internals are owned by other tracks; this subsystem only consumes their existing signatures.

**Key files:** src/scanipy/scanner.py (NEW — orchestrator: discovery, run loop, aggregate/filter/sort/dedup, exit-code helper), src/scanipy/cli.py (REWRITE scan + rules subcommands; keep group/version untouched), src/scanipy/config.py (REWRITE load_config: .scanipy.yml + [tool.scanipy] discovery and merge; add ScanConfig.merged_with helper), src/scanipy/discovery.py (NEW — file walking + exclude/.gitignore matching; or fold into scanner.py — see open questions), src/scanipy/registry.py (IMPLEMENT load_builtin_detectors via parse_spec; add load_detector_specs(selected) selection/error helper), tests/unit/test_cli.py (REWRITE stub-exit tests to assert real behavior), tests/unit/test_config.py (NEW), tests/unit/test_discovery.py (NEW), tests/unit/test_scanner.py (NEW), tests/integration/test_scan_e2e.py (NEW — runs against tests/fixtures/python), docs/usage.md (UPDATE — remove 'stub' language for scan/rules; document config precedence + .gitignore behavior), docs/dsl-reference.md (UPDATE only if config schema section added), README.md + CHANGELOG.md (UPDATE), src/scanipy/__init__.py (version bump to 0.2.0 per release-eng track)

**Interfaces:**
```
## config.py
class ConfigError(ValueError): ...

@dataclass(frozen=True)
class ScanConfig:
    detectors: tuple[str, ...] = ()
    severity_threshold: Severity = Severity.LOW
    fail_on: Severity | None = None
    exclude: tuple[str, ...] = ()
    output_format: str = "text"
    gitignore: bool = True            # NEW field

def load_config(path: str | Path | None = None) -> ScanConfig: ...
def resolve_config(*, file_config: ScanConfig, detectors: tuple[str,...] | None, severity_threshold: Severity | None, fail_on: Severity | None | _Unset, exclude: tuple[str,...] | None, output_format: str | None, gitignore: bool | None) -> ScanConfig: ...
# None means "CLI did not override"; for --exclude, additive merge.

## discovery.py
DEFAULT_EXCLUDE_DIRS: frozenset[str]
def discover_python_files(root: Path, *, exclude: Sequence[str] = (), use_gitignore: bool = True) -> list[Path]: ...

## registry.py (additions)
def load_builtin_detectors() -> tuple[DetectorSpec, ...]: ...   # implement (was stub)
def load_detector_specs(selected: Sequence[str] = ()) -> tuple[DetectorSpec, ...]: ...

## scanner.py
@dataclass(frozen=True)
class ScanError:
    file: str
    message: str

@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    errors: tuple[ScanError, ...] = ()

def run_scan(target: Path, config: ScanConfig) -> ScanResult: ...
def compute_exit_code(result: ScanResult, *, fail_on: Severity | None, threshold: Severity) -> ExitCode: ...
def _finding_sort_key(f: Finding) -> tuple[str, int, int, str, str]: ...
def _witness_fingerprint(f: Finding) -> str: ...   # sha256 hex of ordered (role, file, line, col)

## Consumed (existing, unchanged):
PythonFrontend().parse(path: Path) -> object
TaintEngine(specs: Sequence[DetectorSpec]).analyze(module: object) -> list[Finding]
get_reporter(output_format: str) -> Reporter; Reporter.render(findings: Sequence[Finding]) -> str
Severity.from_str / .rank ; ExitCode(OK=0, FINDINGS=1, ERROR=2)
DetectorSpec(id, name, cwe, severity, languages, message, sources, sinks, sanitizers, propagators, metadata)
```

**Design:**
DETAILED ALGORITHM is captured in the `design` field; this `interfaces` payload lists the concrete signatures. See the StructuredOutput design field for the full prose.

**Tasks:**
- (M) CLI_SCAN_PIPELINE_1: Config loader: .scanipy.yml + [tool.scanipy] discovery and validation
    Rewrite config.py. Add ConfigError(ValueError) and a gitignore:bool=True field to ScanConfig. Implement load_config(path): if path given load that exact file (yaml for .yml, tomllib/tomli for pyproject by extension); else walk up from cwd to find first dir with .scanipy.yml or pyproject.toml[tool.scanipy] (.scanipy.yml wins ties). Map snake_case keys to ScanConfig fields; parse severity_threshold/fail_on via Severity.from_str; validate output_format in {text,json,sarif}; reject unknown keys and bad enum values with ConfigError. Handle 3.10 (no tomllib) per the chosen pyproject strategy. Keep ScanConfig() the zero-config baseline (P6). SPDX header, mypy --strict clean, ruff (line-length 100, double quotes).
- (S) CLI_SCAN_PIPELINE_2: Config merge: CLI > file > defaults with click parameter-source detection [deps: CLI_SCAN_PIPELINE_1]
    Add resolve_config(...) pure function that overlays CLI-provided values onto file_config (None = not provided). Scalars replace; --detectors replaces if non-empty; --exclude is ADDITIVE (defaults+file+CLI). Document additive exclude semantics. Unit-test independently of click. The CLI uses click.Context.get_parameter_source to decide which options were user-supplied (COMMANDLINE/ENVIRONMENT) vs defaults.
- (M) CLI_SCAN_PIPELINE_3: File discovery with default + glob excludes and deterministic ordering
    Create discovery.py (or fold into scanner.py): discover_python_files(root, *, exclude, use_gitignore). os.walk with in-place pruning of DEFAULT_EXCLUDE_DIRS (frozenset: .venv,venv,.git,__pycache__,build,dist,.tox,.mypy_cache,.ruff_cache,.pytest_cache,node_modules,.eggs,*.egg-info). Honor --exclude globs against POSIX relative path AND basename via fnmatch. Single-file root: return [root] if .py. Always return sorted(list) by as_posix() (P3). SPDX header; ruff/mypy clean.
- (M) CLI_SCAN_PIPELINE_4: .gitignore honoring (best-effort, stdlib-only, default-on, --no-gitignore opt-out) [deps: CLI_SCAN_PIPELINE_3]
    Parse root .gitignore (and optionally nested) into the common glob subset (dir/, *.ext, leading-/ anchoring, ! negation) and apply during discovery when use_gitignore. NO new dependency (cap: click/rich/pyyaml). Document as best-effort (P7). Add --no-gitignore CLI flag wired to config.gitignore. If deemed stretch, ship the flag + plumbing and a minimal top-level-.gitignore implementation; mark scope in docs.
- (S) CLI_SCAN_PIPELINE_5: Registry: implement load_builtin_detectors + load_detector_specs(selected) [deps: DSL_PARSER_1]
    Implement load_builtin_detectors() to parse every discover_spec_files() path via parse_spec, returning specs sorted by id (P3); propagate DSLError. Add load_detector_specs(selected) that filters by id and raises ValueError listing unknown ids. BLOCKED on the DSL parser (parse_spec is a stub owned by the taint-engine track).
- (M) CLI_SCAN_PIPELINE_6: Orchestrator scanner.py: run_scan + ScanResult/ScanError + per-file isolation [deps: CLI_SCAN_PIPELINE_3, CLI_SCAN_PIPELINE_5, FRONTEND_1, ENGINE_1]
    Implement run_scan(target, config): load_detector_specs(config.detectors); discover_python_files; construct TaintEngine(specs) once and PythonFrontend(); per sorted file parse+analyze, catching SyntaxError/parse/analyze failures into ScanError and continuing; aggregate. Define frozen ScanResult/ScanError dataclasses. BLOCKED on PythonFrontend.parse and TaintEngine.analyze (taint-engine track).
- (M) CLI_SCAN_PIPELINE_7: Aggregation: severity filter, deterministic dedup, total-order sort [deps: CLI_SCAN_PIPELINE_6]
    In scanner.py: filter findings by severity_threshold.rank; dedup by fingerprint-or-derived-key keeping first under sort order; sort by (file,line,column,detector_id,witness_fingerprint) — total order (P3). Implement _witness_fingerprint (sha256 of ordered (role,file,line,col)). Robust when Finding.fingerprint is None.
- (S) CLI_SCAN_PIPELINE_8: Exit-code computation [deps: CLI_SCAN_PIPELINE_7]
    compute_exit_code(result, *, fail_on, threshold): gate = fail_on or threshold; FINDINGS(1) if any finding.severity.rank >= gate.rank else OK(0). Pure + unit-tested across the threshold/fail-on matrix. Document the threshold-vs-fail-on composition.
- (M) CLI_SCAN_PIPELINE_9: Wire scan command in cli.py (thin) [deps: CLI_SCAN_PIPELINE_2, CLI_SCAN_PIPELINE_8]
    Replace _not_implemented('scan'). Build cfg via load_config + resolve_config (parameter-source aware); try/except wrapping run_scan and rendering; render via get_reporter(cfg.output_format); write to -o FILE or click.echo to stdout; report ScanError count to stderr only; SystemExit(int(compute_exit_code(...))). ConfigError/DSLError/unknown-detector/unexpected -> stderr + exit 2. No network (P1); no detection logic in CLI (P4). Keep stdout clean for json/sarif piping.
- (M) CLI_SCAN_PIPELINE_10: Implement rules list/show/validate in cli.py [deps: CLI_SCAN_PIPELINE_5]
    rules list: load_builtin_detectors() sorted by id; text columns + optional --format json. rules show ID: find by id, print full spec or exit 2 listing available ids; --format json via spec serializer. rules validate FILE: parse_spec(read_text, source_path=FILE); DSLError -> stderr exit 2; success -> 'OK: <id>' exit 0. Add a spec->dict serializer for json output.
- (L) CLI_SCAN_PIPELINE_11: Tests: config, discovery, scanner, exit codes, CLI, e2e [deps: CLI_SCAN_PIPELINE_9, CLI_SCAN_PIPELINE_10]
    Write the test suites enumerated in the tests field, including updating tests/unit/test_cli.py to assert REAL behavior (the existing test_scan_is_stubbed/test_rules_*_is_stubbed assert exit 2 and MUST be rewritten). Add per-detector TP/TN integration assertions over tests/fixtures/python (P5). Add a determinism test (scan twice, byte-identical output; randomized file order yields identical sort).
- (M) CLI_SCAN_PIPELINE_12: Docs + CHANGELOG + version bump [deps: CLI_SCAN_PIPELINE_11]
    Update docs/usage.md to drop 'stub/exits 2' language for scan & rules; document config precedence (CLI>file>defaults), additive --exclude, default-excluded dirs, .gitignore best-effort + --no-gitignore, exit-code/fail-on semantics. Add config schema section (here or dsl-reference). Update README + CHANGELOG (Keep-a-Changelog); coordinate version bump (0.1.0 -> 0.2.0) with release-eng track. SPDX headers on all new .py files.

**acceptance_criteria:**
- `scanipy scan tests/fixtures/python/vulnerable/os-command.py` exits 1 and prints a CWE-78 finding with a source->sink witness; `scanipy scan tests/fixtures/python/safe/os-command.py` exits 0 with 'No findings.' (P5 end-to-end).
- `scanipy scan .` works with NO flags and NO config file (P6) and never touches the network (P1).
- Running the same scan twice produces byte-identical stdout for text, json, and sarif; shuffling on-disk file order does not change output ordering (P3 total order with witness tie-break).
- Default-excluded dirs (.venv/.git/__pycache__/build/dist/etc.) are skipped; --exclude GLOB skips matching files; --exclude is additive over config+defaults; .gitignore is honored by default and disabled by --no-gitignore.
- Config precedence is exactly CLI > file > defaults; .scanipy.yml and [tool.scanipy] are both discovered (auto walk-up) and an explicit --config FILE is loaded verbatim; unknown keys / bad enum values raise a clear ConfigError and exit 2.
- --severity-threshold filters displayed findings by Severity.rank; --fail-on sets the exit gate independently (gate=fail_on or threshold); exit is 1 iff a finding at/above the gate exists, else 0; fatal errors exit 2.
- -o FILE writes the rendered report to that file (with trailing newline) and prints nothing to stdout; without -o the report goes to stdout and per-file parse errors go only to stderr (stdout stays machine-clean for json/sarif).
- `rules list` lists bundled specs sorted by id; `rules show python.injection.os-command` prints its full spec; unknown id exits 2 listing available ids; `rules validate FILE` exits 0 on a valid spec and 2 with a DSLError message on an invalid one.
- scanner.py and cli.py contain ZERO per-detector/per-CWE hardcoding — all detection comes from specs handed to TaintEngine (P4, grep-verifiable).
- ruff check . , ruff format --check . , mypy src , and pytest are all green across Python 3.10-3.13; every new .py file has the SPDX-License-Identifier header; the previously stub-asserting CLI tests are updated to assert real behavior.

**tests:**
- test_config.py: defaults == ScanConfig(); .scanipy.yml is discovered by walk-up and parsed; [tool.scanipy] in pyproject is parsed; .scanipy.yml wins over pyproject in same dir; explicit --config loads that file; unknown key -> ConfigError; bad severity/format -> ConfigError; severity_threshold/fail_on parse via Severity.from_str; gitignore bool parsed.
- test_config.py (merge): resolve_config — CLI scalar overrides file overrides default; CLI --detectors non-empty replaces file; empty CLI tuple does not override; --exclude is additive across defaults+file+CLI; fail_on=None vs provided handled.
- test_discovery.py: walks a tmp tree and returns only *.py sorted by as_posix; prunes each DEFAULT_EXCLUDE_DIRS entry; --exclude glob on basename and on relative path both work; single .py file root returns [file]; single non-.py file returns [] (or errors per chosen UX); .gitignore entries excluded when use_gitignore and included with --no-gitignore.
- test_scanner.py: run_scan aggregates findings across multiple files; a file that raises SyntaxError/parse error is recorded as ScanError and does not abort the scan; severity_threshold filtering by rank; dedup collapses identical findings (fingerprint and None-fingerprint paths); sort is a TOTAL order — construct two findings sharing (file,line,col,detector_id) but different witnesses and assert stable deterministic order; shuffling input order yields identical output.
- test_scanner.py (exit codes): compute_exit_code matrix — no findings->OK; finding below gate->OK; finding at/above gate->FINDINGS; fail_on overrides threshold both directions; ScanResult with only errors and no findings->OK.
- test_cli.py (REWRITE existing stub tests): scan on vulnerable fixture exits 1 with CWE-78 + witness in text/json/sarif; scan on safe fixture exits 0; -o FILE writes report and stdout empty; --format json stdout is valid JSON with sorted keys; unknown --detectors id exits 2 with helpful message; --config to a malformed file exits 2; bare `scanipy` still exits 2 with Usage (unchanged); version still exits 0.
- test_cli.py (rules): rules list lists os-command + sql sorted; rules show known id prints spec; rules show unknown id exits 2; rules validate on a valid bundled spec exits 0; rules validate on an invalid spec exits 2 with a DSL error message.
- test_scan_e2e.py (integration, P5): for EACH bundled detector, scan its vulnerable fixture -> exactly the expected finding(s) flagged; scan its safe fixture -> zero findings; parametrize over the fixture corpus so adding a detector automatically requires its TP/TN pair.
- Determinism test: scan the fixtures tree twice and assert identical stdout bytes for all three formats; assert json output is stable under sort_keys.
- Privacy test (P1, optional but recommended): monkeypatch socket.socket to raise during a scan and assert the scan path still completes without attempting a connection.

**risks:**
- HARD DEPENDENCY on stubs owned by other tracks: load_builtin_detectors needs parse_spec; run_scan needs PythonFrontend.parse and TaintEngine.analyze. This subsystem cannot pass its e2e tests until those land. Mitigation: build config/discovery/merge/exit-code/sort/dedup against the existing signatures with fakes (a stub frontend returning a sentinel + a stub engine returning canned Findings) so 80% is testable independently and sequence CLI_SCAN_PIPELINE_5/6 after DSL_PARSER/FRONTEND/ENGINE.
- Python 3.10 has no stdlib tomllib but is in requires-python>=3.10; reading [tool.scanipy] from pyproject needs tomli on 3.10. Adding any dep brushes against the click/rich/pyyaml cap — needs sign-off. Mitigation options: (a) conditional `tomli; python_version<'3.11'`, (b) skip-pyproject-on-3.10 with a warning, (c) require .scanipy.yml for 3.10. RECOMMEND (a) with justification; otherwise (b).
- Robust .gitignore in pure stdlib is genuinely hard (nested files, negation, anchoring). Over-promising risks false exclusions (silently dropping files = missed findings, the worst failure for a security tool). Mitigation: implement a documented common subset, default-on but overridable, and state scope honestly (P7); consider demoting full .gitignore to a stretch goal.
- click parameter-source detection is the linchpin of CLI>file precedence; getting it wrong silently makes CLI flags or file config no-ops. Mitigation: dedicated tests asserting each option's source-based override; treat ENVIRONMENT same as COMMANDLINE.
- Determinism is fragile: os.walk order, set/dict iteration, and the documented (file,line,col,detector_id) collision (one sink, two sources). Mitigation: sort the file list, sort spec load, and add the witness-fingerprint tie-break for a true total order; add an explicit determinism test.
- Existing CLI tests (test_scan_is_stubbed, test_rules_*_is_stubbed) assert exit 2 and WILL break — they must be rewritten in lockstep, or CI goes red. Mitigation: include the rewrite in CLI_SCAN_PIPELINE_11 and call it out for the qa-test track.
- stdout pollution breaks json/sarif piping: any human chatter (skipped-file notices, rich decoration) on stdout corrupts machine output. Mitigation: all diagnostics to stderr; reporters own stdout exclusively; test stdout is valid JSON.
- ruff's bandit 'S' rules run on src/: subprocess/os usage or yaml.load in our own code could trip them; config parsing must use yaml.safe_load and avoid flagged patterns. Mitigation: lint locally before PR.
- Per-file error isolation vs honest scope: silently swallowing analyzer crashes could hide bugs; surfacing every parse error could be noisy on mixed py2/py3 trees. Mitigation: non-fatal but counted, summarized on stderr, with a verbose/debug path deferred.

**open_questions:**
- Is full .gitignore honoring a v1 must-have or a stretch goal? The task says 'optionally .gitignore'. Recommend: ship the default-excluded-dirs + --exclude globs as must-have, and a documented best-effort top-level .gitignore (+ --no-gitignore) as in-scope-if-time, demotable to stretch without blocking the milestone.
- pyproject [tool.scanipy] on Python 3.10: accept a conditional tomli dep, or skip pyproject parsing on 3.10 (warn) and rely on .scanipy.yml? Need a decision because it affects pyproject.toml dependencies and the dep-cap principle.
- --exclude semantics: additive (defaults+file+CLI, recommended) or does CLI --exclude REPLACE the config excludes? Recommend additive; confirm with the cli-ux owner since it affects user mental model.
- Should a single-file target that is NOT .py be an error (exit 2) or a silent no-op (exit 0, no findings)? Recommend error for an explicitly-named non-Python file; confirm UX.
- Default-excluded dirs list: is the proposed set (.venv/venv/.git/__pycache__/build/dist/.tox/.mypy_cache/.ruff_cache/.pytest_cache/node_modules/.eggs/*.egg-info) the agreed canonical set, or should it be the minimal four from the task (.venv/.git/__pycache__/build/dist) to stay conservative?
- Does Finding.fingerprint get populated by the engine (taint-engine track) or must the orchestrator compute it for dedup? models.py makes it Optional; the orchestrator computes a derived key when None, but the canonical fingerprint contract between engine and pipeline should be agreed to avoid dedup mismatches.
- Should `rules list`/`show` support --format json in v1 (nice for tooling) or text-only to keep scope tight? Recommend adding json since the serializer is small and aids CI.

==========================================================================================
## COMPONENT: Testing & QA

**Summary:** The test architecture for scanipy OSS v1: a layered suite of fast, hermetic (no-network) pytest modules covering every component (DSL parser, Python frontend/IR, pattern matcher, taint engine, summaries, config, scanner, CLI, reporters), plus cross-cutting enforcement suites that are the load-bearing guarantees of the project: a P5 catalog test (every detector flags its TP fixture and is silent on its TN fixture), a P3 determinism test (scan-twice byte-identical for json/sarif), version-tolerant golden snapshots for json/sarif, unparsable-file resilience, and a bounded performance smoke. It also defines coverage targets, a CI coverage gate, and the migration of the two existing stub-asserting CLI tests once `scan`/`rules` are implemented. The suite is driven by shared conftest fixtures and a fixture-pairing convention so adding a detector automatically extends the P5 matrix with zero engine/test edits (P4).

**Key files:** tests/conftest.py, tests/unit/test_cli.py, tests/unit/test_core.py, tests/unit/test_dsl_parser.py, tests/unit/test_frontend_ir.py, tests/unit/test_matcher.py, tests/unit/test_engine.py, tests/unit/test_summaries.py, tests/unit/test_config.py, tests/unit/test_scanner.py, tests/unit/test_reporters.py, tests/unit/test_registry.py, tests/integration/test_scan_end_to_end.py, tests/integration/test_catalog_p5.py, tests/integration/test_determinism.py, tests/integration/test_golden_reports.py, tests/integration/test_resilience.py, tests/integration/test_performance_smoke.py, tests/integration/test_cli_scan.py, tests/golden/scan-corpus.json, tests/golden/scan-corpus.sarif, tests/fixtures/python/vulnerable/*.py, tests/fixtures/python/safe/*.py, tests/_support/fixtures_index.py, tests/_support/normalize.py, pyproject.toml, .github/workflows/ci.yml, docs/testing.md

**Interfaces:**
```
PYTEST SUPPORT (new files)

# tests/_support/fixtures_index.py
from pathlib import Path
from typing import NamedTuple
from scanipy.dsl import DetectorSpec

class FixturePair(NamedTuple):
    detector_id: str
    stem: str
    tp_path: Path | None   # tests/fixtures/python/vulnerable/<stem>.py
    tn_path: Path | None   # tests/fixtures/python/safe/<stem>.py

def fixture_stem_for(spec: DetectorSpec) -> str: ...   # spec.metadata["fixture"] or last dotted id segment
def discover_fixture_pairs() -> list[FixturePair]: ...  # sorted by detector_id (P3)

# tests/_support/normalize.py
def normalize_json_report(text: str) -> dict: ...   # json.loads -> obj["version"]="<VERSION>"
def normalize_sarif(text: str, corpus_root: Path) -> dict: ...  # version + repo-relative POSIX uris

# tests/conftest.py (additions, all typed; SPDX header kept)
@pytest.fixture(scope="session")
def builtin_specs() -> tuple[DetectorSpec, ...]: ...        # registry.load_builtin_detectors()
@pytest.fixture
def fixtures_root() -> Path: ...                             # tests/fixtures/python
@pytest.fixture
def corpus_tmp(tmp_path: Path, fixtures_root: Path) -> Path: ...   # shutil.copytree
@pytest.fixture
def scan_corpus(builtin_specs, corpus_tmp) -> list[Finding]: ...   # sorted findings
def pytest_generate_tests(metafunc) -> None: ...            # parametrize `fixture_pair` over discover_fixture_pairs(), ids=detector_id

CONTRACTS UNDER TEST (real existing signatures)
registry.discover_spec_files() -> tuple[Path, ...]
registry.load_builtin_detectors() -> tuple[DetectorSpec, ...]
dsl.parse_spec(text: str, *, source_path: str | None = None) -> DetectorSpec   # raises DSLError(ValueError)
dsl.load_spec_file(path: str | Path) -> DetectorSpec
PythonFrontend(language="python").parse(path: Path) -> object                  # raises typed FrontendParseError on SyntaxError (new)
TaintEngine(specs: Sequence[DetectorSpec]).analyze(module: object) -> list[Finding]
reporting.get_reporter(fmt: str) -> Reporter ; Reporter.render(findings: Sequence[Finding]) -> str
config.load_config(path: str | Path | None = None) -> ScanConfig
ScanConfig(detectors, severity_threshold=Severity.LOW, fail_on=None, exclude=(), output_format="text")
ExitCode(OK=0, FINDINGS=1, ERROR=2)

NEW COMPONENT CONTRACT THIS SUITE PINS (scanner — to be built by orchestration agent)
# src/scanipy/scanner.py  (proposed; tests written against it)
def scan_paths(paths: Sequence[Path], specs: Sequence[DetectorSpec], config: ScanConfig) -> ScanResult: ...
@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]            # sorted by total order (file,line,column,detector_id,witness-fp)
    skipped: tuple[SkippedFile, ...]         # unparsable/unreadable files (resilience, P7)
@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str

DETERMINISTIC TOTAL ORDER (asserted in tests)
sort_key(f: Finding) = (f.location.file, f.location.line, f.location.column, f.detector_id, witness_fingerprint(f))
witness_fingerprint(f) = stable hashlib hash of tuple((s.role.value, s.location.file, s.location.line, s.location.column) for s in f.witness)  # never builtin hash()
```

**Design:**
ARCHITECTURE OVERVIEW
The suite is split into two pytest trees that already match the configured markers in pyproject.toml ([tool.pytest.ini_options] markers: `unit`, `integration`):
- tests/unit/* (marked `unit`): one module per component, isolated, no filesystem walks beyond tmp_path, no subprocess. Test the public contracts of the real types in src/scanipy.
- tests/integration/* (marked `integration`): exercise the wired pipeline (registry -> scanner -> frontend -> engine -> reporter, and the click CLI via CliRunner) over the real fixtures tree.
A shared helper package tests/_support/ holds the fixture-pairing index and output normalizers so every cross-cutting suite reuses one implementation (DRY, determinism).

GROUNDING IN REAL TYPES (read from source):
- Finding(detector_id, cwe, severity: Severity, message, location: Location, witness: tuple[WitnessStep, ...], fingerprint: str | None) with .to_dict(); Location(file, line, column=0, end_line=None, end_column=None); WitnessStep(role: WitnessRole, location, description=""); WitnessRole(SOURCE/PROPAGATOR/SANITIZER/SINK); Severity(LOW/MEDIUM/HIGH/CRITICAL).rank/.from_str.
- DetectorSpec(id, name, cwe, severity, languages, message, sources, sinks, sanitizers=(), propagators=(), metadata). Pattern(kind: PatternKind, pattern, args: tuple[int,...]|None, when: Mapping|None). Flow(from_, to). Propagator(pattern, flow).
- parse_spec(text, *, source_path=None) -> DetectorSpec, raises DSLError (subclass of ValueError); load_spec_file(path). NotImplementedError today.
- registry.discover_spec_files() -> tuple[Path,...] (sorted, works); registry.load_builtin_detectors() -> tuple[DetectorSpec,...] (stub -> () today; will parse).
- PythonFrontend(language="python").parse(path: Path) -> object (returns the normalized module/IR; opaque to callers).
- TaintEngine(specs: Sequence[DetectorSpec]).analyze(module: object) -> list[Finding]; .specs property.
- get_reporter("text"|"json"|"sarif") -> Reporter; Reporter.render(findings: Sequence[Finding]) -> str. JsonReporter renders json.dumps(payload, indent=2, sort_keys=True) with {"tool","version","findings":[to_dict...]}. SarifReporter renders SARIF 2.1.0 with json.dumps(log, indent=2) (NOTE: no sort_keys -> determinism risk, see RISKS). Both embed scanipy.__version__.
- ScanConfig(detectors, severity_threshold: Severity=LOW, fail_on: Severity|None, exclude, output_format="text"); load_config(path) -> ScanConfig. ExitCode(OK=0, FINDINGS=1, ERROR=2). __version__ = "0.1.0".

NEW TEST-SUPPORT MODULES
1) tests/_support/fixtures_index.py — the heart of the declarative P5 matrix. Provides:
   - discover_fixture_pairs() -> list[FixturePair], where FixturePair = NamedTuple(detector_id, stem, tp_path: Path|None, tn_path: Path|None). Algorithm: load registry.load_builtin_detectors(); for each spec build the expected fixture stem from spec.metadata["fixture"] if present else the last dotted segment of spec.id (e.g. "python.injection.os-command" -> "os-command"); look for tests/fixtures/python/vulnerable/<stem>.py (TP) and .../safe/<stem>.py (TN). The catalog test fails loudly if a spec has no TP or no TN fixture, enforcing P5 by construction.
   - All returned lists are sorted by detector_id (P3) so parametrize ids are stable.
2) tests/_support/normalize.py — version/host tolerant comparison for golden + determinism:
   - normalize_json_report(text) -> dict: json.loads, then set obj["version"] = "<VERSION>". Leaves findings intact.
   - normalize_sarif(text, corpus_root) -> dict: json.loads, then runs[0].tool.driver.version = "<VERSION>"; rewrite absolute file uris to repo-relative POSIX paths so goldens are path-independent across machines/CI.
   - These exist because both reporters embed __version__ and the locked DoD bumps the version; without normalization every golden breaks on the release commit.

CONFTEST ADDITIONS (tests/conftest.py — already defines `runner: CliRunner`)
Add session/function fixtures (typed, SPDX header preserved):
   - fixtures_root() -> Path: tests/fixtures/python (resolved via Path(__file__).parent).
   - builtin_specs() -> tuple[DetectorSpec, ...]: registry.load_builtin_detectors(), cached at session scope.
   - corpus_tmp(tmp_path) -> Path: copies the whole fixtures/python tree into tmp_path (shutil.copytree) so scans run against a stable, isolated path and absolute paths in output are normalizable.
   - scan_corpus(builtin_specs, corpus_tmp) -> list[Finding]: runs the real scanner over corpus_tmp and returns sorted findings (single source of truth for golden + determinism + e2e tests).
   - pytest_generate_tests hook: when a test requests `fixture_pair`, parametrize over discover_fixture_pairs() with ids=detector_id (this is what makes the P5 suite auto-extend per detector, P4).

PER-COMPONENT UNIT TESTS (algorithms)
- test_dsl_parser.py: round-trip the bundled os-command.yml and sql.yml through parse_spec/load_spec_file and assert the produced DetectorSpec field-by-field against the YAML (kinds, patterns, args=[0] on os.system, when={"keyword":{"shell":True}} on subprocess.*, propagator Flow from_="any-arg" to="return", sql sanitizers == ()). Negative tests: each must raise DSLError (ValueError subclass): missing required field (no sources/sinks), unknown top-level key, bad kind value, bad severity, malformed when/args, a pattern referencing an undefined flow token, non-list languages. Also a "closure/declarative" test: parser rejects any key outside the documented schema (P4 guardrail). Assert parse is pure (same text -> equal DetectorSpec) for P3.
- test_frontend_ir.py: PythonFrontend().parse(tmp file) over small ast snippets. Because parse returns an opaque object, test it through the documented IR accessors the frontend agent exposes (import table, function table, per-function statements). Cover the pitfalls list: import resolution forms (import os, import os.path as p, from subprocess import run, from os import system as sysrun) all canonicalize to dotted paths; nested scopes (comprehension/lambda); tuple/star unpacking; AugAssign; JoinedStr/f-string and BinOp +/% nodes tagged as default propagation sites; CFG has the expected blocks/edges for if/else, try/except/finally, with, BoolOp/IfExp. Resilience: parse() on a SyntaxError file raises a typed, catchable error (e.g. frontends.FrontendParseError) carrying the path — NOT a bare SyntaxError that crashes the scan.
- test_matcher.py: the pattern matcher in isolation (dotted-path + wildcard + args + when). Table-driven: ("os.system",[0]) matches os.system(x) arg0 but not arg1; "subprocess.*" matches subprocess.run/Popen but not subprocess.foo.bar; "*.cursor.execute" matches db.cursor.execute(...) via the documented receiver rule; "flask.request.*" attribute matches; when={keyword:{shell:True}} matches only when shell=True literally present (not shell=False or absent). Matching must operate on canonicalized dotted paths (aliased imports match) — assert at least one alias case end-to-end through frontend+matcher.
- test_engine.py: TaintEngine.analyze over hand-built minimal IR modules (or via frontend on tiny source strings) with a SINGLE crafted spec, to test engine mechanics independent of the catalog. Cover engine_design transfer rules: (a) source->sink direct flow emits a Finding with a 2-step witness; (b) kill on reassignment (tainted then rebound to literal => no finding); (c) generic propagators: "a"+t, f"{t}", t.format(), "%s"%t carry taint; (d) sanitizer one-sidedness — sanitized-on-if-not-else (CFG join is UNION) still emits a finding (the load-bearing P5 rule); fully sanitized on all paths emits nothing; (e) args restriction respected (taint in arg1 of os.system(args=[0]) => no finding); (f) when-constraint respected (shell=False => no finding even if tainted); (g) loops monotone/bounded (tainted-in-loop reaches fixpoint, no infinite loop, finding emitted); (h) access-path field sensitivity with depth cap + over-approximation at cap (x.a.b.c tainted collapses to bounded prefix and may taint siblings -> assert FP-not-FN direction). Each emitting case asserts witness role ordering source -> propagator(s) -> sink and that locations point at the right lines.
- test_summaries.py: intra-file interprocedural via TITO summaries. Cases: (a) helper returns its tainted param (param_i->return) then caller passes source -> sink => finding with SPLICED witness (source -> arg enters callee param -> ... -> sink); (b) param_i->internal-sink (sink inside callee) emits at the call site; (c) source-in-callee->return; (d) recursion / mutual recursion terminates via bounded fixpoint and still finds the obvious flow; (e) external/stdlib callee with no summary falls back to spec propagator or conservative pass-through (documented best-effort) — assert behavior matches the documented default. Assert summaries are computed in deterministic (sorted/reverse-topo) order so witnesses are stable.
- test_config.py: load_config returns ScanConfig defaults today; once cli-ux lands, assert .scanipy.yml / [tool.scanipy] parsing into ScanConfig (detectors tuple, severity_threshold via Severity.from_str, fail_on, exclude, output_format), precedence (CLI overrides file overrides defaults), and graceful handling of a malformed/empty config (zero-config P6: missing file => defaults, never crash).
- test_scanner.py: the scanner orchestration module (NEW component — does not exist yet; this suite defines its contract). Expected interface: scanner.scan_paths(paths, specs, config) -> ScanResult. Tests: walks a directory and collects only *.py (respects ScanConfig.exclude globs); applies ScanConfig.detectors selection and severity_threshold filtering; sorts findings by the TOTAL order (file, line, column, detector_id, then witness-fingerprint tie-break) — assert determinism on a synthetic two-source-one-sink collision; an unparsable file in the tree does NOT abort the scan (other files still scanned) and is surfaced via a typed diagnostic, not an exception (resilience); no-network guarantee (P1) — assert by monkeypatching socket to raise and confirming a scan still completes.
- test_reporters.py: extend the existing test_core reporter checks. Assert JSON output is byte-identical across two render() calls (sort_keys gives this); assert SARIF determinism explicitly (this suite catches the missing sort_keys — see RISKS; assert two renders are byte-identical AND keys are sorted, FORCING the SARIF reporter fix). Assert SARIF startColumn = max(column,1), level mapping (HIGH/CRITICAL->error, MEDIUM->warning, LOW->note), witness round-trips through json to_dict (len + roles), text reporter pluralization ("1 finding." vs "N findings.").
- test_registry.py: discover_spec_files() is sorted and finds os-command.yml + sql.yml; load_builtin_detectors() returns one DetectorSpec per discovered yml, sorted by id, and every returned spec passes self-validation (>=1 source and >=1 sink, valid severity, languages==("python",)).

INTEGRATION TESTS (algorithms)
- test_scan_end_to_end.py: run the real pipeline over the os-command vulnerable fixture and assert EXACT findings: exactly one Finding, detector_id "python.injection.os-command", cwe "CWE-78", severity HIGH, location at the os.system line, witness == (SOURCE at input() line, ..., SINK at os.system line) with roles in order. Over the safe fixture: zero findings. This is the "scan works end-to-end on real code" DoD check, asserting the witness exactly (P2).
- test_catalog_p5.py: THE P5 enforcement matrix. Two parametrized tests over discover_fixture_pairs():
    test_detector_flags_its_true_positive(fixture_pair): scan ONLY fixture_pair.tp_path with ONLY that detector_id's spec; assert >=1 finding whose detector_id matches and cwe matches the spec, with a non-empty witness ending in a SINK step.
    test_detector_is_silent_on_its_true_negative(fixture_pair): scan fixture_pair.tn_path with that detector; assert ZERO findings for that detector_id.
  A guard test test_every_detector_has_both_fixtures() asserts each pair has both tp_path and tn_path present (fails the build if a new detector ships without a TP or TN fixture). Auto-covers all 6-8 core + up to 2 stretch detectors with no per-detector test code (P4/P5).
- test_determinism.py: P3. Build scan_corpus findings, render json twice and assert byte-identical; render sarif twice and assert byte-identical; run the FULL scan twice (fresh engine + fresh registry load) and assert the two json renders are byte-identical after normalize (rules out fingerprint/order nondeterminism). Also assert shuffling input file order / spec order yields the same sorted findings (the total order is real, not incidental).
- test_golden_reports.py: scan the whole fixtures corpus, render json and sarif, normalize via tests/_support/normalize.py (version + path), compare to committed goldens tests/golden/scan-corpus.json / .sarif. Provide an env-gated regen path: if SCANIPY_UPDATE_GOLDEN=1, write the normalized output back to the golden file and skip the assert (documented in docs/testing.md). Goldens are normalized-on-disk so they never contain machine paths or the version string.
- test_resilience.py: a corpus subtree containing a file with a Python SyntaxError and a non-UTF-8 / binary .py; assert the scan completes, scans the valid files, reports findings for them, and records the skipped files as diagnostics (not crashes). Assert the CLI exit code is still OK/FINDINGS (not ERROR) for unparsable inputs, and that a truly missing path is a usage ERROR (2) (graceful handling, honest scope P7).
- test_performance_smoke.py: generate (in tmp_path) a synthetic corpus of N files (e.g. 50 files x ~200 lines, including deep call chains and a recursive function to exercise the summary fixpoint cap) and assert the full scan finishes under a generous wall-clock budget (e.g. < 20s on CI) and produces a deterministic finding count. Marked `integration`, kept generous to avoid flakiness; its real job is to catch accidental exponential blowup (no path-depth/fixpoint cap) regressions, not to benchmark.
- test_cli_scan.py: the wired CLI via CliRunner (no subprocess, hermetic). Once scan is implemented: `scanipy scan <vulnerable fixture>` exits 1 (FINDINGS) and prints the finding; `scan <safe fixture>` exits 0; `scan --format json` emits parseable json to stdout; `-o FILE` writes to file and prints nothing to stdout; `--detectors <id>` limits the run; `--severity-threshold critical` suppresses HIGH findings -> exit 0; `--fail-on high` controls exit code independent of threshold; `rules list` lists bundled spec ids (exit 0); `rules show <id>` prints one spec; `rules validate <good yml>` exits 0 and `rules validate <bad yml>` exits non-zero with a DSLError message; `scan <missing path>` exits 2.

CLI STUB-TEST MIGRATION (existing tests/unit/test_cli.py)
test_cli.py currently asserts scan/rules/rules-validate exit 2 (stub contract). When the engine + cli-ux land, these three tests (test_scan_is_stubbed, test_rules_list_is_stubbed, test_rules_validate_is_stubbed) become FALSE and must be replaced by the test_cli_scan.py assertions above. Keep test_help_exits_zero, test_bare_invocation_shows_help, test_version_command, test_version_flag unchanged (those contracts are stable). This migration is an explicit task (TESTING_QA-20) gated on the scan/rules implementation so the suite never ships asserting a behavior the tool no longer has.

COVERAGE + CI
- Coverage already configured ([tool.coverage.run] source=["scanipy"], branch=true, omit tests). Add a gate: in CI test job run `pytest --cov=scanipy --cov-report=term-missing --cov-report=xml --cov-fail-under=90`, and add `[tool.coverage.report] fail_under = 90` to pyproject.toml so local runs match CI. Target 90% line+branch on src/scanipy overall; the engine transfer functions and matcher (correctness-critical core) targeted at/near 100% via focused tests.
- CI: keep the 3.10-3.13 matrix; the coverage gate runs on every matrix entry. Determinism + golden + P5 suites run inside the existing `pytest` step (no new job needed). No network calls anywhere (asserted via the socket-monkeypatch in test_scanner). Everything uses tmp_path / copied corpus so CI is hermetic and parallel-safe.

DETERMINISM/HERMETICITY PRINCIPLES BAKED IN
- Never iterate dict/set/Path.glob results without sorted(); discover_fixture_pairs and scan_corpus return sorted lists.
- Goldens and determinism asserts compare normalized output (version + path stripped) so the locked version bump and machine paths don't cause false failures while still catching real diffs.
- No subprocess for CLI tests (CliRunner only); no real network; no reliance on filesystem ordering.

**Tasks:**
- (S) TESTING_QA-1: Test-support package: fixture pairing index [deps: REGISTRY-load_builtin_detectors]
    Create tests/_support/__init__.py and tests/_support/fixtures_index.py with FixturePair, fixture_stem_for(spec), discover_fixture_pairs() (sorted by detector_id). Stem rule: spec.metadata['fixture'] if present else last dotted segment of spec.id. SPDX header. Unit-test the stem rule and sorting in tests/unit/test_support.py.
- (S) TESTING_QA-2: Output normalizers (version + path tolerant)
    tests/_support/normalize.py: normalize_json_report (set version to <VERSION>) and normalize_sarif (driver.version + repo-relative POSIX uris). Needed because both reporters embed __version__ and the DoD bumps the version. SPDX header; covered by test_golden_reports + test_determinism.
- (M) TESTING_QA-3: Extend conftest with corpus + parametrize hook [deps: TESTING_QA-1, SCANNER-scan_paths]
    Add builtin_specs (session), fixtures_root, corpus_tmp (shutil.copytree into tmp_path), scan_corpus (sorted findings), and pytest_generate_tests parametrizing `fixture_pair` over discover_fixture_pairs() with ids=detector_id. Keep the existing `runner` fixture.
- (M) TESTING_QA-4: DSL parser unit tests (positive + negative + purity) [deps: DSL-parse_spec]
    tests/unit/test_dsl_parser.py: field-by-field round-trip of os-command.yml and sql.yml; DSLError on missing source/sink, unknown key (P4 closure), bad kind/severity, malformed when/args, bad flow token; assert parse purity (same text -> equal spec, P3).
- (L) TESTING_QA-5: Frontend/IR unit tests + resilience contract [deps: FRONTEND-parse]
    tests/unit/test_frontend_ir.py: import resolution (import os, import os.path as p, from subprocess import run, from os import system as sysrun -> canonical dotted), nested scopes, unpacking, AugAssign, JoinedStr/BinOp propagation tags, CFG edges for if/try/with/BoolOp/IfExp; parse() on SyntaxError raises a typed FrontendParseError carrying the path (not a bare crash).
- (M) TESTING_QA-6: Pattern matcher unit tests [deps: ENGINE-matcher, FRONTEND-parse]
    tests/unit/test_matcher.py: dotted-path + wildcard + args + when, table-driven (os.system args=[0], subprocess.*, *.cursor.execute, flask.request.*, when shell=True only). Includes one alias-resolution case end-to-end through frontend+matcher.
- (L) TESTING_QA-7: Engine transfer-function unit tests [deps: ENGINE-analyze, FRONTEND-parse]
    tests/unit/test_engine.py with a single crafted spec: source->sink, kill-on-reassign, generic propagators (+, f-string, .format, %), sanitizer one-sidedness with UNION at CFG join (the P5 rule), args restriction, when-constraint, bounded loop fixpoint, access-path depth cap over-approximation (FP not FN). Assert witness role order and locations for every emitting case (P2).
- (L) TESTING_QA-8: Interprocedural summary unit tests [deps: ENGINE-summaries]
    tests/unit/test_summaries.py: param->return, param->internal-sink, source-in-callee->return, recursion/mutual-recursion termination via bounded fixpoint, external-callee fallback (spec propagator or conservative pass-through). Assert spliced witness order and deterministic summary computation order (P3).
- (S) TESTING_QA-9: Config unit tests [deps: CONFIG-load_config]
    tests/unit/test_config.py: defaults today; once cli-ux lands, .scanipy.yml/[tool.scanipy] -> ScanConfig, CLI>file>default precedence, malformed/empty config -> defaults (P6 zero-config, never crash).
- (M) TESTING_QA-10: Scanner orchestration unit tests [deps: SCANNER-scan_paths]
    tests/unit/test_scanner.py: pin scan_paths/ScanResult contract -- *.py walk, exclude globs, detector selection, severity_threshold filter, total-order sort with two-source-one-sink collision, unparsable file does not abort (recorded in skipped), no-network (socket monkeypatch). Defines the scanner contract for the implementing agent.
- (S) TESTING_QA-11: Reporter determinism + SARIF sort_keys forcing test [deps: REPORTING-sarif-determinism]
    tests/unit/test_reporters.py: json byte-identical across renders; SARIF byte-identical AND keys sorted (this assertion FORCES the SarifReporter to add sort_keys=True); startColumn=max(col,1); level mapping; witness round-trip; text pluralization. File a one-line fix to sarif.py if the determinism assert fails.
- (S) TESTING_QA-12: Registry parse-all + spec self-validation test [deps: REGISTRY-load_builtin_detectors]
    tests/unit/test_registry.py: load_builtin_detectors() returns one spec per yml, sorted by id; every spec has >=1 source, >=1 sink, valid severity, languages==('python',). Subsumes the discover_spec_files checks already in test_core.
- (M) TESTING_QA-13: End-to-end exact-findings integration test [deps: SCANNER-scan_paths, ENGINE-analyze, DSL-parse_spec]
    tests/integration/test_scan_end_to_end.py: os-command vulnerable fixture -> exactly one Finding (id/cwe/severity/location + full witness asserted, P2); safe fixture -> zero findings. The DoD 'works on real code' check.
- (M) TESTING_QA-14: P5 catalog enforcement matrix [deps: TESTING_QA-3, DETECTORS-all]
    tests/integration/test_catalog_p5.py: parametrized over fixture_pair -- test_detector_flags_its_true_positive and test_detector_is_silent_on_its_true_negative, plus test_every_detector_has_both_fixtures guard. Auto-extends per detector with zero per-detector code (P4/P5). Fails the build if any detector lacks a TP or TN fixture.
- (S) TESTING_QA-15: Determinism integration test (P3) [deps: TESTING_QA-2, SCANNER-scan_paths, REPORTING-sarif-determinism]
    tests/integration/test_determinism.py: scan-twice byte-identical json and sarif; full scan twice byte-identical after normalize; shuffled file/spec order yields identical sorted findings (proves the total order).
- (M) TESTING_QA-16: Golden snapshots for json + sarif [deps: TESTING_QA-2, SCANNER-scan_paths, DETECTORS-all]
    tests/integration/test_golden_reports.py: scan corpus, render json+sarif, normalize, compare to committed tests/golden/scan-corpus.json/.sarif; SCANIPY_UPDATE_GOLDEN=1 regen path. Commit initial goldens once engine produces stable output. Document regen in docs/testing.md.
- (M) TESTING_QA-17: Unparsable/binary file resilience integration test [deps: SCANNER-scan_paths, TESTING_QA-5]
    tests/integration/test_resilience.py: corpus subtree with a SyntaxError file and a non-UTF-8 .py; scan completes, valid files still scanned/flagged, bad files recorded as skipped; CLI exits OK/FINDINGS not ERROR; missing path -> ERROR(2).
- (S) TESTING_QA-18: Performance smoke test [deps: SCANNER-scan_paths, ENGINE-summaries]
    tests/integration/test_performance_smoke.py: generate ~50 synthetic files incl. deep call chains + recursion; assert full scan < generous budget (e.g. 20s) and deterministic finding count. Catches exponential-blowup regressions (uncapped depth/fixpoint).
- (M) TESTING_QA-19: CLI scan/rules integration tests via CliRunner [deps: CLI-scan, CLI-rules, SCANNER-scan_paths]
    tests/integration/test_cli_scan.py: scan vulnerable->exit 1; safe->exit 0; --format json parseable; -o FILE writes file/quiet stdout; --detectors limits; --severity-threshold/--fail-on exit-code semantics; rules list/show/validate (good->0, bad->non-zero DSLError); missing path->2. Hermetic (CliRunner, no subprocess).
- (S) TESTING_QA-20: Migrate stub-asserting CLI unit tests [deps: CLI-scan, CLI-rules, TESTING_QA-19]
    Rewrite tests/unit/test_cli.py: drop test_scan_is_stubbed/test_rules_list_is_stubbed/test_rules_validate_is_stubbed (now false) and point them at the implemented behavior (delegating to test_cli_scan.py); keep help/version tests. Gated on scan/rules implementation so the suite never asserts removed behavior.
- (S) TESTING_QA-21: Coverage gate + CI wiring [deps: TESTING_QA-13, TESTING_QA-14]
    Add [tool.coverage.report] fail_under=90 to pyproject.toml; update .github/workflows/ci.yml test step to `pytest --cov=scanipy --cov-report=term-missing --cov-report=xml --cov-fail-under=90`. Keep 3.10-3.13 matrix. No new network. Ensure markers (unit/integration) stay registered.
- (S) TESTING_QA-22: docs/testing.md (test architecture + golden regen + coverage policy) [deps: TESTING_QA-16, TESTING_QA-21]
    Write docs/testing.md: how to run unit vs integration (markers), the P5 fixture-pairing convention (metadata['fixture'] or id-stem), golden regen via SCANIPY_UPDATE_GOLDEN=1, coverage target/gate, and the determinism/no-network policy. Link from README/CHANGELOG per DoD.

**acceptance_criteria:**
- All test files carry the SPDX-License-Identifier: Apache-2.0 header (line 1) and pass ruff (line-length 100, double quotes); test helpers in tests/_support type-check cleanly; tests/** keep the S-suite ruff ignore already configured.
- P5 matrix (test_catalog_p5.py) is parametrized purely from discover_fixture_pairs(): adding a new detector YAML + its TP/TN fixtures extends the matrix with ZERO edits to engine or test code (P4); the guard test fails the build if any detector lacks a TP or TN fixture (P5).
- Every detector in the final catalog (6-8 core + up to 2 stretch) flags its true-positive fixture (>=1 finding with matching detector_id/cwe and a non-empty witness ending in a SINK) and is silent on its true-negative fixture (0 findings for that detector_id).
- End-to-end test asserts the EXACT Finding for the os-command vulnerable fixture incl. id, cwe CWE-78, severity HIGH, sink location, and the ordered SOURCE->...->SINK witness (P2); safe fixture yields zero findings.
- Determinism test: two scans of the corpus produce byte-identical json AND byte-identical sarif output; shuffling input-file and spec order yields identical sorted findings (P3). The SARIF reporter is deterministic (sort_keys), fixing the current indent-only render.
- Golden json + sarif snapshots are committed, normalized (no machine paths, no embedded version), compared on every CI run, and regenerable via SCANIPY_UPDATE_GOLDEN=1.
- Scan over a corpus containing a SyntaxError file and a non-UTF-8 file completes successfully, scans the valid files, and records the bad files as skipped diagnostics; the CLI returns OK/FINDINGS (not ERROR) for unparsable inputs and ERROR(2) only for a missing path / usage error.
- Performance smoke scan of ~50 synthetic files (incl. recursion and deep chains) finishes under the configured budget and returns a deterministic finding count (guards against uncapped depth/fixpoint blowup).
- The whole suite is hermetic: no network (asserted by socket monkeypatch in test_scanner), no subprocess (CLI tested via CliRunner), all I/O confined to tmp_path / a copied corpus; CI passes on Python 3.10-3.13.
- Coverage gate active: pytest --cov-fail-under=90 passes in CI and matches [tool.coverage.report] fail_under in pyproject.toml; the engine transfer functions and matcher are at/near 100% coverage.
- The existing stub-asserting CLI tests are migrated (not left asserting exit 2) once scan/rules are implemented; help/version tests remain green throughout.
- docs/testing.md documents the test architecture, fixture-pairing convention, golden regen, coverage policy, and the no-network/determinism guarantees; README/CHANGELOG reference it (DoD).

**tests:**
- tests/unit/test_support.py: FixturePair stem rule (metadata['fixture'] vs id last-segment) and discover_fixture_pairs() sorted by detector_id.
- tests/unit/test_dsl_parser.py: round-trip os-command.yml/sql.yml field-by-field; DSLError on missing sources/sinks, unknown top-level key, bad kind/severity, malformed when/args, bad flow token; parse purity.
- tests/unit/test_frontend_ir.py: import canonicalization (4 alias forms), nested scopes, tuple/star unpacking, AugAssign, f-string/BinOp propagation tags, CFG edges; SyntaxError -> typed FrontendParseError with path.
- tests/unit/test_matcher.py: dotted+wildcard+args+when table (os.system[0], subprocess.*, *.cursor.execute, flask.request.*, shell=True only); one alias end-to-end.
- tests/unit/test_engine.py: source->sink; kill-on-reassign; +/f-string/.format/% propagation; sanitizer one-sidedness with UNION join (P5); args restriction; when-constraint; bounded loop fixpoint; access-path depth-cap over-approximation; witness order+locations.
- tests/unit/test_summaries.py: param->return, param->internal-sink, source-in-callee->return, recursion termination, external-callee fallback; spliced witness order; deterministic summary order.
- tests/unit/test_config.py: defaults; config-file parsing into ScanConfig; CLI>file>default precedence; malformed/empty -> defaults (P6).
- tests/unit/test_scanner.py: *.py walk, exclude globs, detector selection, severity_threshold filter, total-order sort on a 2-source-1-sink collision, unparsable-file does-not-abort, no-network (socket monkeypatch).
- tests/unit/test_reporters.py: json + sarif byte-identical-across-renders and keys sorted (forces sarif sort_keys); startColumn=max(col,1); level mapping; witness round-trip; text pluralization.
- tests/unit/test_registry.py: load_builtin_detectors() one-spec-per-yml sorted by id; each spec self-validates (>=1 source/sink, valid severity, languages==('python',)).
- tests/integration/test_scan_end_to_end.py: exact Finding + full witness on os-command vulnerable; zero on safe.
- tests/integration/test_catalog_p5.py: test_detector_flags_its_true_positive[fixture_pair], test_detector_is_silent_on_its_true_negative[fixture_pair], test_every_detector_has_both_fixtures.
- tests/integration/test_determinism.py: scan-twice byte-identical json/sarif; shuffled order -> identical sorted findings.
- tests/integration/test_golden_reports.py: normalized json/sarif vs committed goldens; SCANIPY_UPDATE_GOLDEN regen path.
- tests/integration/test_resilience.py: SyntaxError + non-UTF-8 file -> scan completes, valid files flagged, bad files skipped; CLI exit OK/FINDINGS; missing path -> 2.
- tests/integration/test_performance_smoke.py: ~50 synthetic files incl. recursion/deep chains under time budget with deterministic finding count.
- tests/integration/test_cli_scan.py: scan exit codes (1/0), --format json, -o FILE, --detectors, --severity-threshold, --fail-on, rules list/show/validate, missing path -> 2 (CliRunner, hermetic).

**risks:**
- Reporters embed scanipy.__version__ in their output; the locked DoD bumps the version, which would break every golden and any byte-equality assert against a fixed version. MITIGATION: normalize the version field before comparison (tests/_support/normalize.py) and assert determinism per-run, not against a fixed version string.
- The SARIF reporter currently calls json.dumps(log, indent=2) WITHOUT sort_keys=True, while the JSON reporter uses sort_keys=True. This is a real P3 gap; the determinism/reporter test will fail until sarif.py is fixed. MITIGATION: TESTING_QA-11 asserts sorted+byte-identical SARIF, forcing a one-line fix to src/scanipy/reporting/sarif.py.
- Golden snapshots are brittle by nature: minor message/witness wording or column changes flip the test. MITIGATION: keep messages in the YAML specs (single source), provide SCANIPY_UPDATE_GOLDEN regen, and rely on the P5/e2e structural asserts (not goldens) for correctness so goldens act as change-detectors only.
- The scanner module does not exist yet; test_scanner.py pins a contract (scan_paths/ScanResult/SkippedFile) the orchestration agent must honor. RISK of drift if the implementing agent picks a different shape. MITIGATION: this spec's interfaces section is the agreed contract; the dependency edge SCANNER-scan_paths must be resolved before TESTING_QA-3/10/13.
- Fixture<->detector pairing currently relies on a filename-stem convention not yet encoded in specs (metadata['fixture'] is absent from os-command.yml/sql.yml). RISK of silent mispairing as detectors grow. MITIGATION: the guard test fails if a spec has no TP/TN; prefer an explicit metadata['fixture'] key and document it.
- Absolute paths from corpus_tmp leak into json/sarif output and into the total-order sort key, making goldens machine-dependent. MITIGATION: normalize uris to repo-relative POSIX in the SARIF/json normalizers and assert findings on relative paths.
- Performance smoke can flake on slow CI runners. MITIGATION: keep the budget generous (20s), make the corpus modest, treat it as a blowup-detector rather than a benchmark, and mark it integration so it can be skipped locally.
- Determinism across Python 3.10-3.13: hash-based fingerprints vary if PYTHONHASHSEED-sensitive builtin hash() is used. MITIGATION: witness fingerprints must use a stable hashlib digest over the role/location tuple, never builtin hash(); assert the fingerprint is reproducible.
- Coverage gate at 90% with branch=true may be hard to hit on defensive engine branches. MITIGATION: use the existing exclude_lines (raise NotImplementedError, @abstractmethod, TYPE_CHECKING), add targeted tests for engine branches, and tune the threshold once the engine lands rather than blocking the first green CI.

**open_questions:**
- Fixture pairing: explicit metadata['fixture'] key in each spec vs implicit id-last-segment convention? Recommendation: explicit key, falling back to the convention. Needs sign-off from the detector-author component.
- Exact scanner module interface (function scan_paths vs Scanner class; ScanResult.findings tuple vs list; how skipped files are surfaced). Needs alignment with the CLI/orchestration component owner before TESTING_QA-10/13 land.
- Does the frontend raise a project-typed FrontendParseError (preferred for catchability) or surface SyntaxError directly? The resilience tests assume a typed error carrying the path; confirm with the frontend component.
- Should the JSON/SARIF reporters omit the embedded version entirely (cleaner goldens) or keep it (useful provenance)? Current code keeps it; this spec normalizes it. If the reporting owner removes it, the normalizers simplify.
- Coverage threshold: is 90% line+branch the right v1 gate, or should the engine/matcher carry a higher per-module bar? Final number to be set once the engine exists and real coverage is measured.
- Golden corpus scope: snapshot the full fixtures tree (grows with every detector) or a curated stable subset? Full tree gives strongest change-detection but more churn; needs a policy decision.
- Should the performance smoke be in the default CI run or behind an opt-in marker/job to keep the matrix fast? Default-on is simplest for the DoD but adds runtime.

==========================================================================================
## COMPONENT: Docs, Changelog, Version, Release Readiness

**Summary:** This subsystem ships the "tool now works" story: it de-stubs README and docs/usage.md (scan + rules are real, not "coming soon"), finalizes docs/dsl-reference.md by promoting the `parameter`/`import` pattern kinds from PLANNED to supported and locking the v0 schema (including the new flow forms the engine/detectors use), refreshes docs/writing-detectors.md against the real parser/validation and the 6-8 detector catalog, writes the CHANGELOG 0.2.0 section, bumps `__version__` to 0.2.0, embeds a real verified end-to-end example (vulnerable snippet -> exact witness-backed finding scanipy prints), and defines a release-readiness checklist that explicitly stops short of any PyPI publish (v1 DoD). It is documentation/release-only: it changes no engine/CLI behavior and must accurately mirror the behavior the engine/CLI/detector components ship. Critically it must reconcile two artifacts that currently assume publishing — `usage.md`'s `pip install scanipy-oss` + SARIF-CI snippet and the `/release` slash command (`.claude/commands/release.md`) which tags and pushes to PyPI — with the locked v1 decision of NO PyPI publish.

**Key files:** README.md, docs/usage.md, docs/dsl-reference.md, docs/writing-detectors.md, CHANGELOG.md, src/scanipy/__init__.py, docs/examples/end-to-end.md (new), tests/docs/test_readme_version.py (new), tests/docs/test_end_to_end_example.py (new), tests/docs/test_dsl_reference_consistency.py (new), .claude/commands/release.md (note/flag only — see open questions)

**Interfaces:**
```

No NEW public interfaces — this component is docs/release only. It CONSUMES these real existing types/symbols (must be referenced exactly, never re-declared):

# Version (single source of truth)
src/scanipy/__init__.py: __version__: str = "0.2.0"   # read by hatchling [tool.hatch.version]; imported by cli.version, JsonReporter, SarifReporter

# CLI (document its real surface; do not change it)
scanipy.cli.cli  (click.Group)
  scan(path, output_format, detectors, severity_threshold, fail_on, exclude, config_path, output_path)
  rules: rules_list(), rules_show(detector_id), rules_validate(spec_file)
  version()
scanipy.exit_codes.ExitCode(IntEnum): OK=0, FINDINGS=1, ERROR=2

# Finding model (the end-to-end example's JSON shape comes from here)
scanipy.models.Severity(str, Enum): LOW/MEDIUM/HIGH/CRITICAL; .rank; .from_str(value)
scanipy.models.WitnessRole(str, Enum): SOURCE/PROPAGATOR/SANITIZER/SINK
scanipy.models.Location(file, line, column=0, end_line=None, end_column=None)  # 1-based line, 0-based column
scanipy.models.WitnessStep(role: WitnessRole, location: Location, description: str = "")
scanipy.models.Finding(detector_id, cwe, severity, message, location, witness: tuple[WitnessStep, ...] = (), fingerprint: str | None = None)
  Finding.to_dict() -> {detector_id, cwe, severity(str), message, location{file,line,column,end_line,end_column}, witness[{role,location,description}], fingerprint}

# DSL types (the schema the dsl-reference doc locks)
scanipy.dsl.patterns.PatternKind(str, Enum): CALL/ATTRIBUTE/PARAMETER/IMPORT
scanipy.dsl.patterns.Pattern(kind, pattern, args: tuple[int,...] | None = None, when: Mapping | None = None)
scanipy.dsl.patterns.Flow(from_: str, to: str)        # vocab: "any-arg","arg:N","self","return" (+ documented additions if parser supports)
scanipy.dsl.patterns.Propagator(pattern: Pattern, flow: Flow)
scanipy.dsl.spec.DetectorSpec(id, name, cwe, severity, languages, message, sources, sinks, sanitizers=(), propagators=(), metadata)
scanipy.dsl.parser.DSLError(ValueError)               # the error class `rules validate` raises; document in dsl-reference Validation section
scanipy.dsl.parser.parse_spec(text, *, source_path=None) -> DetectorSpec
scanipy.dsl.parser.load_spec_file(path: str | Path) -> DetectorSpec

# Registry (used to enumerate the real catalog for README/CHANGELOG/tests)
scanipy.registry.builtin_detectors_path() -> Path
scanipy.registry.discover_spec_files() -> tuple[Path, ...]      # sorted; works today
scanipy.registry.load_builtin_detectors() -> tuple[DetectorSpec, ...]   # returns real specs once parser lands

# Reporters (output shapes the end-to-end doc quotes verbatim)
scanipy.reporting.get_reporter(output_format) -> Reporter   # "text"/"json"/"sarif"
scanipy.reporting.TextReporter.render(findings) -> str   # "SEV detector_id [CWE] file:line:col" + message + "    - role: file:line:col  desc" + "N finding(s)."
scanipy.reporting.JsonReporter.render(findings) -> str   # json.dumps({tool,version,findings:[to_dict()]}, indent=2, sort_keys=True)
scanipy.reporting.SarifReporter.render(findings) -> str  # SARIF 2.1.0; level map LOW->note MEDIUM->warning HIGH/CRITICAL->error

# Config (document only if the config component shipped real loading)
scanipy.config.ScanConfig(detectors=(), severity_threshold=Severity.LOW, fail_on=None, exclude=(), output_format="text")
scanipy.config.load_config(path=None) -> ScanConfig

# Test harness anchor (reuse, do not reinvent)
tests/conftest.py: fixture `runner` -> click.testing.CliRunner

```

**Design:**

APPROACH: docs/release work is the LAST milestone in the dependency chain — it documents behavior that the DSL-parser, engine, CLI, and detector components have already shipped. Every claim in the docs must be machine-verified against the real CLI output, not hand-written, to honor P7 (honest scope) and P3 (determinism). The design therefore pairs prose edits with executable doc-tests that scrape the real CLI/reporter output.

== 1. VERSION BUMP (src/scanipy/__init__.py) ==
- Change line 9 `__version__ = "0.1.0"` -> `__version__ = "0.2.0"`. This is the single source of truth; pyproject.toml `[tool.hatch.version] path = "src/scanipy/__init__.py"` reads it dynamically, and `cli.version`, JsonReporter, SarifReporter all import `from scanipy import __version__`. No other version literal exists — do NOT add one.
- Acceptance is enforced by a test (test_readme_version) that asserts `scanipy.__version__ == "0.2.0"` and that the CHANGELOG has a matching `## [0.2.0]` section heading.

== 2. README.md DE-STUB ==
- DELETE the "Early development / 0.1.0 scaffold / scan is currently a stub" blockquote (lines 17-20). Replace with a one-line status line: alpha, single-language (Python), intraprocedural + intra-file interprocedural, NOT published to PyPI yet.
- Quickstart (lines 48-53): remove every "(coming soon)" annotation; `scanipy scan .` and `scanipy scan app.py` now work. Keep `version`/`--help`.
- Install section (lines 38-44): CRITICAL — v1 has NO PyPI publish, so `pip install scanipy-oss` does NOT work yet. Replace with from-source install: `git clone` + `pip install -e ".[dev]"` (matches /scan-self step 1), and keep `python -m scanipy` as the module form. Add an explicit note: "Not yet on PyPI; install from source." (P7).
- "How detectors work" YAML snippet: keep but ensure it matches the real os-command.yml shape exactly (it does — `kind: call/attribute`, `args: [0]`, dotted patterns).
- Status & roadmap (lines 105-109): rewrite to "0.2.0 ships a working taint engine + N detectors". List the actual core detectors shipped (OS command CWE-78, SQLi CWE-89, code injection CWE-94, path traversal CWE-22, SSRF CWE-918, unsafe deserialization CWE-502, plus any stretch). Cross-check this list against the actual `src/scanipy/detectors/**/*.yml` present at build time via a doc-test, do not hand-maintain.
- Keep the "scanipy Cloud" section (honest scope contrast) unchanged.

== 3. docs/usage.md DE-STUB ==
- DELETE the "Early scaffold — read this first" blockquote (lines 7-13) and every per-line "(stub)/(coming soon)/exits 2" note (lines 49-52, the Status column in the command table lines 66-71, the exit-code note line 104, and the CI heads-up lines 117-119).
- Installation (lines 15-39): replace `pip install scanipy-oss` with from-source instructions; KEEP the `requires Python 3.10+` line.
- Command-surface table: change Status column to "works" for scan and rules; describe real behavior (scan walks PATH, runs builtin detectors, prints witness-backed findings; rules list/show/validate operate on bundled + given specs).
- Exit codes table (lines 96-104): remove "or a not-yet-implemented stub" from the `2` row — now `2` is error/usage only. Keep `0` clean, `1` findings.
- CI snippet (lines 121-149): replace `pip install scanipy-oss` with a from-source install step (checkout already present; add `pip install -e .`). KEEP `if: always()` and `security-events: write` rationale, but update the rationale text to drop "and today the scan stub exits 2". The SARIF upload still works because SarifReporter emits valid SARIF 2.1.0.
- Add a short "What scanipy reports" subsection linking to docs/examples/end-to-end.md.
- Optional config (lines 152-162): if the config component shipped real `.scanipy.yml` parsing, document the real keys (detectors, severity_threshold, fail_on, exclude, output_format — exactly the ScanConfig fields). If config parsing was deferred, keep zero-config framing and say config is not loaded yet (honest). Coordinate with the config/CLI component — depends_on CLI task.

== 4. docs/dsl-reference.md FINALIZE / LOCK v0 ==
- Status blockquote (lines 3-7): change from "engine still being built / co-evolves" to "Status: v0 (LOCKED for 0.2.0). The schema is stable for the 0.2.0 detector pack; future changes are additive and versioned." Keep the pre-1.0 caveat but stop saying "still being built".
- `kind` table (lines 71-77): promote BOTH rows. `parameter` -> "supported" (engine treats formal params as symbolic taint internally; as a SOURCE kind it marks entrypoint params, e.g. a Flask handler's args, as tainted). `import` -> "supported" (matches an imported name; useful for import-presence sources/sinks). Each must have a real working detector or fixture exercising it, OR be documented as supported-by-parser-but-unused — verify against the actual catalog; do not claim support the parser/engine does not have. Coordinate with DSL-parser + engine components (depends_on).
- Patterns section: document precisely what `parameter` and `import` patterns match and their `pattern` grammar (dotted path for import; bare-name / function-scoped for parameter). Add examples mirroring real usage.
- Flow vocabulary (lines 108-113): ADD the forms the prior-art research says the engine/detectors need: (a) kwarg-targeted argument selection in `args`/flow (taint a named keyword arg, not just positional) — document the exact syntax the parser accepts; (b) the by-side-effect propagator form `flow: { from: arg:N, to: arg:self }` / `{ from: arg:self, to: arg:N }` for mutators like `list.append`, `dict.__setitem__`. ONLY document forms the parser actually implements — read the real parser before writing, mark anything unimplemented as "planned" (do not over-promise; P7).
- `args` / `when` constraint table (lines 88-92): lock the exact accepted shapes. `when: { keyword: { name: value } }` — document value coercion (bool true/false, ints, strings) the parser does. Document that `args` restricts positional indices and taint in ANY listed index fires.
- Add a "Validation" subsection: enumerate what `scanipy rules validate` checks and the exact error class (DSLError, a ValueError subclass) — every rule the parser enforces (required fields id/name/cwe/severity/languages/message/sources/sinks; severity in {low,medium,high,critical}; >=1 source and >=1 sink; closed schema — unknown keys rejected for P4). Pull the real rule list from the parser implementation.
- Worked example (lines 147-166): verify it parses with the real parser; keep it byte-identical to a spec that round-trips (it currently mirrors os-command.yml; confirm it still validates).

== 5. docs/writing-detectors.md REFRESH ==
- Draft notice (lines 9-13): align with dsl-reference — schema is v0-locked for 0.2.0; additive changes only.
- Illustrative example (lines 59-70): keep, but confirm `parameter`/`import` are now described as supported (line 56 list).
- "/new-detector" section (lines 108-114): verify the helper still scaffolds to `src/scanipy/detectors/<class>/<name>.yml` + the two fixtures under `tests/fixtures/python/{vulnerable,safe}/`. Keep P5 (TP+TN) framing — it is correct.
- "Validating a spec" (lines 117-133): DELETE the "early scaffold / subcommands are still stubs" heads-up (lines 131-133). Document the real `rules validate`/`list`/`show` behavior and the real fixture-naming convention so authored detectors are picked up by the per-detector TP/TN test harness (coordinate with qa-test component — depends_on).
- Add a concrete "anatomy of the bundled os-command detector" walkthrough that maps each YAML key to engine behavior, grounded in the real `src/scanipy/detectors/injection/os-command.yml`.

== 6. CHANGELOG.md 0.2.0 SECTION ==
- Keep-a-Changelog format (already in use). Add `## [0.2.0] - 2026-06-08` (use the merge date) ABOVE the 0.1.0 section, with subsections Added / Changed / Fixed.
- Added: working taint engine (intraprocedural flow-sensitive + intra-file interprocedural via TITO function summaries); PythonFrontend (stdlib ast IR + import resolution); DSL parser (`parse_spec`/`load_spec_file`) with closed-schema validation; `parameter`/`import` pattern kinds promoted to supported; the N core detectors (list each with id + CWE); per-detector TP/TN fixtures; working `scanipy scan` (text/json/sarif, witness-backed), working `rules list/show/validate`; config loading (if shipped).
- Changed: `scan`/`rules` no longer stubs (were exit-2 in 0.1.0); exit code `2` no longer means "not-yet-implemented" — only error/usage now; DSL v0 schema locked.
- Update the link refs at the bottom (lines 52-53): add `[0.2.0]` compare/tag link, keep `[Unreleased]` pointing to compare/v0.2.0...HEAD. NOTE: v1 does NOT publish, so the tag may not exist on the remote yet — keep the link template but flag in the release checklist that the tag link resolves only once (if ever) a tag is cut.
- Leave a fresh empty `## [Unreleased]`.
- Generate the detector list in the changelog from the real `detectors/**/*.yml` (cross-checked by a test), not from memory.

== 7. END-TO-END EXAMPLE (docs/examples/end-to-end.md, NEW) ==
- Use the REAL bundled fixture `tests/fixtures/python/vulnerable/os-command.py`:
    import os
    def main() -> None:
        name = input("name: ")
        os.system("echo " + name)
- Show the exact command: `scanipy scan path/to/os-command.py`.
- Show the EXACT text-reporter output, matching TextReporter.render() format precisely:
    HIGH python.injection.os-command [CWE-78] <file>:10:4
        Untrusted input reaches an OS command without sanitization...
        - source: <file>:9:11  input(...)
        - propagator: <file>:10:14  "echo " + name
        - sink: <file>:10:4  os.system(...)

    1 finding.
  (the witness is the ordered source -> propagator -> sink WitnessStep tuple from models.py; line/col MUST be copied from real output, not guessed — the doc-test generates them.)
- Show the exact `--format json` output skeleton (JsonReporter: top-level `tool`/`version`/`findings`, `sort_keys=True`, `indent=2`; each finding via Finding.to_dict() with detector_id/cwe/severity/message/location/witness/fingerprint).
- Show the safe counterpart (`tests/fixtures/python/safe/os-command.py`) producing "No findings." and exit 0 — demonstrates sanitizer/no-shell suppression (P5 one-sidedness).
- Explain exit codes inline (1 for the vuln, 0 for the safe file).
- CRITICAL: the displayed output is produced by running the real CLI in the doc-test and pasted verbatim; the test re-runs and asserts the doc matches, so the example can never drift (P3 determinism gives stable bytes to assert).

== 8. RELEASE-READINESS CHECKLIST (in CHANGELOG or a docs/RELEASING note; v1 = NO PUBLISH) ==
Define an ordered checklist the release-eng agent runs, EXPLICITLY stopping before any outward-facing publish:
  1. All component PRs merged into protected main, CI green (auto-merge admin flow).
  2. `__version__ == "0.2.0"` and CHANGELOG `## [0.2.0]` present and dated.
  3. Full local gate green: `ruff check .` · `ruff format --check .` · `mypy src` · `pytest` (the locked quality gates).
  4. SPDX header present on every new .py (grep gate).
  5. Dogfood: `scanipy scan src` runs clean or every self-finding is triaged (per /scan-self).
  6. Per-detector TP/TN fixtures all pass (P5).
  7. Build sanity (LOCAL only): `python -m build`; confirm the wheel bundles `scanipy/detectors/**/*.yml` and `py.typed`. Do NOT upload.
  8. STOP. v1 ships NO PyPI publish and creates NO `v0.2.0` git tag/release that triggers publishing. Document this divergence from `.claude/commands/release.md` (which tags + Trusted-Publishes) — see open questions. The `/release` command's steps 1-4 apply; steps 5 (tag/push/publish) are DEFERRED for v1.

VERIFICATION STRATEGY: all doc claims that quote CLI output are backed by tests under tests/docs/ that invoke the real CLI via Click's CliRunner (matching the existing tests/conftest.py `runner` fixture) and assert the documented strings appear. This is what makes the docs honest and keeps them from rotting.


**Tasks:**
- (S) RELEASE_DOCS_1: Bump __version__ to 0.2.0
    Edit src/scanipy/__init__.py line 9: `__version__ = "0.1.0"` -> `"0.2.0"`. Do NOT add a version literal anywhere else; pyproject [tool.hatch.version] reads this file. Verify `python -c 'import scanipy; print(scanipy.__version__)'` prints 0.2.0 and `scanipy version` echoes it.
- (M) RELEASE_DOCS_2: De-stub README.md [deps: CLI scan/rules implemented, detector catalog shipped]
    Remove the 0.1.0-scaffold/scan-is-a-stub blockquote (lines 17-20) and all '(coming soon)' notes in Quickstart (lines 48-53). Rewrite Install (lines 38-44) to from-source (`git clone` + `pip install -e ".[dev]"`, `python -m scanipy`) with an explicit 'not on PyPI yet' note (P7). Rewrite Status & roadmap (105-109) to '0.2.0 ships a working engine + the core detectors', listing the actual shipped detector ids+CWEs. Keep the YAML snippet and scanipy Cloud section. Cross-check the detector list against src/scanipy/detectors/**/*.yml.
- (M) RELEASE_DOCS_3: De-stub docs/usage.md [deps: CLI scan/rules implemented, RELEASE_DOCS_7]
    Delete the 'Early scaffold' blockquote (7-13) and every stub/exit-2 note (49-52, the Status column 66-71, exit-code note 104, CI heads-up 117-119). Rewrite Installation to from-source. Update command-surface + exit-code tables to real behavior (2 = error/usage only). Rewrite the CI snippet (121-149) to install from source while KEEPING `if: always()` and `security-events: write`; drop the 'stub exits 2' rationale. Add a 'What scanipy reports' link to docs/examples/end-to-end.md. Document real config keys only if the config component shipped loading, else keep zero-config framing and say config is not loaded.
- (M) RELEASE_DOCS_4: Finalize + lock docs/dsl-reference.md (promote parameter/import) [deps: DSL parser implemented, engine parameter/import support]
    Change status blockquote to 'v0 LOCKED for 0.2.0; additive changes only'. Promote `parameter` and `import` in the kind table (71-77) from 'planned' to 'supported', documenting exactly what each matches and its pattern grammar. Add the flow forms the parser actually accepts (kwarg-targeted args; by-side-effect `from:arg:self`/`to:arg:N`) — READ src/scanipy/dsl/parser.py first; mark anything unimplemented as planned (P7). Lock the `args`/`when` accepted shapes and value coercion. Add a 'Validation' subsection enumerating every rule `scanipy rules validate` enforces and the DSLError class. Confirm the worked example still validates with parse_spec.
- (M) RELEASE_DOCS_5: Refresh docs/writing-detectors.md [deps: RELEASE_DOCS_4, new-detector helper finalized, qa-test fixture harness]
    Align draft notice with dsl-reference (v0-locked, additive-only). Update line-56 kind list so parameter/import read as supported. Delete the 'subcommands still stubs' heads-up (131-133); document real rules validate/list/show. Verify /new-detector scaffolds to src/scanipy/detectors/<class>/<name>.yml + the two fixtures and keep P5 framing. Add an 'anatomy of the bundled os-command detector' walkthrough mapping each YAML key in src/scanipy/detectors/injection/os-command.yml to engine behavior. Document the fixture-naming convention the qa-test harness expects.
- (M) RELEASE_DOCS_6: Write CHANGELOG 0.2.0 section [deps: RELEASE_DOCS_1, detector catalog shipped]
    Add `## [0.2.0] - <merge date>` above the 0.1.0 section with Added/Changed sub-headings per Keep-a-Changelog. Added: working engine (intraproc + intra-file interproc TITO summaries), PythonFrontend, DSL parser+validation, parameter/import promoted, the N core detectors (id+CWE each), per-detector TP/TN fixtures, working scan (text/json/sarif witness-backed) + rules list/show/validate, config (if shipped). Changed: scan/rules no longer stubs; exit 2 no longer means 'not implemented'; DSL v0 locked. Update bottom link refs (52-53): add [0.2.0] compare/tag links, repoint [Unreleased]; flag that the tag may not exist (no publish). Leave a fresh empty ## [Unreleased]. Generate the detector list from the real specs, cross-checked by RELEASE_DOCS_TEST_3.
- (M) RELEASE_DOCS_7: Write verified end-to-end example (docs/examples/end-to-end.md) [deps: CLI scan implemented, engine emits os-command finding, RELEASE_DOCS_1]
    New file. Use the real fixture tests/fixtures/python/vulnerable/os-command.py. Show `scanipy scan <file>` and paste the EXACT TextReporter output (HIGH python.injection.os-command [CWE-78] file:line:col + message + ordered source/propagator/sink witness steps + 'N finding.'). Paste the `--format json` skeleton (tool/version/findings, sort_keys=True). Show the safe counterpart yielding 'No findings.' + exit 0. Explain exit codes inline. Output strings must be produced by running the real CLI (not guessed) and are pinned by RELEASE_DOCS_TEST_2.
- (S) RELEASE_DOCS_8: Define release-readiness checklist (NO publish, v1) [deps: RELEASE_DOCS_1, RELEASE_DOCS_6]
    Add a 'Release readiness (0.2.0)' note (in CHANGELOG header area or a new docs/RELEASING.md). Ordered gate: all PRs merged + CI green; version 0.2.0 + CHANGELOG dated; full local gate (ruff check, ruff format --check, mypy src, pytest); SPDX header grep on new .py; dogfood `scanipy scan src` triaged; per-detector TP/TN green; LOCAL `python -m build` wheel-contents check (detectors yml + py.typed bundled) WITHOUT upload; then STOP — v1 creates NO git tag and does NO PyPI publish. Explicitly note the divergence from .claude/commands/release.md (which tags+publishes): only its steps 1-4 apply for v1.
- (S) RELEASE_DOCS_TEST_1: Test: version + changelog consistency [deps: RELEASE_DOCS_1, RELEASE_DOCS_2, RELEASE_DOCS_3, RELEASE_DOCS_6]
    tests/docs/test_readme_version.py: assert scanipy.__version__ == '0.2.0'; assert '## [0.2.0]' substring in CHANGELOG.md; assert README/usage contain NO 'coming soon' or 'not implemented yet' or 'exit(s) 2 ... stub' strings.
- (M) RELEASE_DOCS_TEST_2: Test: end-to-end example matches real CLI output [deps: RELEASE_DOCS_7]
    tests/docs/test_end_to_end_example.py: invoke cli via CliRunner on the vulnerable fixture; assert key lines from docs/examples/end-to-end.md appear in real output (detector id, CWE-78, role labels source/propagator/sink, '1 finding.'); assert exit_code==1. Invoke on the safe fixture; assert 'No findings.' and exit_code==0. Parse `--format json` output as JSON and assert tool=='scanipy', version=='0.2.0', findings[0].cwe=='CWE-78', witness roles ordered source->...->sink. This pins the doc to reality (P3/P7).
- (M) RELEASE_DOCS_TEST_3: Test: docs reflect the real detector catalog [deps: RELEASE_DOCS_4, RELEASE_DOCS_6, detector catalog shipped, DSL parser implemented]
    tests/docs/test_dsl_reference_consistency.py: load every spec via load_builtin_detectors(); assert each shipped detector id+CWE is mentioned in CHANGELOG.md and README.md (no doc/catalog drift); assert dsl-reference.md no longer marks parameter/import as 'planned'; assert a parameter-kind and import-kind pattern (if any detector uses them) parse via parse_spec without DSLError.

**acceptance_criteria:**
- scanipy.__version__ == '0.2.0' and `scanipy version` prints 'scanipy 0.2.0'; no other version literal exists in the tree.
- README.md and docs/usage.md contain ZERO occurrences of 'coming soon', 'not implemented yet', 'stub', or 'scaffold' as descriptions of scan/rules; scan and rules are described as working.
- Install instructions in README + usage are from-source (pip install -e) and explicitly state scanipy is NOT yet on PyPI (P7); no doc instructs `pip install scanipy-oss` as a working path for v1.
- docs/dsl-reference.md marks `parameter` and `import` as supported (not 'planned'), states the v0 schema is LOCKED for 0.2.0, and has a Validation subsection naming DSLError and the enforced rules; every documented flow/constraint form is actually accepted by parse_spec.
- docs/writing-detectors.md has no 'subcommands are stubs' notice and documents real rules validate/list/show plus the fixture-naming convention; the os-command anatomy walkthrough matches src/scanipy/detectors/injection/os-command.yml.
- CHANGELOG.md has a dated `## [0.2.0]` section listing every shipped detector (id + CWE) and the exit-code semantics change; a fresh empty [Unreleased] remains; link refs updated.
- docs/examples/end-to-end.md shows the real vulnerable fixture, the exact witness-backed finding scanipy prints (source -> propagator -> sink, CWE-78, HIGH), the safe counterpart producing 'No findings.', and correct exit codes 1/0 — all matching real CLI output byte-for-relevant-substring.
- Release-readiness checklist exists, ends with an explicit STOP before any PyPI publish/tag, and documents the divergence from .claude/commands/release.md for v1.
- The detector list in README/CHANGELOG and the parameter/import 'supported' claim are enforced by tests (no manual drift).
- Full quality gate green on the docs/release PR: ruff check . / ruff format --check . / mypy src / pytest; every new .py carries the SPDX header.
- Every documented detector id maps to a real file under src/scanipy/detectors/**/*.yml and vice-versa (bijection enforced by RELEASE_DOCS_TEST_3).

**tests:**
- tests/docs/test_readme_version.py::test_version_is_0_2_0 — scanipy.__version__ == '0.2.0'.
- tests/docs/test_readme_version.py::test_changelog_has_0_2_0 — '## [0.2.0]' in CHANGELOG.md.
- tests/docs/test_readme_version.py::test_no_stub_language — README.md and docs/usage.md contain none of {'coming soon','not implemented yet'} describing scan/rules.
- tests/docs/test_readme_version.py::test_install_not_pypi — README/usage state from-source install (no bare 'pip install scanipy-oss' as the working path).
- tests/docs/test_end_to_end_example.py::test_vulnerable_fixture_reported — CliRunner scan of vulnerable/os-command.py: exit 1, output contains 'python.injection.os-command', 'CWE-78', 'source', 'propagator', 'sink', '1 finding.'.
- tests/docs/test_end_to_end_example.py::test_safe_fixture_clean — scan of safe/os-command.py: exit 0, 'No findings.'.
- tests/docs/test_end_to_end_example.py::test_json_shape — `--format json` parses; tool=='scanipy', version=='0.2.0', findings[0]['cwe']=='CWE-78', witness roles begin 'source' and end 'sink'.
- tests/docs/test_end_to_end_example.py::test_doc_quotes_match_output — the fenced text block in docs/examples/end-to-end.md (sans volatile line:col) is a substring set of the real CLI output.
- tests/docs/test_dsl_reference_consistency.py::test_catalog_documented — every load_builtin_detectors() id+CWE appears in CHANGELOG.md and README.md, and no extra detector is documented.
- tests/docs/test_dsl_reference_consistency.py::test_parameter_import_supported — dsl-reference.md does not mark parameter/import 'planned'; a parameter and an import pattern parse via parse_spec without DSLError (or the doc explicitly says supported-by-parser-unused).
- tests/docs/test_dsl_reference_consistency.py::test_worked_example_validates — the YAML worked example in dsl-reference.md round-trips through parse_spec into a DetectorSpec.
- (reuse) extend tests/unit/test_cli.py to drop the now-false stub assertions (test_scan_is_stubbed etc.) — coordinate with CLI component so the suite is internally consistent.

**risks:**
- DOC DRIFT / over-promising (P7): docs are written by an agent that may not have run the real engine, risking claims the tool does not honor. Mitigation: every CLI-output claim is pinned by a CliRunner doc-test (RELEASE_DOCS_TEST_2); the detector list and parameter/import 'supported' claim are test-enforced (RELEASE_DOCS_TEST_3).
- Witness line/col volatility: hard-coding exact line:col in the end-to-end doc will break if the engine numbers nodes differently. Mitigation: assert role labels + ids + counts, not exact columns; treat line:col as illustrative and regenerate from real output.
- PUBLISH conflict: usage.md CI + .claude/commands/release.md assume `pip install scanipy-oss` and a tag-triggered PyPI publish, but v1 forbids publish. If the docs are edited but release.md is not, the /release slash command will still try to tag+publish. Mitigation: the release checklist explicitly stops before publish and flags release.md; editing release.md itself is an open question (it is harness config, not user docs).
- Parameter/import promotion accuracy: promoting these kinds to 'supported' is only honest if the parser AND engine actually handle them and at least one detector/fixture exercises them. If the engine deferred them, the doc must say 'parsed but not yet acted on' rather than 'supported'. Mitigation: read parser+engine before writing; test parse-without-error.
- Hard dependency on upstream components: nearly every task depends_on the CLI/engine/parser/detector components shipping first. If docs are scheduled too early the doc-tests fail. Mitigation: this is the LAST milestone PR in the dependency-ordered merge flow; gate it on all functional PRs being merged.
- Stale unit tests: tests/unit/test_cli.py currently asserts scan/rules exit 2 (stub). Those tests will FAIL once scan/rules work, blocking auto-merge. Mitigation: coordinate removal/rewrite with the CLI component; the docs PR must not silently leave the suite red.
- Config documentation mismatch: usage.md documents a config file; if the config component deferred real loading, documenting keys as working violates P7. Mitigation: condition the config docs on the real load_config behavior (RELEASE_DOCS_3 depends on CLI/config).
- Determinism in doc-tests (P3): if the engine output order is unstable, substring-set assertions could be flaky. Mitigation: the engine guarantees stable sorted output; the doc-tests rely on that and would surface any P3 regression as a test failure (a feature, not a bug).

**open_questions:**
- Should .claude/commands/release.md (steps 5: tag + push + Trusted-Publish to PyPI) be edited for v1 to remove the publish step, or left as-is with the checklist documenting that v1 stops at step 4? It is harness/agent config, not user-facing docs — recommend leaving it and adding a v1 note, but the user may want it gated.
- Final detector count and stretch detectors: core is 6 (CWE-78/89/94/22/918/502); are XXE and/or disabled-TLS-verification stretch detectors actually shipping in 0.2.0? The README/CHANGELOG lists must match exactly what merges — confirm with the detector-catalog component before writing the lists (tests enforce the bijection regardless).
- Does any shipped detector actually USE the `parameter` or `import` source kind (e.g. a Flask-handler-param SSRF source), or are they only parser-supported? This determines whether dsl-reference says 'supported' vs 'supported by parser, not yet used by a bundled detector'.
- Did the config component ship real `.scanipy.yml` / `[tool.scanipy]` loading? usage.md's config section must reflect reality (document keys vs say zero-config-only).
- What date stamps the 0.2.0 CHANGELOG section — the merge date of the final PR, or left as the build date? Keep-a-Changelog wants a real date; since there is no release/tag, propose the merge date of the docs/release PR.
- Should the version-bump (RELEASE_DOCS_1) live in the docs/release PR or a separate version PR? The /release flow bundles it; recommend bundling into the final docs/release PR so CHANGELOG + version + docs land atomically.
- PyPI badge in README (line 10) currently links to pypi.org/project/scanipy-oss — since v1 does not publish, should the badge be removed/changed to 'not published' to avoid a dead/misleading link (P7)?

