// CloudShield analyst console.
// Every value shown here can come from an attacker (process names, command lines, alert titles),
// so the page is built only with DOM nodes and text nodes: no value is ever parsed as HTML
// (tests/test_console.py fails the build if an HTML-parsing sink appears in this file).
"use strict";

const TOKEN_KEY = "cloudshield-analyst-token";
const SEVERITY = ["informational", "low", "medium", "high", "critical"];
const state = { token: null, me: null, caseId: null };
const $root = () => document.getElementById("root");

// ---- DOM helper -------------------------------------------------------------------------------

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

const pill = (text, kind = "") => el("span", { class: `pill ${kind}` }, text);
const time = (iso) => (iso ? iso.slice(11, 19) + "Z" : "");
const short = (id) => (id && id.length > 14 ? id.slice(0, 8) + "…" + id.slice(-4) : id);

// ---- API --------------------------------------------------------------------------------------

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { Accept: "application/json" };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = data && data.detail;
    const text = typeof detail === "string" ? detail : detail ? JSON.stringify(detail) : res.statusText;
    throw new ApiError(res.status, text);
  }
  return data;
}

function toast(message, isError = false) {
  const box = document.getElementById("toast");
  box.textContent = message;
  box.className = isError ? "toast error" : "toast";
  box.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (box.hidden = true), 5000);
}

async function act(label, fn) {
  try {
    await fn();
    toast(label);
  } catch (err) {
    toast(err.status ? `${err.status}: ${err.message}` : String(err), true);
  }
  await refresh();
}

// ---- session ----------------------------------------------------------------------------------

function storeToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch (_) {
    /* private mode: the session simply isn't remembered */
  }
}

async function startSession() {
  try {
    state.token = sessionStorage.getItem(TOKEN_KEY);
  } catch (_) {
    state.token = null;
  }
  if (!state.token) {
    try {
      state.token = (await api("/v1/console/demo-session")).token; // lab demo mode only
    } catch (_) {
      state.token = null;
    }
  }
  if (state.token) {
    try {
      state.me = await api("/v1/me");
      storeToken(state.token);
    } catch (_) {
      state.token = null;
      storeToken(null);
    }
  }
  renderWho();
  if (!state.me) return renderLogin();
  await refresh();
}

function renderWho() {
  const who = document.getElementById("who");
  who.replaceChildren();
  if (!state.me) return;
  who.append(
    el("span", {}, state.me.id),
    pill(state.me.roles.join(", ")),
    el("button", { onclick: () => { storeToken(null); state.token = state.me = null; renderWho(); renderLogin(); } }, "Sign out"),
  );
}

function renderLogin() {
  const input = el("input", { type: "password", placeholder: "Analyst token", autocomplete: "off", required: true });
  const form = el(
    "form",
    {
      onsubmit: async (event) => {
        event.preventDefault();
        state.token = input.value.trim();
        try {
          state.me = await api("/v1/me");
          storeToken(state.token);
          renderWho();
          await refresh();
        } catch (_) {
          state.token = null;
          toast("That token was not accepted.", true);
        }
      },
    },
    el("h2", {}, "Sign in"),
    el("p", { class: "muted" }, "Paste the analyst token issued for this deployment."),
    input,
    el("button", { class: "primary", type: "submit" }, "Sign in"),
  );
  $root().replaceChildren(el("section", { class: "card login" }, form));
}

// ---- pages ------------------------------------------------------------------------------------

async function refresh() {
  if (!state.me) return;
  const [cases, coverage] = await Promise.all([api("/v1/cases"), api("/v1/health/coverage")]);
  renderCoverage(coverage);
  if (!state.caseId && cases.length) {
    // Open on the case that most needs attention: highest severity, then the most evidence.
    const rank = (c) => SEVERITY.indexOf(c.severity) * 1000 + c.event_count;
    state.caseId = [...cases].sort((a, b) => rank(b) - rank(a))[0].case_id;
  }
  const list = el(
    "nav",
    { class: "cases", "aria-label": "Cases" },
    cases.length ? null : el("p", { class: "muted" }, "No cases yet."),
    cases.map((c) =>
      el(
        "button",
        { class: `case-item${c.case_id === state.caseId ? " active" : ""}`, onclick: () => { state.caseId = c.case_id; refresh(); } },
        el("span", { class: "title" }, c.title),
        el("span", { class: "meta" }, pill(c.severity, c.severity), el("span", {}, `${c.event_count} events`), el("span", {}, c.status)),
      ),
    ),
  );
  const main = state.caseId ? await renderCase(state.caseId) : el("section", {});
  $root().replaceChildren(el("aside", {}, list), main);
}

function renderCoverage(coverage) {
  const box = document.getElementById("coverage");
  box.replaceChildren(
    ...Object.entries(coverage.sources).map(([source, s]) =>
      el("span", { class: `pill ${s.state}`, title: s.last_seen ? `last seen ${s.last_seen}` : "never seen" }, el("span", { class: "dot" }), `${source} ${s.state}`),
    ),
  );
}

async function renderCase(caseId) {
  const [detail, timeline, investigations, proposals, audit] = await Promise.all([
    api(`/v1/cases/${encodeURIComponent(caseId)}`),
    api(`/v1/cases/${encodeURIComponent(caseId)}/timeline`),
    api(`/v1/cases/${encodeURIComponent(caseId)}/investigations`),
    api(`/v1/cases/${encodeURIComponent(caseId)}/proposals`),
    api(`/v1/audit?case_id=${encodeURIComponent(caseId)}`),
  ]);
  const byId = Object.fromEntries(timeline.map((t) => [t.event_id, t]));
  const investigation = investigations.at(-1);
  const proposal = proposals.at(-1);
  const pod = detail.events.find((e) => e.resource_id && e.resource_id.startsWith("k8s:pod/"));

  return el(
    "section",
    { class: "incident" },
    el(
      "div",
      { class: "incident-head" },
      el("div", {}, el("h1", {}, detail.title), el("div", { class: "muted mono" }, detail.case_id)),
      el("div", { class: "row" }, pill(detail.severity, detail.severity), proposal ? pill(proposal.state.replaceAll("_", " "), proposal.state) : pill("no action proposed")),
    ),
    synopsisCard(caseId, investigation),
    await entityCard(pod),
    timelineCard(timeline),
    findingsCard(investigation, byId),
    actionCard(caseId, detail, investigation, proposal),
    el(
      "div",
      { class: "auditbar" },
      pill(audit.chain_intact ? "audit chain intact" : "AUDIT CHAIN BROKEN", audit.chain_intact ? "ok" : "failed"),
      `${audit.records.length} hash-chained records for this case`,
    ),
  );
}

function card(num, title, ...body) {
  return el("section", { class: "card" }, el("h2", {}, el("span", { class: "num" }, num), title), ...body);
}

function synopsisCard(caseId, inv) {
  if (!inv) {
    return card("1", "Synopsis",
      el("p", { class: "muted" }, "No investigation yet."),
      el("div", { class: "actions" },
        el("button", { class: "primary", onclick: () => act("Investigation stored", () => api(`/v1/cases/${encodeURIComponent(caseId)}/investigations`, { method: "POST" })) }, "Run AI investigation")));
  }
  const note = el("input", { type: "text", placeholder: "Review note (required)" });
  const review = (decision) => () =>
    act(`Investigation ${decision}`, () => {
      if (!note.value.trim()) throw new Error("Add a review note first.");
      return api(`/v1/investigations/${encodeURIComponent(inv.investigation_id)}/review`, { method: "POST", body: { decision, note: note.value } });
    });
  return card("1", "Synopsis",
    el("p", {}, inv.output.synopsis),
    el("div", { class: "row muted" },
      pill(inv.review_status, inv.review_status),
      el("span", {}, `model ${inv.model_id}`), el("span", {}, "·"), el("span", {}, `prompt ${inv.prompt_version}`),
      el("span", {}, "·"), el("span", {}, `runbooks ${inv.retrieved_doc_ids.join(", ") || "none"}`)),
    inv.review_status === "unreviewed"
      ? el("div", { class: "actions" }, note, el("button", { onclick: review("accepted") }, "Accept"), el("button", { class: "danger", onclick: review("rejected") }, "Reject"))
      : el("p", { class: "muted" }, `Reviewed by ${inv.reviewed_by}.`));
}

const CHAIN = ["pod", "deployment", "service_account", "iam_role", "ec2_instance"];
const PAST = { approve: "approved", reject: "rejected" };

async function entityCard(pod) {
  if (!pod) return card("2", "Affected entity", el("p", { class: "muted" }, "No Kubernetes pod in this case."));
  let entities = [];
  try {
    entities = (await api(`/v1/entities/${encodeURI(pod.resource_id)}/graph`)).entities;
  } catch (_) {
    /* not enriched: show the pod alone, unresolved */
  }
  const found = CHAIN.map((kind) => entities.find((e) => e.kind === kind)).filter(Boolean);
  const nodes = found.length ? found : [{ kind: "pod", entity_id: pod.resource_id }];
  const parts = [];
  nodes.forEach((n, i) => {
    if (i) parts.push(el("span", { class: "arrow" }, "→"));
    parts.push(el("span", { class: "node", title: n.entity_id }, el("span", { class: "kind" }, n.kind.replace("_", " ")), el("span", {}, n.entity_id.split("/").at(-1))));
  });
  const note = found.length < CHAIN.length ? el("p", { class: "muted" }, "Links not shown were not resolved; CloudShield never guesses them.") : null;
  return card("2", "Affected entity", el("div", { class: "chain" }, parts), note);
}

function timelineCard(timeline) {
  return card("3", "Timeline (event time)",
    el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Time"), el("th", {}, "Source"), el("th", {}, "What happened"), el("th", {}, "Severity"), el("th", {}, "Event"))),
      el("tbody", {}, timeline.map((t) =>
        el("tr", {}, el("td", { class: "mono" }, time(t.event_time)), el("td", {}, t.source), el("td", {}, t.title), el("td", {}, pill(t.severity, t.severity)), el("td", { class: "mono", title: t.event_id }, short(t.event_id)))))));
}

function findingsCard(inv, byId) {
  if (!inv) return card("4", "Facts and hypotheses", el("p", { class: "muted" }, "Run an investigation to see cited facts."));
  const cite = (id) => el("span", { class: "cite", title: id }, byId[id] ? `${byId[id].source} ${time(byId[id].event_time)}` : short(id));
  return card("4", "Facts and hypotheses",
    el("ul", { class: "plain" },
      inv.output.observed_facts.map((f) => el("li", { class: "fact" }, el("span", { class: "tag fact" }, "FACT"), el("span", {}, f.statement, f.evidence_ids.map(cite)))),
      inv.output.hypotheses.map((h) => el("li", { class: "fact" }, el("span", { class: "tag hyp" }, "HYPOTHESIS"), el("span", {}, pill(h.confidence, h.confidence), " ", h.statement, h.supporting_evidence.map(cite)))),
      inv.output.missing_evidence.map((m) => el("li", { class: "fact" }, el("span", { class: "tag miss" }, "MISSING"), el("span", { class: "muted" }, m)))),
    el("p", { class: "muted" }, inv.output.confidence_limits));
}

function actionCard(caseId, detail, inv, proposal) {
  if (!proposal) {
    const option = inv && inv.output.containment_options[0];
    if (!option) return card("5", "Proposed action", el("p", { class: "muted" }, "Nothing proposed. Run an investigation for containment options."));
    const [, namespace, name] = option.target_entity_id.split("/");
    const event = detail.events.find((e) => e.resource_id === option.target_entity_id && e.keys.pod_uid);
    const propose = () => api(`/v1/cases/${encodeURIComponent(caseId)}/proposals`, {
      method: "POST",
      body: { action_type: option.action_type, rationale: option.rationale, target: { kind: "Pod", name, namespace, uid: event ? event.keys.pod_uid : "" } },
    });
    return card("5", "Proposed action",
      el("dl", { class: "kv" }, el("dt", {}, "Suggested"), el("dd", {}, option.action_type), el("dt", {}, "Target"), el("dd", { class: "mono" }, option.target_entity_id), el("dt", {}, "Why"), el("dd", {}, option.rationale), el("dt", {}, "Blast radius"), el("dd", {}, option.expected_blast_radius)),
      el("div", { class: "actions" }, el("button", { class: "primary", onclick: () => act("Proposal created", propose) }, "Propose this action")));
  }

  const pid = encodeURIComponent(proposal.proposal_id);
  const impact = proposal.impact_preview || {};
  const policy = proposal.policy;
  const rows = [
    ["Action", proposal.action_type],
    ["Target", `${proposal.target.namespace}/${proposal.target.name}`],
    ["Requested by", proposal.requested_by],
    ["Policy", policy ? `${policy.decision.replaceAll("_", " ")} · ${policy.required_approvals} approval(s) · ${policy.reasons.join("; ")}` : "not checked yet"],
    ["Impact", impact.allow_policies_lost ? `pod keeps running; loses ${impact.allow_policies_lost.join(", ") || "nothing"}` : "dry-run not run yet"],
    ["Approvals", proposal.approvals.length ? proposal.approvals.map((a) => `${a.approver} ${PAST[a.decision]}`).join(", ") : "none"],
    ["Version", proposal.proposal_hash.slice(0, 19) + "…"],
  ];
  const body = [el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]))];
  if (impact.caveat) body.push(el("p", { class: "muted" }, impact.caveat));

  const justification = el("input", { type: "text", placeholder: "Justification (required)" });
  const decide = (verb) => () =>
    act(`Proposal ${PAST[verb]}`, () => {
      if (!justification.value.trim()) throw new Error("Add a justification first.");
      return api(`/v1/proposals/${pid}/${verb}`, { method: "POST", body: { proposal_hash: proposal.proposal_hash, justification: justification.value } });
    });
  const buttons = {
    proposed: [el("button", { class: "primary", onclick: () => act("Dry-run and policy check done", () => api(`/v1/proposals/${pid}/dry-run`, { method: "POST" })) }, "Run dry-run and policy check")],
    awaiting_approval: [justification, el("button", { class: "primary", onclick: decide("approve") }, "Approve"), el("button", { class: "danger", onclick: decide("reject") }, "Reject")],
    approved: [el("button", { class: "primary", onclick: () => act("Executed and verified", () => api(`/v1/proposals/${pid}/execute`, { method: "POST" })) }, "Execute once and verify")],
  }[proposal.state];
  if (buttons) body.push(el("div", { class: "actions" }, buttons));

  if (proposal.execution) {
    const mark = { true: ["ok", "ok"], false: ["failed", "failed"], null: ["skipped", ""] };
    body.push(el("ul", { class: "plain checks" },
      Object.entries(proposal.execution.checks).map(([name, passed]) => {
        const [text, kind] = mark[String(passed)];
        return el("li", {}, pill(text, kind), el("span", { class: "mono" }, name), proposal.execution.notes[name] ? el("span", { class: "muted" }, proposal.execution.notes[name]) : null);
      })));
  }
  return card("5", "Proposed action", ...body);
}

startSession();
