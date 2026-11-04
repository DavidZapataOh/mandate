import { counted, formatCents, formatShare, type Posture, railsText } from "./posture";
import { bankText, type Provenance } from "./provenance";

export type Framework = "NIST AI RMF 1.0" | "ISO/IEC 42001:2023" | "EU AI Act";

export type EvidenceKey =
  | "policies" | "consent" | "decided" | "attacks" | "denied" | "breaches" | "registry" | "verified" | "attribution" | "rails" | "bank";

export interface Control {
  readonly framework: Framework;
  readonly id: string;
  readonly title: string;
  readonly source: string;
  readonly mandate: string;
  readonly evidence: EvidenceKey;
  readonly gap: string;
}

const NIST_GOVERN = "https://airc.nist.gov/airmf-resources/playbook/govern/";
const NIST_MAP = "https://airc.nist.gov/airmf-resources/playbook/map/";
const NIST_MEASURE = "https://airc.nist.gov/airmf-resources/playbook/measure/";
const NIST_MANAGE = "https://airc.nist.gov/airmf-resources/playbook/manage/";
const ISO = "https://www.iso.org/standard/42001";
const EU = "https://eur-lex.europa.eu/eli/reg/2024/1689/oj";
const TEMPLATES = "Seven fixed attack templates are a regression check, not a full adversarial evaluation.";
const INCIDENTS =
  "Attacks that were not blocked and Nimbus steps that ran when they should not are counted, and each opens its forensic record.";
const NO_NOTICE = "Mandate counts and records the incident; it notifies no one.";

export const DISCLAIMER =
  "This report maps Mandate controls to framework provisions. It is not a certification, an audit opinion or a statement of compliance.";
export const APPLICABILITY =
  "The EU AI Act provisions below apply to high-risk AI systems; whether a deployment is high-risk is the deployer's determination, and Mandate does not make it.";

export const CONTROLS: readonly Control[] = [
  {
    framework: "NIST AI RMF 1.0", id: "GOVERN 1.4", source: NIST_GOVERN,
    title: "The risk management process and its outcomes are established through transparent policies, procedures, and other controls based on organizational risk priorities.",
    mandate: "Declarative, versioned policies decide every governed action before it runs; the desk, payments and Nimbus rules in force are served with each report; Muse Code hook lines name their policy id only.",
    evidence: "policies",
    gap: "Mandate enforces the rules an organization writes; it does not set the organization's risk priorities or review them.",
  },
  {
    framework: "NIST AI RMF 1.0", id: "MAP 3.5", source: NIST_MAP,
    title: "Processes for human oversight are defined, assessed, and documented in accordance with organizational policies from GOVERN function.",
    mandate: "A policy rule can require the holder's signed consent; the gate verifies it against the exact action and consumes it once.",
    evidence: "consent",
    gap: "Who may approve, and how approvers are trained, is set by the organization.",
  },
  {
    framework: "NIST AI RMF 1.0", id: "MEASURE 2.4", source: NIST_MEASURE,
    title: "The functionality and behavior of the AI system and its components are monitored when in production.",
    mandate: "Every decision is streamed live with its canonical action, verdict, reason and gate time.",
    evidence: "decided",
    gap: "Mandate observes the actions an agent asks for, not the model's internal behavior or the quality of its output.",
  },
  {
    framework: "NIST AI RMF 1.0", id: "MEASURE 2.7", source: NIST_MEASURE,
    title: "AI system security and resilience are evaluated and documented.",
    mandate: "Pinned attacks run against the real defense layers; each line records the layer, its reason and the cents moved.",
    evidence: "attacks",
    gap: TEMPLATES,
  },
  {
    framework: "NIST AI RMF 1.0", id: "MANAGE 2.4", source: NIST_MANAGE,
    title: "Mechanisms are in place and applied, responsibilities are assigned and understood to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use.",
    mandate: "No certificate, no execution: an action that fails policy, consent or verification is refused before it runs.",
    evidence: "denied",
    gap: "The SDK's kill switch is not operated from this console; assigning responsibility is the organization's.",
  },
  {
    framework: "NIST AI RMF 1.0", id: "MANAGE 4.3", source: NIST_MANAGE,
    title: "Incidents and errors are communicated to relevant AI actors including affected communities. Processes for tracking, responding to, and recovering from incidents and errors are followed and documented.",
    mandate: INCIDENTS,
    evidence: "breaches",
    gap: NO_NOTICE,
  },
  {
    framework: "ISO/IEC 42001:2023", id: "Annex A.6.2.6", source: ISO,
    title: "AI system operation and monitoring",
    mandate: "Every decision is streamed live with its canonical action, verdict, reason and gate time.",
    evidence: "decided",
    gap: "The organization's monitoring plan, thresholds and response are out of scope.",
  },
  {
    framework: "ISO/IEC 42001:2023", id: "Annex A.6.2.8", source: ISO,
    title: "AI system recording of event logs",
    mandate: "Every confirmed or denied desk payment is appended to a Merkle registry with an inclusion proof; every line carries its gate decision event.",
    evidence: "registry",
    gap: "The console keeps the newest 2000 lines in memory and writes them to disk only when started with --record; it enforces no retention period.",
  },
  {
    framework: "ISO/IEC 42001:2023", id: "Annex A.8.4", source: ISO,
    title: "Communication of incidents",
    mandate: INCIDENTS,
    evidence: "breaches",
    gap: NO_NOTICE,
  },
  {
    framework: "ISO/IEC 42001:2023", id: "Annex A.9.2", source: ISO,
    title: "Processes for responsible use of AI systems",
    mandate: "Each money action needs a policy match, the holder's intent or consent, and a single-use certificate the bank verifies.",
    evidence: "verified",
    gap: "The processes are the organization's; Mandate enforces their machine-checkable part.",
  },
  {
    framework: "ISO/IEC 42001:2023", id: "Annex A.10.3", source: ISO,
    title: "Suppliers",
    mandate: "Each decision names the model call behind it: provider, model, request or response id.",
    evidence: "attribution",
    gap: "No supplier assessment; template attacks and desk steps carry no model call.",
  },
  {
    framework: "EU AI Act", id: "Article 12(1)", source: EU,
    title: "Record-keeping: high-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system.",
    mandate: "Gate decision events on every line and a Merkle registry of desk payments with inclusion proofs.",
    evidence: "registry",
    gap: "The obligation is the provider's; Mandate records the actions an agent asked for, not the AI system's own events.",
  },
  {
    framework: "EU AI Act", id: "Article 14(4)(d)-(e)", source: EU,
    title: "Human oversight: decide not to use, or disregard, override or reverse the output; intervene or interrupt the system.",
    mandate: "A desk payment executes only with the holder's signed consent for that exact action, and a bill payment only within the holder's signed intent; a payment that fails either is refused before it runs.",
    evidence: "consent",
    gap: "This console has no stop control; the competence and authority of overseers (Article 26(2)) are the deployer's.",
  },
  {
    framework: "EU AI Act", id: "Article 15(5)", source: EU,
    title: "Accuracy, robustness and cybersecurity: resilient against attempts by unauthorised third parties to alter their use, outputs or performance by exploiting system vulnerabilities.",
    mandate: "Payee swaps, inflated amounts, replays, post-certificate edits, scope escalation, undeclared MCP servers and forged holder approvals are refused at their layer.",
    evidence: "attacks",
    gap: TEMPLATES,
  },
  {
    framework: "EU AI Act", id: "Article 26(5)", source: EU,
    title: "Obligations of deployers: monitor the operation of the high-risk AI system on the basis of the instructions for use.",
    mandate: "This view and the live console show every decision as it happens, each one drillable to its record.",
    evidence: "decided",
    gap: "Informing the provider and suspending use are not automated.",
  },
  {
    framework: "EU AI Act", id: "Article 26(6)", source: EU,
    title: "Obligations of deployers: keep the automatically generated logs for a period of at least six months.",
    mandate: "Lines can be recorded to a JSONL file as they are published (--record); registry proofs verify offline.",
    evidence: "registry",
    gap: "Not met by the console alone: it holds lines in memory; six-month retention needs the deployer to keep the recorded file.",
  },
  {
    framework: "EU AI Act", id: "Article 73(1)", source: EU,
    title: "Reporting of serious incidents by providers to the market surveillance authorities.",
    mandate: INCIDENTS,
    evidence: "breaches",
    gap: "Mandate does not report to any authority.",
  },
];

/** The registry a window rests on; an empty one is said to be empty rather than shown as a root over nothing. */
export function registryText(r: NonNullable<Provenance["registry"]>): string {
  if (r.leaves === 0) return `registry empty (${r.from})`;
  return `registry root ${r.root.slice(0, 16)} over ${counted(r.leaves, "entry", "entries")} (${r.from})`;
}

/** This window's evidence for a control, computed from the posture and provenance only. */
export function evidenceText(key: EvidenceKey, p: Posture, prov: Provenance): string {
  switch (key) {
    case "decided":
      return `${counted(p.decided.count, "action", "actions")} decided`;
    case "verified":
      return `${p.verified.count} verified`;
    case "denied":
      return `${p.denied.count} denied before execution`;
    case "breaches":
      return `${counted(p.breaches.count, "attack", "attacks")} not blocked · ${counted(p.stepsRan.count, "deploy step ran when it should not", "deploy steps ran when they should not")}`;
    case "attacks": {
      const attempts = p.attacks.reduce((n, a) => n + a.attempts, 0);
      const blocked = p.attacks.reduce((n, a) => n + a.blocked, 0);
      return `${blocked} of ${counted(attempts, "attack", "attacks")} blocked · ${formatCents(p.movedCents)} moved`;
    }
    case "consent":
      return `certified payments with holder consent: ${formatShare(p.consent.withConsent.count, p.consent.certified.count)}`;
    case "attribution":
      return `decisions naming their model call: ${formatShare(p.attribution.attributed.count, p.decided.count)}`;
    case "rails":
      return `verified payments by rail: ${railsText(p)}`;
    case "bank": {
      const b = prov.bank;
      if (prov.source === "replay" || prov.epoch === null || b === null || b.error !== null) {
        return bankText(prov);
      }
      const twice = b.paid_twice.length > 0 ? `; paid twice: ${b.paid_twice.join(", ")}` : "";
      const unread = b.unreadable.length > 0 ? `; not read: ${b.unreadable.join(", ")}` : "";
      return `bank lists ${counted(b.transfers, "transfer", "transfers")} since ${b.since}: ${b.certified} with a certificate and a sealed entry, ${b.unbacked.length} without; ${counted(b.missing.length, "sealed payment", "sealed payments")} missing at the bank${twice}${unread}`;
    }
    case "registry":
      return prov.registry === null
        ? "no registry root in this window"
        : registryText(prov.registry);
    case "policies":
      return prov.policies === null
        ? "policies not served in this window"
        : `policies served: ${prov.policies.map((x) => `${x.policy_id} v${x.version}`).join(", ")}`;
  }
}
