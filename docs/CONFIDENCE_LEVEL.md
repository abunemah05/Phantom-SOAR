# AI minimum confidence level

The setting `agent_min_confidence` (environment variable `PHANTOM_AGENT_MIN_CONFIDENCE`) is the lowest confidence an
AI agent proposal may report and still run **without a person**. The console shows it as a drop-down of named levels,
not as a box you type a number into (requirement from the instructor review). This page lists the levels, explains
why our default is 85%, and records what other products publish. Everything in the research table was read on the
page linked in the table; where a product publishes nothing, the table says so.

## How the setting works here

* Autonomy decides whether the agent may act alone at all. The default is `recommend_only`: every proposal waits for
  an analyst, and the minimum confidence has no effect. See [ARCHITECTURE.md](ARCHITECTURE.md).
* Only when autonomy is `low_impact` or `policy` does the policy engine compare the agent's confidence with this
  setting (`backend/engine/policy.py`): a proposal below the minimum, or one without a confidence, waits for approval.
  High-impact actions always need approval, protected assets are never touched by an agent, and simulation mode
  still blocks real actions. The confidence check is one gate of several, never the only one.
* The backend stores a plain number and validates it strictly as `0 <= value <= 1` (`backend/routers/config.py`). The
  drop-down only changes how the number is picked in the UI; the saved string and the policy engine are unchanged.

## Selectable levels

Lower levels let weaker proposals through, so they are listed with what that costs. The list is defined in
`frontend/src/lib/confidenceLevels.ts`; a backend test reads that file and checks that every level is accepted.

| Level in the drop-down | Stored value | Meaning |
|---|---|---|
| Near certain (99%) | `0.99` | Almost every proposal waits for an analyst. |
| Very high (95%) | `0.95` | Strict. |
| High (90%) | `0.9` | Strict. |
| **Default (85%)** | `0.85` | Our default. Conservative. |
| Moderate (80%) | `0.8` | More proposals qualify. Review past proposals first. |
| Lenient (75%) | `0.75` | Use only for low-impact actions. |
| Low (70%) | `0.7` | Not recommended in production. |
| Very low (60%) | `0.6` | Not recommended outside a lab. |
| Minimal (50%) | `0.5` | No real filtering. Lab only. |

A value saved earlier through the API or an environment variable that is not in the list (for example `0.87`) is shown
as **Custom (87%)**. It keeps working; the page tells the user it was set outside the console, and choosing any listed
level replaces it. Backend validation is unchanged, so the API still accepts any number from 0 to 1.

## Why our default is 0.85

1. **It is a conservative starting value, not a measured one.** No calibration data from this project backs 85%
   specifically. We chose a value in the "strict" part of the range so a fresh install errs towards asking a person.
   Treat it as a placeholder until you have measured the agent on your own alerts.
2. **The default does not act on it.** Autonomy defaults to `recommend_only`, so out of the box the number only
   labels proposals. Raising autonomy is the deliberate step; the confidence minimum is the second lock.
3. **Model-stated confidence is not calibrated.** The agent asks the model for a 0..1 estimate
   (`backend/engine/ai_triage.py`). Published work finds that models that state their own confidence in words tend to
   be overconfident ([arXiv 2306.13063](https://arxiv.org/abs/2306.13063)), while larger models can be fairly
   well calibrated under favourable test formats ([arXiv 2207.05221](https://arxiv.org/abs/2207.05221)). Neither
   result tells you what 0.85 means for *your* alerts, so the number is a coarse filter, not a probability.
4. **Why steps of 5 to 10 points.** Because the estimate is coarse, finer choices (0.851 versus 0.849) would be false
   precision. The list therefore uses named steps and stops at 99%: 100% would mean "the model is never wrong", which
   no test can show.
5. **Our guidance for changing it:** keep autonomy on `recommend_only` first, compare the agent's verdicts with
   analyst decisions on the Agent page, and only then consider `low_impact`. Swimlane describes the same idea:
   autonomy per case type is earned from measured agreement with analysts (see the table).

## What other products do (researched)

Findings are limited to what the linked page says. "No public default found" means the page(s) we opened did not state
one; it does not mean the product has none.

| Product | Setting or concept | Default | How chosen or documented | Source |
|---|---|---|---|---|
| Splunk SOAR | Approvers per asset for actions with a write component | No confidence or percentage threshold; approval is by a fixed number of approvers (number and SLA defaults not stated on the page) | Documented as a human approval gate with SLA and escalation, not a confidence score | [Approve actions before they run](https://help.splunk.com/en/splunk-soar/soar-cloud/use-soar-cloud/get-started-using-splunk-soar-cloud/approve-actions-before-they-run-in-splunk-soar-cloud) |
| Splunk Enterprise Security | Risk score from "impact and confidence"; risk threshold for notables | No default threshold stated; examples use 100, and a confidence example uses 80 (high), 100 (medium), 200 (other) | Guidance: lower the threshold for a high-confidence risk notable, raise it for a low-confidence one; set by the probability a risk event is malicious or by asset criticality. Scores 20 to 100 by severity; the page says the range "does not represent an industry standard" | [Adjust the risk threshold](https://docs.splunk.com/Documentation/ES/7.1.1/RBA/AdjustRiskThreshold), [How risk scores work](https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/introduction/how-risk-scores-work-in-splunk-enterprise-security) |
| Palo Alto Cortex XSOAR | DBotScore 0 to 3 (Unknown, Good, Suspicious, Bad); integration "Source Reliability" A+ to F | No numeric mapping or default threshold on the page; the developer example uses "C - Fairly reliable"; enrichment integrations without a reliability parameter default to A+ | Verdict comes from the source with the highest reliability; ties go to the worse verdict. No reason is given for the defaults | [DBot score](https://xsoar.pan.dev/docs/integrations/dbot), [Source reliability](https://cortex-docs.paloaltonetworks.com/xsoar-6-administrator-guide/6.15/customize-cortex-xsoar/customize-and-configure-cortex-xsoar/indicators/feed-integrations/set-the-source-reliability-of-enrichment-integrations), [Indicator verdict](https://cortex-docs.paloaltonetworks.com/cortex-xsoar-6-threat-intel-management-guides/6.15/learn-about-threat-intel-management/readme-1/indicator-verdict) |
| Microsoft Defender (Endpoint AIR) | Automation level (full, three semi levels, none) | No confidence threshold. Full automation is the default for tenants created on or after 16 Aug 2020 without device groups; semi (approve all folders) for older tenants; full for Defender for Business | Page cites that customers on full automation had 40% more high-confidence malware samples removed; it does not explain how the default was chosen | [Automation levels](https://learn.microsoft.com/en-us/defender-endpoint/automation-levels) |
| Microsoft Defender XDR | Automatic attack disruption | Not configurable as a threshold. Containment actions are held to "a confidence level of 99% or higher" (detector precision, from production data) | Detectors run in audit mode first and are released only if they meet quality requirements; exclusions for critical assets are configurable | [Automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption) |
| Microsoft Sentinel | Alert `ConfidenceLevel` and `ConfidenceScore` (0.0 to 1.0); automation rule conditions | No default or threshold. Automation rules compare severity with equals / not equals only; alert-trigger rules can filter only on the analytics rule | Fields are described as how sure the provider is that the alert is not a false positive | [Alert schema](https://learn.microsoft.com/en-in/azUre/sentinel/security-alert-schema), [Automation rules](https://learn.microsoft.com/en-us/azure/sentinel/create-manage-use-automation-rules) |
| IBM QRadar SOAR | Confidence or threshold for automatic playbook actions | No public default found (the documentation index page we opened has none) | Not documented on the page we opened | [QRadar SOAR docs](https://www.ibm.com/docs/en/SSTDPP_1.10/orchestration/Resilient_SOAR.html) |
| Google SecOps (Chronicle) SOAR | Entity risk score bands; rule `$risk_score` | No confidence threshold found. If a rule omits the risk score, SecOps assigns 40 (alerts) or 15 (detections). Bands on a 1 to 1000 scale: Low 1 to 300, Medium 310 to 790, High 800+ | A community adoption guide (not formal product docs) says to audit the default scores against your risk appetite; example thresholds (90, 100) are illustrations | [Adoption guide: risk analytics](https://security.googlecloudcommunity.com/google-security-operations-66/adoption-guide-risk-analytics-in-google-secops-engineering-entity-centric-detection-6589) |
| Tines | Human approval for AI agent actions | No numeric confidence threshold on the page | Qualitative: "Matching autonomy to blast radius is the underlying principle"; high-impact actions such as disabling a production identity or isolating a host always need approval | [How to build AI agents your security team will approve](https://www.tines.com/blog/how-to-build-ai-agents-your-security-team-will-approve/) |
| Swimlane | Autonomy tiers for its verdict agent | No numeric confidence default. Tiers by agreement with analysts per case type: 98% or more agreement is an auto-close candidate, around 90% goes to one-click analyst confirmation, low confidence or unbenchmarked cases get a full human investigation | Vendor blog; says agents were benchmarked against about 35,000 human investigations. It does not say how the percentages were chosen | [Swimlane verdict agent](https://swimlane.com/blog/verdict-ai-agent/) |
| Shuffle | Confidence or threshold for automatic actions | No public default found (the docs page we opened rendered no content on this topic) | Not verified | [Shuffle docs](https://shuffler.io/docs/workflows) |
| Elastic Security | Detection rule risk score and severity | No confidence setting. Risk score is 0 to 100 and changes to a default value when severity changes; guideline ranges Low 0 to 21, Medium 22 to 47, High 48 to 73, Critical 74 to 100 | Called "General guidelines"; the page does not say how the ranges were chosen | [Common rule settings](https://www.elastic.co/docs/solutions/security/detect-and-alert/common-rule-settings) |
| NIST AI RMF 1.0 | Risk tolerance and human oversight | No universal threshold: "it does not prescribe risk tolerance"; "Where established guidelines do not exist, organizations should define reasonable risk tolerance" | Thresholds are set by organizational judgment and documented (MAP 1.5, MAP 3.5); the document does not discuss confidence calibration directly | [NIST AI 100-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) |

### What the research shows

* **No product we could verify publishes a default minimum confidence for AI-initiated actions that was derived from
  calibration data.** Where a number exists it is either a detector-quality target (Defender: 99% or higher precision
  for containment, validated before release), an example (Splunk ES), or a guideline range (Elastic, Google SecOps).
* **The common pattern is not a confidence number at all.** Splunk SOAR, Tines and Defender (levels) gate by human
  approval and by the blast radius of the action. This matches our policy engine, where high-impact actions always
  need approval whatever the confidence.
* **Where a product does use a high bar for automatic containment, it is very high** (Defender: 99% or higher; Swimlane:
  98% or more agreement for auto-close). Our selectable list therefore starts at 99% and keeps 85% as a conservative,
  not a maximal, default.
* Not verified: Cortex XSOAR numeric thresholds per vendor (they are set in each integration), QRadar SOAR and Shuffle
  (nothing found), and the formula Splunk ES uses to combine impact and confidence (not stated on the page we read).

## Other typed settings (not changed)

These are score thresholds for threat-intelligence verdicts, not the AI trust level, and stay typed numbers with range
validation: `tip_malicious_threshold`, `tip_suspicious_threshold`, `tip_critical_threshold` (1 to 100),
`vt_malicious_threshold` (0.001 to 1), `vt_min_detections`, `vt_malicious_weight`, `vt_suspicious_weight`. They tune how a
reputation score is computed from provider data and have to be consistent with each other, so a single list of named
levels would not describe them.
