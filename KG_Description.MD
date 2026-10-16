# Cybersecurity Knowledge Graph: CVE / CWE / CAPEC

A Neo4j knowledge graph of ~370K nodes and ~177K relationships integrating CVE vulnerabilities, CWE weaknesses, and CAPEC attack patterns. CVEs link to CWEs via `RELATED_WEAKNESS`, CWEs form a hierarchy via `CHILD_OF`/`PARENT_OF`, and CWEs link to CAPECs via `RELATED_ATTACK_PATTERN`, enabling traversal from a specific vulnerability to its root-cause weakness class and the attack techniques that exploit it.

## Overview

This property graph links three major cybersecurity taxonomies into one traversable structure. It connects **concrete vulnerabilities** (CVE) to the **weakness classes** that cause them (CWE) and the **attack patterns** that exploit those weaknesses (CAPEC).

| Metric | Value |
|---|---|
| Nodes | ~370,000 |
| Relationships | ~177,000 |

## Node Types

| Label | Count (approx.) | Represents | Source |
|---|---|---|---|
| **CVE** | the vast majority of nodes | A specific, publicly disclosed vulnerability in a particular product | CVE / NVD |
| **CWE** | ~1,000 | A general class of software or hardware weakness | MITRE CWE |
| **CAPEC** | ~600 | A known attack pattern describing how adversaries exploit weaknesses | MITRE CAPEC |

> Counts for CWE and CAPEC are estimates based on typical catalog sizes. Verify with `MATCH (n:CWE) RETURN count(n)`.

### CVE (Vulnerability)

An individual vulnerability record, e.g. `CVE-2024-45402` (a double free in picotls).

- **Identity:** `id`, `vendor`, `product`, `assigner`, `state`
- **Severity:** `cvss_base_score`, `cvss_severity`, with the full vector and version in `meta_cvss_*`
- **Content:** `description`, `date_published`, `date_updated`
- **Meta:** references (advisories, patches) in `meta_rdf_type`
- **Typing:** `rdf_type = "Vulnerability"`

### CWE (Weakness)

A root-cause category, e.g. `CWE-1021` (Improper Restriction of Rendered UI Layers or Frames, i.e. clickjacking).

- **Identity:** `id`, `name`, `description`, `abstraction` (Pillar / Class / Base / Variant), `status`
- **Impact:** `consequence_scope` and `consequence_impact` (e.g. Access Control → Gain Privileges)
- **Context:** `platform`, `introduction_phase`
- **Meta:** detection methods and observed example CVEs
- **Typing:** `rdf_type = "Weakness"`

### CAPEC (Attack Pattern)

An adversary technique, e.g. `CAPEC-151` (Identity Spoofing).

- **Identity:** `id`, `name`, `description`, `abstraction` (Meta / Standard / Detailed), `status`
- **Risk:** `likelihood`, `severity`
- **Impact:** `consequence_scope` and `consequence_impact`
- **Meta:** prerequisites and mitigations
- **Typing:** `rdf_type = "AttackPattern"`

## Relationship Types

| Relationship | Connects | Meaning |
|---|---|---|
| **RELATED_WEAKNESS** | CVE → CWE (also CAPEC → CWE) | The vulnerability is an instance of this weakness, or the attack pattern targets it |
| **RELATED_ATTACK_PATTERN** | CWE → CAPEC | Attack patterns that can exploit this weakness |
| **CHILD_OF** | CWE → CWE (CAPEC → CAPEC) | Hierarchical link to a more general parent |
| **PARENT_OF** | CWE → CWE (CAPEC → CAPEC) | Inverse of CHILD_OF, pointing to more specific children |

`CHILD_OF` and `PARENT_OF` are stored as separate edges, so traversals can go in either direction without reversing relationships.

## Structure and Example

The graph is layered:

```
CVE  ──RELATED_WEAKNESS──▶  CWE  ◀──CHILD_OF/PARENT_OF──▶  CWE
                             │
                             └──RELATED_ATTACK_PATTERN──▶  CAPEC
```

Example path:

```
CVE-2024-45402
  └─ RELATED_WEAKNESS ─▶ CWE-415  (Double Free)
       └─ CHILD_OF ─▶ CWE-666  (Operation on Resource in Wrong Phase of Lifetime)
            └─ CHILD_OF ─▶ CWE-664  (Improper Control of a Resource Through its Lifetime)
                 └─ PARENT_OF ─▶ CWE-610
                      └─ PARENT_OF ─▶ CWE-1021
```

This lets you move from a single vulnerability up to its abstract weakness family, across to sibling weaknesses, and over to the attack patterns that exploit them.

## Data Model Notes

- Properties are **flattened with numeric suffixes** (`child_of_5`, `consequence_impact_18`, `platform_15`), which looks like an RDF-to-property-graph import. Multi-valued fields are expanded into separate properties, so queries on them need wildcard or `keys(n)` handling. Normalizing these into lists or relationships would make querying easier.
- Each node has an `rdf_type` (Vulnerability / Weakness / AttackPattern) mirroring its label.
- Nested data (detection methods, observed examples, references, prerequisites, mitigations) is stored as **JSON strings** in `meta_*` properties.
- `cvss_base_score` is stored as a **string**, so cast it with `toFloat()` for numeric filtering.

## Example Use Cases

- **Root-cause analysis:** map a CVE to its weakness hierarchy and find sibling vulnerabilities.
- **Threat modeling:** from a CWE, find which CAPEC attack patterns can exploit it.
- **Risk prioritization:** filter CVEs by CVSS severity, grouped by weakness class or vendor.
- **Defensive coverage:** from an attack pattern, derive the weaknesses to test for and the mitigations to apply.
- **GraphRAG / LLM grounding:** use the graph as a structured knowledge base for security Q&A, retrieving a CVE with its CWE ancestors and linked CAPEC patterns as context.