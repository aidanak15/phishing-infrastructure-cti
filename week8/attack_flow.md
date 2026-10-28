# Week 8 — Conceptual Attack Flow

This diagram maps hypotheses to ATT&CK, **not** an observed successful compromise.

```mermaid
flowchart TD
    A[Training link navigation<br/>T1566.002 — Initial Access context] --> B{Hypothetical compromise<br/>NOT demonstrated}
    B --> C[Benign cron marker plan<br/>T1053.003 — Persistence]
    C --> D[Fictional test data access plan<br/>T1005 — Collection]
    D --> E[Approved HTTP dummy transfer plan<br/>T1048.003 — Exfiltration context]
    A -.-> F[Week 6 HTTP evidence: partial]
    C -.-> G[Need endpoint task telemetry]
    E -.-> H[Need network + receiver proof]
```

**Legend:** solid arrows = conceptual adversary progression; dashed arrows = evidentiary constraints. The diagram does not claim that any later stages occurred in Week 8.
