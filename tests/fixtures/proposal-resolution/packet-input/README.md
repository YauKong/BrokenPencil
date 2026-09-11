# Proposal Resolution Packet Fixture Boundary

Packet tests construct their report, decision, rewrite, semantic-review, and
code-identity bytes inside a temporary directory. This committed marker fixes
the fixture namespace without storing any real proposal, snapshot, decision
note, or rewritten body.

The miniature fixture conserves all five decision states and two accepted
record decisions. The current 225-item count vector remains a frozen design
input; real Agent Memory artifacts are outside repository tests.
