# Agent-to-Agent Manipulation / Delegated Authority

## What is it?
Agent-to-agent manipulation happens when one AI agent tricks another into performing unintended actions by impersonating a trusted entity. Delegated authority risk happens when an AI agent is given permissions it doesn't need.

## Why should I care?
As AI agents become more autonomous and communicate with each other, one compromised or malicious agent can manipulate others. Over-privileged agents can cause more damage if compromised.

## Try it
Run "The Impersonator" and "The Over-Privileged Agent" exercises.

## What happened?
Agent A followed instructions from Agent B without verifying identity. The over-privileged agent had permissions beyond what the task required.

## Defend it
Verify agent identity through cryptographic signatures or trusted channels. Restrict the AI's permissions to only what the task requires.

## Try again
Run the same scenarios with identity verification and permission scoping in place.

## Remember these three things
- Trust must be established through verifiable credentials, not claimed identity.
- Principle of least privilege: give the AI only the permissions it needs.
- Agent communication boundaries are as important as human-AI boundaries.
