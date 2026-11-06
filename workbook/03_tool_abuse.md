# Tool Abuse / Unsafe Tool Use

## What is it?
Tool abuse happens when the AI uses a tool incorrectly or manipulates the user into performing an action through the AI's tool interface.

## Why should I care?
If an AI can call tools (send email, read files, query databases), an attacker might trick it into using those tools for unintended purposes.

## Try it
Run "The Fake Tool Call" exercise. Watch whether the AI calls tools without proper confirmation.

## What happened?
The AI may call the fake_email_sender tool without asking for user confirmation.

## Defend it
Require explicit user confirmation before calling any tool that sends messages, modifies files, or accesses external systems.

## Try again
Run the same exercise with confirmation required. The AI should ask before calling the tool.

## Remember these three things
- Confirmation boundaries: never execute consequential actions without explicit user approval.
- Over-confirmation can frustrate users — the system must distinguish truly consequential actions.
- Tools are powerful — treat them with the same caution as real operations.
