# RAG/Retrieval Poisoning

## What is it?
RAG poisoning injects malicious or misleading content into the documents an AI retrieves. When the AI answers based on retrieved content, it gives wrong or harmful answers.

## Why should I care?
Many AI systems use retrieval to improve answers. If retrieved content is poisoned, the AI's answers become unreliable.

## Try it
Run "The Fake Source" exercise. Ask the AI about company policy based on the knowledge base.

## What happened?
The AI repeated a suspicious claim from the retrieved document as if it were true company policy.

## Defend it
Verify retrieved information against trusted sources. Flag suspicious or unusual claims for user review.

## Try again
Run the same question with source verification enabled. The AI should flag the suspicious content.

## Remember these three things
- Don't trust retrieved content blindly.
- Cross-check with authoritative sources.
- The AI's confidence doesn't mean the information is correct.
