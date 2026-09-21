const SCHEMA_DESCRIPTION = `
Node labels:
  (:CVE   { id: string, name?, description?, ... })
  (:CWE   { id: string, name?, description?, abstraction?, status?, ... })
  (:CAPEC { id: string, name?, description?, abstraction?, status?, ... })

Ids follow the format 'CVE-YYYY-NNNN', 'CWE-<number>', 'CAPEC-<number>'.
Node properties are lowercase, snake_cased versions of source predicates
(for example: name, description, abstraction, status, assigner, date_published,
child_of, parent_of, peer_of, consequence_scope, consequence_impact,
introduction_phase, related_attack_pattern, related_weakness).

Relationship types you may see:
  (:CWE)-[:CHILD_OF]->(:CWE)
  (:CAPEC)-[:RELATED_ATTACK_PATTERN]->(:CAPEC)
  (:CVE)-[:RELATED_WEAKNESS]->(:CWE)
`;

const CYPHER_SYSTEM = `You are a Cypher expert working with a security knowledge graph.
Given a natural-language question, output exactly one read-only Cypher query that answers it.
Rules:
- Output ONLY the Cypher query. No prose. No markdown fences. No comments.
- Never use CREATE, MERGE, DELETE, REMOVE, SET, DROP, LOAD, CALL apoc.
- Always end with RETURN.
- Add LIMIT 25 at the end unless the question clearly needs a scalar aggregate.
- Prefer matching on 'id' when the question mentions a specific CVE/CWE/CAPEC identifier.

Schema:
${SCHEMA_DESCRIPTION}`;

const ANSWER_SYSTEM = `You are a security analyst. Given a user's question, the Cypher query that was run, and the JSON result rows, answer the question in plain English using only the data provided. If the result is empty, say so and briefly suggest why the query might have returned nothing.`;

const FORBIDDEN = /\b(create|merge|delete|remove|set|drop|load\s+csv|call\s+dbms|call\s+apoc|foreach)\b/i;

export class GraphRAG {
  constructor({ ollama, neo4j: neo4jReader }) {
    this.ollama = ollama;
    this.neo4j = neo4jReader;
  }

  async ask(question) {
    const cypherStep = await this.generateCypher(question);
    this.assertReadOnly(cypherStep.cypher);
    const results = await this.neo4j.run(cypherStep.cypher);
    const answerStep = await this.generateAnswer(question, cypherStep.cypher, results);
    return {
      question,
      cypher: cypherStep.cypher,
      results,
      answer: answerStep.answer,
      cypherThinking: cypherStep.thinking,
      answerThinking: answerStep.thinking,
    };
  }

  async generateCypher(question) {
    const { content, thinking } = await this.ollama.chat(
      [
        { role: 'system', content: CYPHER_SYSTEM },
        { role: 'user', content: question },
      ],
      { think: true },
    );
    return {
      cypher: stripFence(content).trim(),
      thinking,
    };
  }

  async generateAnswer(question, cypher, results) {
    const { content, thinking } = await this.ollama.chat(
      [
        { role: 'system', content: ANSWER_SYSTEM },
        {
          role: 'user',
          content:
            `Question: ${question}\n\n` +
            `Cypher:\n${cypher}\n\n` +
            `Results (JSON, up to 25 rows):\n${JSON.stringify(results, null, 2)}`,
        },
      ],
      { think: true },
    );
    return {
      answer: content.trim(),
      thinking,
    };
  }

  assertReadOnly(cypher) {
    if (FORBIDDEN.test(cypher)) {
      throw new Error(`Refusing to run non-read-only Cypher:\n${cypher}`);
    }
  }
}

function stripFence(text) {
  const fenced = text.match(/```(?:\w+)?\s*([\s\S]*?)```/);
  if (fenced) return fenced[1];
  return text;
}
