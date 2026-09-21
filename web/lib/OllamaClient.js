const DEFAULT_URL = 'http://localhost:11434';
const DEFAULT_MODEL = 'gemma4:26b';

export class OllamaClient {
  constructor(options = {}) {
    this.url = options.url ?? process.env.OLLAMA_URL ?? DEFAULT_URL;
    this.model = options.model ?? process.env.OLLAMA_MODEL ?? DEFAULT_MODEL;
  }

  async chat(messages, options = {}) {
    const body = {
      model: this.model,
      messages,
      stream: false,
      options: {
        temperature: options.temperature ?? 0.1,
      },
    };
    if (options.think !== undefined) {
      body.think = options.think;
    }

    const response = await fetch(`${this.url}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(`Ollama ${response.status}: ${errorBody}`);
    }

    const data = await response.json();
    return extractThinking(data.message);
  }
}

function extractThinking(message) {
  const rawContent = message?.content ?? '';
  const explicitThinking = message?.thinking ?? '';

  if (explicitThinking) {
    return { content: rawContent, thinking: explicitThinking };
  }

  const inlineMatch = rawContent.match(/^\s*<think>([\s\S]*?)<\/think>\s*/i);
  if (inlineMatch) {
    return {
      content: rawContent.slice(inlineMatch[0].length),
      thinking: inlineMatch[1].trim(),
    };
  }

  return { content: rawContent, thinking: '' };
}
