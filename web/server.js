import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config as loadDotenv } from 'dotenv';
import express from 'express';
import { OllamaClient } from './lib/OllamaClient.js';
import { Neo4jReader } from './lib/Neo4jReader.js';
import { GraphRAG } from './lib/GraphRAG.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

loadDotenv({ path: path.join(__dirname, '..', '.env') });

const PORT = Number.parseInt(process.env.WEB_PORT ?? '3000', 10);
const PUBLIC_DIR = path.join(__dirname, 'public');

async function main() {
  const ollama = new OllamaClient();
  const reader = new Neo4jReader();
  await reader.connect();

  const rag = new GraphRAG({ ollama, neo4j: reader });

  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(express.static(PUBLIC_DIR));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, model: ollama.model, neo4j: reader.uri });
  });

  app.post('/api/ask', async (req, res) => {
    const question = String(req.body?.question ?? '').trim();
    if (!question) {
      res.status(400).json({ error: 'question is required' });
      return;
    }
    try {
      const result = await rag.ask(question);
      res.json(result);
    } catch (err) {
      console.error('ask failed:', err?.stack ?? err);
      res.status(500).json({ error: err?.message ?? 'internal error' });
    }
  });

  const server = app.listen(PORT, () => {
    console.log(`security-kg-graph web listening on http://localhost:${PORT}`);
    console.log(`  neo4j : ${reader.uri}`);
    console.log(`  ollama: ${ollama.url} (${ollama.model})`);
  });

  const shutdown = async (signal) => {
    console.log(`\nreceived ${signal}, shutting down`);
    server.close();
    await reader.close();
    process.exit(0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error('fatal:', err?.stack ?? err);
  process.exit(1);
});
