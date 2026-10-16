import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config as loadDotenv } from 'dotenv';
import { DuckDBInstance } from '@duckdb/node-api';
import { Neo4jWriter } from './Neo4jWriter.js';
import { PostgresWriter } from './PostgresWriter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

loadDotenv({ path: path.join(__dirname, '..', '.env') });

const DATASET_DIR = process.env.DATASET_DIR
  ? path.resolve(process.env.DATASET_DIR)
  : path.join(__dirname, 'dataset');

const DATASETS = [
  { name: 'cwe', file: 'cwe.parquet' },
  { name: 'capec', file: 'capec.parquet' },
  { name: 'cve', file: 'cve.parquet' },
];

  async function getSubjects(postgres, dataset) {
    const result = await postgres.query(
      `SELECT DISTINCT subject FROM ${quoteIdent(dataset.name)}`,
    );
    return result.rows.map((row) => row.subject);
  }

  async function readSubject(postgres, dataset, subject) {
    const result = await postgres.query(
      `SELECT * FROM ${quoteIdent(dataset.name)} WHERE subject = $1`,
      [subject],
    );
    return result.rows;
  }

  function quoteIdent(name) {
    return `"${String(name).replace(/"/g, '""')}"`;
  }

  function renderProgress(label, current, total) {
    const width = 20;
    const ratio = total === 0 ? 1 : current / total;
    const filled = Math.round(width * ratio);
    const bar = '#'.repeat(filled) + '-'.repeat(width - filled);
    const percent = Math.round(ratio * 100);
    process.stdout.write(
      `\r${label} [${bar}] ${current}/${total} ${percent}%`,
    );
    if (current >= total) process.stdout.write('\n');
  }

  const sqlString = (value) => `'${String(value).replace(/'/g, "''")}'`;
  const BATCH_SIZE = Number.parseInt(process.env.POSTGRES_BATCH_SIZE ?? '5000', 10);

  async function countParquetRows(conn, filePath) {
    const result = await conn.runAndReadAll(
      `SELECT count(*) AS n FROM read_parquet(${sqlString(filePath)})`,
    );
    return Number(result.getRowObjectsJS()[0].n);
  }

  async function readParquetBatch(conn, filePath, rowStart, rowEnd) {
    const result = await conn.runAndReadAll(`
      SELECT subject, predicate, object, source, object_type, meta
      FROM read_parquet(${sqlString(filePath)}, file_row_number = true)
      WHERE file_row_number >= ${rowStart}
        AND file_row_number < ${rowEnd}
    `);
    return result.getRowObjectsJS();
  }

  async function importParquetToPostgres(conn, postgres) {
    for (const dataset of DATASETS) {
      const filePath = path.join(DATASET_DIR, dataset.file);
      if (!fs.existsSync(filePath)) {
        console.warn(`[script] ${dataset.file} not found — skipping`);
        continue;
      }

      const table = quoteIdent(dataset.name);
      const indexName = quoteIdent(`${dataset.name}_subject_idx`);

      await postgres.query(`DROP TABLE IF EXISTS ${table}`);
      await postgres.query(`
        CREATE TABLE ${table} (
          subject TEXT,
          predicate TEXT,
          object TEXT,
          source TEXT,
          object_type TEXT,
          meta TEXT
        )
      `);
      await postgres.query(`CREATE INDEX ${indexName} ON ${table} (subject)`);
      console.log(`[script/postgres] created table ${dataset.name} with index on subject`);

      const started = performance.now();
      const total = await countParquetRows(conn, filePath);
      let written = 0;

      for (let rowStart = 0; rowStart < total; rowStart += BATCH_SIZE) {
        const rowEnd = Math.min(rowStart + BATCH_SIZE, total);
        const rows = await readParquetBatch(conn, filePath, rowStart, rowEnd);
        await postgres.writeBatch(dataset.name, rows);
        written += rows.length;
        console.log(
          `[script/postgres] ${dataset.name}: wrote ${written.toLocaleString()} / ${total.toLocaleString()} rows`,
        );
      }

      const seconds = ((performance.now() - started) / 1000).toFixed(1);
      console.log(`[script/postgres] ${dataset.name}: ${written.toLocaleString()} rows in ${seconds}s`);
    }
  }

async function main() {
  console.log(`security-kg-graph — populating nodes from datasets in: ${DATASET_DIR}`);

  const db = await DuckDBInstance.create();
  const conn = await db.connect();

  const postgres = new PostgresWriter();
  await postgres.connect();

  try {
    // await importParquetToPostgres(conn, postgres);

    const writer = new Neo4jWriter();
    await writer.connect();
    try {
      for (const dataset of DATASETS) {
        try {
          const subjects = await getSubjects(postgres, dataset);
          let done = 0;
          renderProgress(dataset.name, done, subjects.length);

          for (const subject of subjects) {
            const rows = await readSubject(postgres, dataset, subject);
            await writer.writeEntity(dataset, rows);
            done++;
            renderProgress(dataset.name, done, subjects.length);
          }
        } catch (err) {
          console.error(`[${dataset.name}] failed:`, err?.stack ?? err);
          process.exitCode = 1;
        }
      }
    } finally {
      await writer.close();
    }
  } finally {
    await postgres.close();
  }
}

main().catch((err) => {
  console.error('fatal:', err?.stack ?? err);
  process.exit(1);
});
