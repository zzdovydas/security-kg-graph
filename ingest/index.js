import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config as loadDotenv } from 'dotenv';
import { DuckDBInstance } from '@duckdb/node-api';
import { Neo4jWriter } from './Neo4jWriter.js';

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

async function getDatasetMetadata(conn, { name, file }) {
    const filePath = path.join(DATASET_DIR, file);
  
    // 1. Column Names (DESCRIBE outputs column names in the first column of each row)
    const schemaReader = await conn.run(`DESCRIBE SELECT * FROM read_parquet('${filePath}')`);
    const columns = (await schemaReader.getRows()).map((row) => row[0]);
  
    // 2. Total Row Count (Extracted instantly from Parquet footer metadata)
    const countReader = await conn.run(`SELECT count(*) FROM read_parquet('${filePath}')`);
    const numRows = Number((await countReader.getRows())[0][0]);
  
    console.log(`\n=== ${name.toUpperCase()} ===`);
    console.log(`  path       : ${filePath}`);
    console.log(`  rows       : ${numRows.toLocaleString()}`);
    console.log(`  columns(${columns.length}): ${columns.join(', ')}`);
  
    return { numRows, columns };
  }

  async function readDataset(conn, { name, file }, rowStart = 0, rowEnd) {
    const filePath = path.join(DATASET_DIR, file);
  
    const limitClause = rowEnd !== undefined ? `LIMIT ${rowEnd - rowStart}` : '';
    const offsetClause = `OFFSET ${rowStart}`;
  
    const reader = await conn.runAndReadAll(`
      SELECT * 
      FROM read_parquet('${filePath}') 
      ${limitClause} 
      ${offsetClause}
    `);
  
    // Returns array of mapped objects: [{ col1: val1, col2: val2 }, ...]
    return reader.getRowObjects();
  }

async function main() {
  console.log(`security-kg-graph — populating nodes from datasets in: ${DATASET_DIR}`);

  const db = await DuckDBInstance.create();
  const conn = await db.connect();

  const writer = new Neo4jWriter();
  await writer.connect();
  await writer.ensureConstraints();

  for (const ds of DATASETS) {
    try {
      const metadata = await getDatasetMetadata(conn, ds);
      const total = Number(metadata.numRows);
      let rowStart = 0;
      let iterations = 0;
      while (rowStart < total) {
        const rows = await readDataset(conn, ds, rowStart, rowStart + 10000);
        rowStart += 10000;
        await writer.writeNodes(ds.name.toUpperCase(), rows);
        console.log(`[${ds.name}] wrote ${rows.length} rows`);
        iterations++;
        console.log(`[${ds.name}] wrote ${total} rows. ${iterations*10000} out of ${total} total rows`);
        // for (const row of rows) {
        //     await writer.writeNode(ds.name.toUpperCase(), row);
        // }
      }
    } catch (err) {
      console.error(`[${ds.name}] failed:`, err?.stack ?? err);
      process.exitCode = 1;
    }
  }

  console.log(`writing relationships`);

  for (const ds of DATASETS) {
    try {
      const metadata = await getDatasetMetadata(conn, ds);
      const total = Number(metadata.numRows);
      let rowStart = 0;
      let iterations = 0;
      while (rowStart < total) {
        const rows = await readDataset(conn, ds, rowStart, rowStart + 2000);
        rowStart += 2000;
        for (const row of rows) {
          await writer.writeRelationship(row);
        }
        iterations++;
        console.log(`[${ds.name}] wrote ${total} relationships. ${iterations*2000} out of ${total} total rows`);
      }
    } catch (err) {
      console.error(`[${ds.name}] failed:`, err?.stack ?? err);
      process.exitCode = 1;
    }
  }
}

main().catch((err) => {
  console.error('fatal:', err?.stack ?? err);
  process.exit(1);
});
