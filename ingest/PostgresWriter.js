import pg from 'pg';

const DEFAULT_HOST = 'localhost';
const DEFAULT_PORT = 5432;
const DEFAULT_USER = 'postgres';
const DEFAULT_PASSWORD = 'postgres';
const DEFAULT_DATABASE = 'postgres';

export class PostgresWriter {
  constructor(options = {}) {
    this.host = options.host ?? process.env.POSTGRES_HOST ?? DEFAULT_HOST;
    this.port = Number(options.port ?? process.env.POSTGRES_PORT ?? DEFAULT_PORT);
    this.user = options.user ?? process.env.POSTGRES_USER ?? DEFAULT_USER;
    this.password =
      options.password ?? process.env.POSTGRES_PASSWORD ?? DEFAULT_PASSWORD;
    this.database =
      options.database ?? process.env.POSTGRES_DB ?? DEFAULT_DATABASE;
    this.client = null;
  }

  async connect() {
    this.client = new pg.Client({
      host: this.host,
      port: this.port,
      user: this.user,
      password: this.password,
      database: this.database,
    });
    await this.client.connect();
    const result = await this.client.query('SELECT current_database() AS database, current_user AS user');
    const row = result.rows[0];
    console.log(`connected to postgres ${this.host}:${this.port}/${row.database} as ${row.user}`);
  }

  async close() {
    if (this.client) {
      await this.client.end();
      this.client = null;
    }
  }

  async query(text, params) {
    if (!this.client) {
      throw new Error('PostgresWriter is not connected. Call connect() first.');
    }
    return this.client.query(text, params);
  }

  async writeBatch(table, rows) {
    if (!rows || rows.length === 0) return;

    const subjects = [];
    const predicates = [];
    const objects = [];
    const sources = [];
    const objectTypes = [];
    const metas = [];

    for (const row of rows) {
      subjects.push(row.subject ?? null);
      predicates.push(row.predicate ?? null);
      objects.push(row.object ?? null);
      sources.push(row.source ?? null);
      objectTypes.push(row.object_type ?? null);
      metas.push(row.meta ?? null);
    }

    await this.query(
      `INSERT INTO ${quoteIdent(table)}
        (subject, predicate, object, source, object_type, meta)
       SELECT * FROM UNNEST(
         $1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[]
       )`,
      [subjects, predicates, objects, sources, objectTypes, metas],
    );
  }
}

function quoteIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}
