import neo4j from 'neo4j-driver';

const DEFAULT_URI = 'bolt://localhost:7687';
const DEFAULT_USER = 'neo4j';
const DEFAULT_PASSWORD = 'neo4j';
const DEFAULT_DATABASE = 'neo4j';

export class Neo4jReader {
  constructor(options = {}) {
    this.uri = options.uri ?? process.env.NEO4J_URI ?? DEFAULT_URI;
    this.user = options.user ?? process.env.NEO4J_USER ?? DEFAULT_USER;
    this.password =
      options.password ?? process.env.NEO4J_PASSWORD ?? DEFAULT_PASSWORD;
    this.database =
      options.database ?? process.env.NEO4J_DATABASE ?? DEFAULT_DATABASE;
    this.driver = null;
  }

  async connect() {
    this.driver = neo4j.driver(
      this.uri,
      neo4j.auth.basic(this.user, this.password),
    );
    await this.driver.verifyConnectivity();
  }

  async close() {
    if (this.driver) {
      await this.driver.close();
      this.driver = null;
    }
  }

  async run(cypher, params = {}) {
    const session = this.driver.session({
      database: this.database,
      defaultAccessMode: neo4j.session.READ,
    });
    try {
      const result = await session.run(cypher, params);
      return result.records.map((record) => {
        const row = {};
        for (const key of record.keys) {
          row[key] = normalize(record.get(key));
        }
        return row;
      });
    } finally {
      await session.close();
    }
  }
}

function normalize(value) {
  if (value === null || value === undefined) return null;
  if (neo4j.isInt(value)) return value.toNumber();
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === 'object' && value.properties) {
    return {
      labels: value.labels ?? undefined,
      type: value.type ?? undefined,
      properties: normalize(value.properties),
    };
  }
  if (typeof value === 'object') {
    const obj = {};
    for (const [k, v] of Object.entries(value)) {
      obj[k] = normalize(v);
    }
    return obj;
  }
  return value;
}
