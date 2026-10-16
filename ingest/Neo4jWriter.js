import neo4j from 'neo4j-driver';

const DEFAULT_URI = 'bolt://localhost:7687';
const DEFAULT_USER = 'neo4j';
const DEFAULT_PASSWORD = 'neo4j';
const DEFAULT_DATABASE = 'neo4j';

export class Neo4jWriter {
  constructor(options = {}) {
    this.uri = options.uri ?? process.env.NEO4J_URI ?? DEFAULT_URI;
    this.user = options.user ?? process.env.NEO4J_USER ?? DEFAULT_USER;
    this.password =
      options.password ?? process.env.NEO4J_PASSWORD ?? DEFAULT_PASSWORD;
    this.database =
      options.database ?? process.env.NEO4J_DATABASE ?? DEFAULT_DATABASE;
    this.driver = null;
    this.session = null;
  }

  async connect() {
    this.driver = neo4j.driver(
      this.uri,
      neo4j.auth.basic(this.user, this.password),
    );
    await this.driver.verifyConnectivity();
    this.session = this.driver.session({ database: this.database });
  }

  async ensureConstraints() {
    if (!this.session) {
      throw new Error('Neo4jWriter is not connected. Call connect() first.');
    }

    const constraints = [
      { name: 'cve_id',   label: 'CVE' },
      { name: 'cwe_id',   label: 'CWE' },
      { name: 'capec_id', label: 'CAPEC' },
    ];

    for (const { name, label } of constraints) {
      const cypher = `CREATE CONSTRAINT ${name} IF NOT EXISTS FOR (n:${label}) REQUIRE n.id IS UNIQUE`;
      await this.session.run(cypher);
      console.log(`ensured constraint ${name} on :${label}(id)`);
    }
  }

  async close() {
    if (this.session) {
      await this.session.close();
      this.session = null;
    }
    if (this.driver) {
      await this.driver.close();
      this.driver = null;
    }
  }

  async writeNode(entity, record) {
    if (!this.session) {
      throw new Error('Neo4jWriter is not connected. Call connect() first.');
    }

    const subject = String(record.subject);
    const object = String(record.object);
    const predicate = String(record.predicate);
    const relationshipType = toRelationshipType(predicate);

    const cypher = `
      MERGE (s:${toRelationshipType(entity).toUpperCase()} {id: $subject})
      SET s.${toRelationshipType(predicate).toLowerCase()} = $object,
          s.source = $source,
          s.object_type = $object_type,
          s.meta = $meta
    `;

    await this.session.run(cypher, {
      subject,
      object,
      source: record.source ?? null,
      object_type: record.object_type ?? null,
      meta: record.meta ?? null,
    });
  }

  async handleIfRelationship(row) {

    const subject = String(row.subject);
    const object = String(row.object);
    const predicate = String(row.predicate).toLowerCase();
    const relationshipType = toRelationshipType(predicate).toUpperCase();

    if (!predicate.startsWith('child-of') && !predicate.startsWith('parent-of')
      && !predicate.startsWith('related-attack-pattern') && !predicate.startsWith('related-weakness') && !predicate.startsWith('can-precede')) {
      return false;
    }
    
    // Case when child of relationship is in the subject
    let child = subject.split('-')[0];
    let parent = object.split('-')[0];

    let cypher;

    // Case when parent of relationship is in the subject
    if (predicate.startsWith('child-of')) {

      cypher = `
      MERGE (s:${child} {id: $subject})
      MERGE (o:${parent} {id: $object})
      MERGE (s)-[r:CHILD_OF]->(o)`;
      
      await this.session.run(cypher, {
        subject,
        object,
      });

      cypher = `
      MERGE (s:${child} {id: $subject})
      MERGE (o:${parent} {id: $object})
      MERGE (o)-[r:PARENT_OF]->(s)`;

      await this.session.run(cypher, {
        subject,
        object,
      });

    } else {

      cypher = `
      MERGE (s:${child} {id: $subject})
      MERGE (o:${parent} {id: $object})
      MERGE (s)-[r:${relationshipType}]-(o)`;

      await this.session.run(cypher, {
        subject,
        object,
      });
      
    }

    return true;
  }

  async writeEntity(dataset, rows) {
    if (!this.session) {
      throw new Error('Neo4jWriter is not connected. Call connect() first.');
    }
    if (!rows || rows.length === 0) return;

    // const subject = String(rows[0].subject);
    // const label = dataset.name.toUpperCase();
    // const props = buildEntityProperties(rows);

    // await this.session.run(
    //   `MERGE (s:${label} {id: $subject})
    //    SET s += $props`,
    //   { subject, props },
    // );

    for (const row of rows) {
      await this.handleIfRelationship(row);
    }
  }

  async writeCweParentOfEdges(edges, batchSize = 500) {
    if (!this.session) {
      throw new Error('Neo4jWriter is not connected. Call connect() first.');
    }
    if (!edges || edges.length === 0) return 0;

    const cypher = `
      UNWIND $batch AS row
      MERGE (parent:CWE {id: row.parentId})
      MERGE (child:CWE  {id: row.childId})
      MERGE (s)-[r:PARENT_OF]->(o)
      
    `;

    let written = 0;
    for (let i = 0; i < edges.length; i += batchSize) {
      const batch = edges.slice(i, i + batchSize).map((e) => ({
        childId: String(e.childId),
        parentId: String(e.parentId),
      }));
      await this.session.run(cypher, { batch });
      written += batch.length;
    }
    return written;
  }
}

function toRelationshipType(predicate) {
  const cleaned = predicate.replace(/[^A-Za-z0-9_]/g, '_').toUpperCase();
  return cleaned.length > 0 ? cleaned : 'RELATED_TO';
}

function buildEntityProperties(rows) {
  const props = {};

  for (const [index, row] of rows.entries()) {
    const key = `${toRelationshipType(String(row.predicate)).toLowerCase()}_${index}`;
    props[key] = row.object == null ? null : String(row.object);

    const meta = row.meta ?? '';
    if (meta !== '') {
      props[`meta_${key}`] = String(meta);
    }
  }

  return props;
}
