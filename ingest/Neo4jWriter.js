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

  async writeNodes(entity, records) {
    if (!this.session) {
      throw new Error('Neo4jWriter is not connected. Call connect() first.');
    }
    if (!records || records.length === 0) return;

    const entityLabel = records[0].source.toUpperCase();

    // 1. Group records by predicate, as Cypher cannot parameterize property keys directly
    const batchesByPredicate = {};
    for (const record of records) {
      const predicate = String(record.predicate);
      if (!batchesByPredicate[predicate]) {
        batchesByPredicate[predicate] = [];
      }
      
      batchesByPredicate[predicate].push({
        subject: String(record.subject),
        object: String(record.object),
        source: record.source ?? null,
        object_type: record.object_type ?? null,
        meta: record.meta ?? null,
      });
    }

    console.log(`[${entity}] writing ${Object.keys(batchesByPredicate).length} predicates`);
    // 2. Execute one UNWIND query per predicate group
    for (const [predicate, batch] of Object.entries(batchesByPredicate)) {
      const propertyName = toRelationshipType(predicate).toLowerCase();

      const cypher = `
        UNWIND $batch AS row
        MERGE (s:${entityLabel} {id: row.subject})
        SET s.${propertyName} = row.object,
            s.${propertyName}_source = row.source,
            s.${propertyName}_object_type = row.object_type,
            s.${propertyName}_meta = row.meta
      `;
      console.log(`Successfully [${entity}] wrote ${Object.keys(batchesByPredicate).length} predicates`);

      await this.session.run(cypher, { batch });
    }
  }

  async writeRelationship(record) {
    if (!this.session) {
      throw new Error('Neo4jWriter is not connected. Call connect() first.');
    }

    const subject = String(record.subject);
    const object = String(record.object);
    const predicate = String(record.predicate).toLowerCase();
    const relationshipType = toRelationshipType(predicate).toUpperCase();

    if (!predicate.startsWith('child-of') && !predicate.startsWith('parent-of') && !predicate.startsWith('related-attack-pattern')
    && !predicate.startsWith('related-weakness')) {
      return false;
    }
    
    // Case when child of relationship is in the subject
    let child = subject.split('-')[0];
    let parent = object.split('-')[0];

    let cypher = `
      MERGE (s:${child} {id: $subject})
      MERGE (o:${parent} {id: $object})
      MERGE (s)-[r:CHILD_OF]->(o)
    `;

    // Case when parent of relationship is in the subject
    if (predicate.startsWith('parent-of')) {
      cypher = `
      MERGE (s:${parent} {id: $subject})
      MERGE (o:${child} {id: $object})
      MERGE (s)-[r:PARENT_OF]->(o)
    `;
    } else {

      cypher = `
      MERGE (s:${child} {id: $subject})
      MERGE (o:${parent} {id: $object})
      MERGE (s)-[r:${relationshipType}]->(o)
    `;
    }

    await this.session.run(cypher, {
      subject,
      object,
    });

    return true;
  }
}

function toRelationshipType(predicate) {
  const cleaned = predicate.replace(/[^A-Za-z0-9_]/g, '_').toUpperCase();
  return cleaned.length > 0 ? cleaned : 'RELATED_TO';
}
