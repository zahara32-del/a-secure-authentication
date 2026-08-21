const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function createDatabase(filename = process.env.DATABASE_PATH || './data/auth.sqlite') {
  const absolute = filename === ':memory:' ? filename : path.resolve(filename);
  if (absolute !== ':memory:') fs.mkdirSync(path.dirname(absolute), { recursive: true });
  const db = new DatabaseSync(absolute);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
  db.exec(schema);
  return db;
}

if (require.main === module) {
  const db = createDatabase();
  db.close();
  console.log('Database initialized.');
}

module.exports = { createDatabase };
