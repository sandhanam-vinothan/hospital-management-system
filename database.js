require('dotenv').config();

const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not configured');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : { rejectUnauthorized: false }
});

pool.on('error', (error) => {
  console.error('Unexpected PostgreSQL error:', error);
});

async function query(text, params = []) {
  return pool.query(text, params);
}

async function checkDatabase() {
  const result = await pool.query(
    'SELECT NOW() AS server_time, current_database() AS database'
  );

  return result.rows[0];
}

module.exports = {
  pool,
  query,
  checkDatabase
};