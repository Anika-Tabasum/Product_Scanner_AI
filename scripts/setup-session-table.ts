import { Pool } from '@neondatabase/serverless';
import dotenv from 'dotenv';

dotenv.config();

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL environment variable is required');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function setupSessionTable() {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Create the user_sessions table if it doesn't exist
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        "sid" varchar NOT NULL,
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "user_sessions_pkey" PRIMARY KEY ("sid")
      )
    `);
    
    // Create index for faster lookups
    await client.query(`
      CREATE INDEX IF NOT EXISTS "IDX_user_sessions_expire" 
      ON user_sessions ("expire")
    `);
    
    await client.query('COMMIT');
    console.log('Session table and index created successfully');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error setting up session table:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

setupSessionTable()
  .then(() => console.log('Setup completed'))
  .catch((error) => {
    console.error('Setup failed:', error);
    process.exit(1);
  });
