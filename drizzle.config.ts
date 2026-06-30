import 'dotenv/config';
import { defineConfig } from 'drizzle-kit';

// drizzle-kit reads this to generate + apply migrations.
// Schema lives in src/db/schema.ts; migrations land in ./drizzle.
export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    // DATABASE_URL comes from env (.env locally, Sealed Secret in prod).
    url: process.env.DATABASE_URL!,
  },
});
