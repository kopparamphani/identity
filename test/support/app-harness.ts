import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule, TestingModuleBuilder } from '@nestjs/testing';
import cookieParser from 'cookie-parser';
import { sql } from 'drizzle-orm';
import { AppModule } from '../../src/app.module';
import { DRIZZLE, DrizzleDB } from '../../src/db/db.module';

// Let a caller tweak the testing module before it compiles. INTENT: the Google
// e2e needs to swap the real GoogleVerifierService for a stub (no live Google),
// without changing how 1a boots. Pass a function that overrides providers.
type ModuleCustomizer = (builder: TestingModuleBuilder) => TestingModuleBuilder;

// Boot the REAL app the SAME way main.ts does. If we forget cookieParser or the
// 422 ValidationPipe here, refresh/logout cookies and 422 errors would behave
// differently from production — so we mirror main.ts exactly.
export async function bootTestApp(customize?: ModuleCustomizer): Promise<{
  app: INestApplication;
  db: DrizzleDB;
}> {
  let builder = Test.createTestingModule({
    imports: [AppModule],
  });

  // Optional: override providers (e.g. stub the Google verifier) before compile.
  if (customize) {
    builder = customize(builder);
  }

  const moduleRef: TestingModule = await builder.compile();

  const app = moduleRef.createNestApplication();

  // --- mirror of main.ts bootstrap() ---
  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      errorHttpStatusCode: HttpStatus.UNPROCESSABLE_ENTITY,
    }),
  );
  // --------------------------------------

  await app.init();

  const db = app.get<DrizzleDB>(DRIZZLE);
  return { app, db };
}

// Wipe both tables so each test starts clean. CASCADE handles the session FK.
// Like: clear the whiteboard before the next test writes on it.
export async function resetTables(db: DrizzleDB): Promise<void> {
  // Raw SQL truncate is fastest + guarantees zero rows + resets nothing we need.
  await db.execute(sql`TRUNCATE TABLE "session", "account" CASCADE`);
}
