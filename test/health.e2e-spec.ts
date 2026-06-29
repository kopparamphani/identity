import { INestApplication } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';

// Health endpoint tests. Iteration 0 = plumbing only.
// We boot the REAL app (same wiring as production) and poke it over HTTP,
// just like K8s probes would. Proves the pipes connect end to end.
describe('Health endpoints (e2e)', () => {
  let app: INestApplication;

  // Build app once before tests. Test module mirrors the real AppModule
  // so we test the actual wiring, not a fake.
  beforeAll(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  // Shut app down after tests so no dangling handles linger.
  afterAll(async () => {
    await app.close();
  });

  // INTENT: liveness probe says "I am alive".
  // Objective: GET /health/live answers 200 with {status:"ok"}.
  it('GET /health/live -> 200 { status: "ok" }', async () => {
    const res = await request(app.getHttpServer()).get('/health/live');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  // INTENT: readiness probe says "ready for traffic".
  // Objective: GET /health/ready answers 200 with {status:"ready"}.
  it('GET /health/ready -> 200 { status: "ready" }', async () => {
    const res = await request(app.getHttpServer()).get('/health/ready');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ready' });
  });
});
