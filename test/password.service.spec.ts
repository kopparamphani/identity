import { PasswordService } from '../src/auth/password.service';
import { BREACHED_FALLBACK } from '../src/auth/breached-passwords';

// Unit tests for the breach check. Pure logic — no DB, no app boot.
// The whole point here is the FAIL-OPEN rule (ADR-0025): if HIBP is down, we
// must not lock everyone out, but we must still block the worst known passwords
// using the bundled fallback list.
describe('PasswordService breach check (fail-open)', () => {
  let service: PasswordService;

  beforeEach(() => {
    service = new PasswordService();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // INTENT: HIBP unreachable + password NOT on bundled list -> allowed (fail-open).
  // We must not block a perfectly good password just because the network died.
  it('HIBP throws + password not on fallback -> policy ok (does NOT block)', async () => {
    jest.spyOn(global, 'fetch').mockRejectedValue(new Error('ECONNREFUSED'));

    // 8+ chars, definitely not in the bundled list.
    const result = await service.checkPolicy('Zx9-quokka-trot');

    expect(result).toEqual({ ok: true });
  });

  // INTENT: HIBP unreachable + password IS on bundled list -> still blocked.
  // Fail-open does not mean fail-blind: the worst passwords stay banned offline.
  it('HIBP throws + password on fallback -> blocked as breached', async () => {
    jest.spyOn(global, 'fetch').mockRejectedValue(new Error('timeout'));

    // 'password' lives in BREACHED_FALLBACK and is 8 chars (passes length gate).
    expect(BREACHED_FALLBACK.has('password')).toBe(true);
    const result = await service.checkPolicy('password');

    expect(result).toEqual({ ok: false, reason: 'breached' });
  });

  // INTENT: a fetch that times out (AbortError style) is treated the same as
  // any other failure -> fall back, don't crash.
  it('HIBP times out -> falls back, non-listed password still allowed', async () => {
    jest
      .spyOn(global, 'fetch')
      .mockRejectedValue(new DOMException('aborted', 'AbortError'));

    const result = await service.checkPolicy('Another-Good-1');
    expect(result).toEqual({ ok: true });
  });

  // INTENT: length gate runs BEFORE any network call. Too-short never reaches HIBP.
  it('too-short password -> too_short and never calls HIBP', async () => {
    const fetchSpy = jest
      .spyOn(global, 'fetch')
      .mockRejectedValue(new Error('should not be called'));

    const result = await service.checkPolicy('short7!'); // 7 chars

    expect(result).toEqual({ ok: false, reason: 'too_short' });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
