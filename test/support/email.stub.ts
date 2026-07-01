// Controllable stand-in for EmailService. INTENT: tests CAPTURE the reset link
// instead of hitting real SMTP. Like: a mailbox we read from directly, no
// postman involved. The running app holds THIS object, so the test can pull the
// last link/url out after a reset request and replay its token at /confirm.
export class EmailStub {
  // Every send is recorded here so tests can assert "was a mail sent?".
  sent: { to: string; resetUrl: string }[] = [];

  // Same signature as the real EmailService.sendPasswordReset.
  // eslint-disable-next-line @typescript-eslint/require-await
  async sendPasswordReset(to: string, resetUrl: string): Promise<void> {
    this.sent.push({ to, resetUrl });
  }

  // Forget everything captured — call between tests.
  reset(): void {
    this.sent = [];
  }

  // The most recent reset URL, or undefined if nothing was sent.
  lastUrl(): string | undefined {
    return this.sent[this.sent.length - 1]?.resetUrl;
  }

  // Pull the raw token out of the last reset URL's ?token= query.
  lastToken(): string | undefined {
    const url = this.lastUrl();
    if (!url) return undefined;
    return new URL(url).searchParams.get('token') ?? undefined;
  }

  // Wait until AT LEAST `count` mails have landed, then return the newest token.
  // WHY: the request endpoint now sends fire-and-forget (off the response path,
  // for constant-time no-enumeration), so the 202 comes back BEFORE the mail is
  // captured here. Tests poll this instead of reading immediately. Like: check
  // the mailbox a few times instead of assuming the letter arrived instantly.
  async waitForToken(count = 1, timeoutMs = 2000): Promise<string> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (this.sent.length >= count) {
        return this.lastToken()!;
      }
      if (Date.now() > deadline) {
        throw new Error(
          `Timed out waiting for ${count} reset mail(s); got ${this.sent.length}`,
        );
      }
      await new Promise((r) => setTimeout(r, 10));
    }
  }
}
