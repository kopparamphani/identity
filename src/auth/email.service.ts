import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

// EmailService = how identity talks to the outside world by mail.
// INTENT: keep it small + SWAPPABLE. Tests inject a fake that just captures the
// link (no real SMTP). Local dev points SMTP at Mailpit (localhost:1025), a
// catch-all inbox. PROD SMTP host/credentials are deploy-time config/secret
// (Sealed Secrets, ADR-0018) — never hardcoded here.
@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);

  // One reusable transport built from env. Lazy so a missing SMTP host doesn't
  // crash boot for code paths that never send (e.g. Google-only flows).
  private transport?: nodemailer.Transporter;

  constructor(private readonly config: ConfigService) {}

  // Send the forgotten-password reset link to the user's inbox.
  // resetUrl already carries the RAW one-time token in its query string.
  async sendPasswordReset(to: string, resetUrl: string): Promise<void> {
    const from = this.config.get<string>('SMTP_FROM') ?? 'no-reply@localhost';

    // Plain + simple HTML. Keep copy minimal; this is identity, not marketing.
    const text =
      `We got a request to reset your password.\n\n` +
      `Open this link to set a new one (expires in 1 hour, one-time use):\n` +
      `${resetUrl}\n\n` +
      `If you didn't ask for this, ignore this email — nothing changed.`;
    const html =
      `<p>We got a request to reset your password.</p>` +
      `<p>Open this link to set a new one (expires in 1 hour, one-time use):</p>` +
      `<p><a href="${resetUrl}">${resetUrl}</a></p>` +
      `<p>If you didn't ask for this, ignore this email — nothing changed.</p>`;

    await this.getTransport().sendMail({
      from,
      to,
      subject: 'Reset your password',
      text,
      html,
    });
  }

  // Build the SMTP transport once. Fail loud if host missing — no silent drop.
  private getTransport(): nodemailer.Transporter {
    if (this.transport) {
      return this.transport;
    }
    const host = this.config.getOrThrow<string>('SMTP_HOST');
    const port = Number(this.config.get<string>('SMTP_PORT') ?? '1025');
    // Local Mailpit speaks plain SMTP (no TLS, no auth). Prod transport config
    // (secure + auth) comes from env/secrets at deploy time.
    this.transport = nodemailer.createTransport({
      host,
      port,
      secure: false,
    });
    return this.transport;
  }
}
