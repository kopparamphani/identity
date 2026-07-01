import {
  Body,
  Controller,
  HttpCode,
  HttpException,
  HttpStatus,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import {
  AccountLockedException,
  AuthService,
  InvalidResetTokenException,
  IssuedTokens,
} from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { GoogleAuthDto } from './dto/google-auth.dto';
import { PasswordResetRequestDto } from './dto/password-reset-request.dto';
import { PasswordResetConfirmDto } from './dto/password-reset-confirm.dto';

// One generic line for reset requests. Same text whether the email exists or
// not -> never leaks who has an account (REQ-ACC-03 locked behavior).
const RESET_REQUEST_MESSAGE =
  'If an account exists, a reset link was sent';

// Cookie name for the opaque refresh token (web clients).
const REFRESH_COOKIE = 'refresh_token';
const REFRESH_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly config: ConfigService,
  ) {}

  // POST /auth/signup -> 201 + TokenResponse, 409 dup, 422 weak/breached.
  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(
    @Body() dto: SignupDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TokenResponseBody> {
    const tokens = await this.auth.signup(dto.email, dto.password, dto.display_name);
    return this.deliver(tokens, res);
  }

  // POST /auth/login -> 200 + TokenResponse, 401 wrong, 429 locked.
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TokenResponseBody> {
    try {
      const tokens = await this.auth.login(dto.email, dto.password);
      return this.deliver(tokens, res);
    } catch (err) {
      // Lockout is a domain signal -> 429 per contract.
      if (err instanceof AccountLockedException) {
        throw new HttpException(err.message, HttpStatus.TOO_MANY_REQUESTS);
      }
      throw err;
    }
  }

  // POST /auth/google -> ID-token flow (REQ-ACC-01/02 Google paths).
  // Status is DYNAMIC: brand-new Google account -> 201, existing/linked -> 200.
  // We set it ourselves on res, so no @HttpCode here. 401 on a bad token.
  // NOTE: not in OpenAPI yet (see report).
  @Post('google')
  async google(
    @Body() dto: GoogleAuthDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TokenResponseBody> {
    const result = await this.auth.googleAuth(dto.id_token);
    res.status(result.created ? HttpStatus.CREATED : HttpStatus.OK);
    return this.deliver(result.tokens, res);
  }

  // POST /auth/logout -> 204. Revoke the session behind the cookie.
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const token = this.readRefreshCookie(req);
    await this.auth.logout(token);
    // Clear the cookie on the client too.
    res.clearCookie(REFRESH_COOKIE, this.cookieOptions(0));
  }

  // POST /auth/refresh -> 200 + new access token. NOT in OpenAPI yet (see report).
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TokenResponseBody> {
    const token = this.readRefreshCookie(req);
    const tokens = await this.auth.refresh(token);
    return this.deliver(tokens, res);
  }

  // POST /auth/password-reset/request -> ALWAYS 202 + generic message.
  // We never reveal whether the email exists. If a local-capable account is
  // there, the service emails a one-time link; otherwise it quietly no-ops.
  // NOTE: not in OpenAPI yet (docs adds it — see report).
  @Post('password-reset/request')
  @HttpCode(HttpStatus.ACCEPTED)
  async passwordResetRequest(
    @Body() dto: PasswordResetRequestDto,
  ): Promise<{ message: string }> {
    await this.auth.requestPasswordReset(dto.email);
    return { message: RESET_REQUEST_MESSAGE };
  }

  // POST /auth/password-reset/confirm -> 200 on success.
  // 400 generic on missing/used/expired token; 422 on weak/breached password.
  // On success: new password set, token spent, ALL sessions revoked.
  // NOTE: not in OpenAPI yet (docs adds it — see report).
  @Post('password-reset/confirm')
  @HttpCode(HttpStatus.OK)
  async passwordResetConfirm(
    @Body() dto: PasswordResetConfirmDto,
  ): Promise<{ message: string }> {
    try {
      await this.auth.confirmPasswordReset(dto.token, dto.new_password);
      return { message: 'Password updated' };
    } catch (err) {
      // Bad/used/expired ticket -> generic 400. Don't say which.
      if (err instanceof InvalidResetTokenException) {
        throw new HttpException(err.message, HttpStatus.BAD_REQUEST);
      }
      throw err; // 422 (weak/breached) bubbles up unchanged.
    }
  }

  // Put the refresh token in an httpOnly Secure cookie; return only the access
  // token in the body (matches the contract's TokenResponse schema).
  private deliver(tokens: IssuedTokens, res: Response): TokenResponseBody {
    res.cookie(
      REFRESH_COOKIE,
      tokens.refresh_token,
      this.cookieOptions(REFRESH_MAX_AGE_MS),
    );
    return {
      access_token: tokens.access_token,
      token_type: tokens.token_type,
      expires_in: tokens.expires_in,
    };
  }

  private readRefreshCookie(req: Request): string | undefined {
    return (req.cookies as Record<string, string> | undefined)?.[REFRESH_COOKIE];
  }

  // Secure off in dev (http localhost), on in prod. SameSite=lax for web flows.
  private cookieOptions(maxAge: number) {
    const isProd = this.config.get<string>('NODE_ENV') === 'production';
    return {
      httpOnly: true,
      secure: isProd,
      sameSite: 'lax' as const,
      path: '/',
      maxAge,
    };
  }
}

// Body shape returned to the client = the locked TokenResponse schema.
interface TokenResponseBody {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
}
