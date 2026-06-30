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
import { AccountLockedException, AuthService, IssuedTokens } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';

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
