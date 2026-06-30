import { HttpStatus, ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

// App entry point. Boot Nest, then start listening.
async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);

  // Read the refresh-token cookie on logout/refresh.
  app.use(cookieParser());

  // Global input gate: strip unknown fields, coerce types, fail bad DTOs.
  // Contract maps bad email (and weak password) to 422, not 400 — so make
  // validation failures return 422 to honor the OpenAPI contract.
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      errorHttpStatusCode: HttpStatus.UNPROCESSABLE_ENTITY,
    }),
  );

  // Port comes from env so K8s/Docker can set it. Default 3000 for local runs.
  const port = Number(process.env.PORT) || 3000;

  // Bind to 0.0.0.0 not localhost — inside a container we must accept traffic
  // from outside the container, otherwise probes/requests can't reach us.
  await app.listen(port, '0.0.0.0');
}

bootstrap();
