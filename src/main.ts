import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

// App entry point. Boot Nest, then start listening.
async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);

  // Port comes from env so K8s/Docker can set it. Default 3000 for local runs.
  const port = Number(process.env.PORT) || 3000;

  // Bind to 0.0.0.0 not localhost — inside a container we must accept traffic
  // from outside the container, otherwise probes/requests can't reach us.
  await app.listen(port, '0.0.0.0');
}

bootstrap();
