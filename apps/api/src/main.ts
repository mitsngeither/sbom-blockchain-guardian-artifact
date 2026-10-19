import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configureApiApp } from './config/configure-api-app';
import { loadApiEnv } from './config/load-api-env';

loadApiEnv();

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bodyParser: false });
  configureApiApp(app);

  await app.listen(process.env.BE_PORT ?? 5006);
}
bootstrap();