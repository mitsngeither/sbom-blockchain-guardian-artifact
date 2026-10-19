import type { INestApplication } from '@nestjs/common';
import { json, urlencoded } from 'express';

const DEFAULT_JSON_LIMIT = '5mb';

export function configureApiApp(app: INestApplication): void {
  const jsonLimit = process.env.API_JSON_LIMIT ?? DEFAULT_JSON_LIMIT;

  app.use(json({ limit: jsonLimit }));
  app.use(urlencoded({ extended: true, limit: jsonLimit }));
  app.setGlobalPrefix('api');
}
