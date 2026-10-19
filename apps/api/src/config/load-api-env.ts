import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { config } from 'dotenv';

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

export function apiEnvPaths(startDir = process.cwd()): string[] {
  return unique([
    resolve(startDir, '.env'),
    resolve(startDir, '../../.env'),
    resolve(__dirname, '../../../.env'),
    resolve(__dirname, '../../../../.env'),
  ]);
}

export function loadApiEnv(startDir = process.cwd()): string[] {
  const loaded: string[] = [];

  for (const path of apiEnvPaths(startDir)) {
    if (!existsSync(path)) continue;

    const result = config({ path, override: false, quiet: true });
    if (!result.error) loaded.push(path);
  }

  return loaded;
}
