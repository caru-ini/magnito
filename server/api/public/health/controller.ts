import { cognito } from 'service/cognito';
import { APP_VERSION } from 'service/envValues';
import { prismaClient } from 'service/prismaClient';
import { returnGetError, returnSuccess } from 'service/returnStatus';
import { checkSmtpHealth } from 'service/sendMail';
import { defineController } from './$relay';

const check = async () => ({
  version: APP_VERSION,
  server: 'ok' as const,
  db: await prismaClient.$queryRaw`SELECT CURRENT_TIMESTAMP;`.then(() => 'ok' as const),
  smtp: await checkSmtpHealth().then(() => 'ok' as const),
  cognito: await cognito.health().then(() => 'ok' as const),
});

export default defineController(() => ({
  get: () => check().then(returnSuccess).catch(returnGetError),
}));
