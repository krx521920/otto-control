import type { FastifyInstance, FastifyReply } from 'fastify';

import {
  OPERATOR_CONSOLE_APPROVAL_CSS,
  OPERATOR_CONSOLE_APPROVAL_JS,
} from '../modules/operator-console/approval-assets.js';
import {
  OPERATOR_CONSOLE_CSS,
  OPERATOR_CONSOLE_HTML,
  OPERATOR_CONSOLE_JS,
} from '../modules/operator-console/assets.js';
import {
  OPERATOR_CONSOLE_WRITE_CSS,
  OPERATOR_CONSOLE_WRITE_JS,
} from '../modules/operator-console/write-assets.js';
import {
  OPERATOR_CONSOLE_LICENSE_CSS,
  OPERATOR_CONSOLE_LICENSE_JS,
} from '../modules/operator-console/license-lifecycle-assets.js';

const HTML_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

function hardened(reply: FastifyReply): FastifyReply {
  return reply
    .header('cache-control', 'no-store')
    .header('content-security-policy', HTML_CSP)
    .header('cross-origin-opener-policy', 'same-origin')
    .header('cross-origin-resource-policy', 'same-origin');
}

export async function registerOperatorConsoleRoutes(app: FastifyInstance): Promise<void> {
  const page = async (_request: unknown, reply: FastifyReply) => hardened(reply)
    .type('text/html; charset=utf-8')
    .send(OPERATOR_CONSOLE_HTML);

  app.get('/admin', page);
  app.get('/admin/', page);
  app.get('/admin/assets/app.css', async (_request, reply) => hardened(reply)
    .type('text/css; charset=utf-8')
    .send(`${OPERATOR_CONSOLE_CSS}\n${OPERATOR_CONSOLE_WRITE_CSS}\n${OPERATOR_CONSOLE_LICENSE_CSS}\n${OPERATOR_CONSOLE_APPROVAL_CSS}`));
  app.get('/admin/assets/app.js', async (_request, reply) => hardened(reply)
    .type('text/javascript; charset=utf-8')
    .send(`${OPERATOR_CONSOLE_JS}\n${OPERATOR_CONSOLE_WRITE_JS}\n${OPERATOR_CONSOLE_LICENSE_JS}\n${OPERATOR_CONSOLE_APPROVAL_JS}`));
}
