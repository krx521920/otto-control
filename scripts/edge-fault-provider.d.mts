import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Server } from 'node:https';

export type EdgeFaultScenario = 'success' | 'timeout' | 'slow_stream' | '429' | '500' | '503';

export interface EdgeFaultProviderOptions {
  host: string;
  port: number;
  certificateFile: string;
  privateKeyFile: string;
  secret: string;
  timeoutDelayMs: number;
  slowStreamDelayMs: number;
}

export function edgeFaultScenario(value: unknown): EdgeFaultScenario | null;
export function createEdgeFaultProviderHandler(input: EdgeFaultProviderOptions): (
  request: IncomingMessage,
  response: ServerResponse,
) => Promise<void>;
export function startEdgeFaultProvider(input: EdgeFaultProviderOptions): Server;
