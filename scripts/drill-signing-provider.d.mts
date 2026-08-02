export interface SigningProviderDrillInput {
  controlUrl: URL;
  token: string;
  keyId: string;
  expectedLocation: string | null;
  minimumFailovers: number;
}

export interface SigningProviderDrillReport {
  version: 1;
  drill: 'signing_provider';
  keyId: string;
  startedAt: string;
  completedAt: string;
  result: 'passed';
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

export function runSigningProviderDrill(
  input: SigningProviderDrillInput,
): Promise<SigningProviderDrillReport>;
