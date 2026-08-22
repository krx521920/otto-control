export interface EdgeReleaseAssuranceReport {
  schemaVersion: 1;
  product: 'otto-edge-gateway';
  releaseCandidate: string;
  checkedAt: string;
  result: 'passed' | 'blocked';
  blockers: string[];
}

export function checkEdgeReleaseAssurance(
  raw: unknown,
  options: { root: string; now?: () => number },
): EdgeReleaseAssuranceReport;
