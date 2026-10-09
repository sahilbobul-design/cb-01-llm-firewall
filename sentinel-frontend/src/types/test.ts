import { ScanResult } from './scan';

export type PipelineStageStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'COMPLETED'
  | 'DETECTED'
  | 'BLOCKED'
  | 'FAILED'
  | 'UNAVAILABLE';

export interface PipelineStageNode {
  id: string;
  name: string;
  description: string;
  status: PipelineStageStatus;
  evidence?: string;
  weight?: string;
}

export interface TestCaseItem {
  id: string;
  title: string;
  description: string;
  category: 'INJECTION' | 'CREDENTIAL' | 'PII' | 'FILE' | 'MALWARE' | 'BENIGN';
  input: string;
  sourceType: 'text' | 'email' | 'webpage' | 'pdf';
  fileData?: Blob;
  fileName?: string;
  expectedDecision: 'SAFE' | 'SUSPICIOUS' | 'BLOCKED';
  actualDecision?: 'SAFE' | 'SUSPICIOUS' | 'BLOCKED';
  status: 'PENDING' | 'RUNNING' | 'PASS' | 'FAIL' | 'UNAVAILABLE';
  evidence?: string;
  scanResult?: ScanResult;
}

export interface TestSummaryStats {
  total: number;
  passed: number;
  failed: number;
  unavailable: number;
  passRate: number;
}
