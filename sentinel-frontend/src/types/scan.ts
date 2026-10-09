export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'BLOCKED';

export interface ScanThreats {
  prompt_injection: boolean;
  system_attack: boolean;
  secret_detected: boolean;
  pii_detected: boolean;
  suspicious_ip: boolean;
  suspicious_url: boolean;
  yara_detected: boolean;
  clamav_infected: boolean;
}

export interface FileSecurityInfo {
  file_hash: string | null;
  file_size: number | null;
  mime_type: string | null;
  yara: string;
  clamav: string;
}

export interface ToolResultDetail {
  tool: string;
  status: string;
  detected?: boolean;
  infected?: boolean;
  matches?: string[];
  signature?: string;
  execution_time_ms?: number;
  error?: string;
}

export interface ScanResult {
  scan_id: string;
  timestamp: string;
  source_type: string;
  risk_score: number;
  status: RiskLevel;
  reasons: string[];
  threat_breakdown: Record<string, number>;
  threats: ScanThreats;
  file_security: FileSecurityInfo;
  tool_results: Record<string, ToolResultDetail>;
  sanitized_content: string;
  redactions_count: number;
  original_content?: string;
}

export interface OutputFirewallResult {
  is_sensitive: boolean;
  action: 'ALLOW' | 'REDACT_AND_ALLOW' | 'BLOCK';
  secrets_detected: boolean;
  pii_detected: boolean;
  system_prompt_leakage: boolean;
  redactions_count: number;
  safe_output: string;
}

export interface DatasetItem {
  id: string;
  name: string;
  source: string;
  description: string;
  created_at: string;
  record_count: number;
}

export interface RecordItem {
  id: string;
  dataset_id: string;
  source_type: string;
  content: string;
  label: string;
  attack_type: string | null;
  file_name: string | null;
  created_at: string;
}
