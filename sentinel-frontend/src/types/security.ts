export type ToolStatus = 'ACTIVE' | 'DISABLED' | 'UNAVAILABLE' | 'ERROR';

export interface ToolHealthInfo {
  tool: string;
  status: ToolStatus;
  installed?: boolean;
  enabled?: boolean;
  binary?: string;
  engine?: string;
  note?: string;
}

export interface SecurityToolsResponse {
  yara: { installed: boolean; enabled: boolean };
  clamav: { installed: boolean; enabled: boolean };
  tshark: { installed: boolean; enabled: boolean };
}

export interface SecurityHealthResponse {
  gateway_status: 'ONLINE' | 'OFFLINE';
  linux_security_enabled: boolean;
  tools: {
    yara?: ToolHealthInfo;
    clamav?: ToolHealthInfo;
    tshark?: ToolHealthInfo;
    jev?: ToolHealthInfo;
  };
  timestamp?: string;
}

export interface DashboardSummaryResponse {
  security_tools: {
    YARA: string;
    ClamAV: string;
    tshark: string;
    Jev: string;
  };
  tools_detailed?: SecurityToolsResponse;
  latest_scan?: {
    scan_id: string | null;
    available: boolean;
    recent_events_count: number;
    recent_tools_scanned_count: number;
  };
}

export interface SecurityEventItem {
  id: string;
  scan_id: string;
  layer: string;
  event_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  created_at: string;
}
