import { request } from './api';
import {
  SecurityToolsResponse,
  SecurityHealthResponse,
  DashboardSummaryResponse,
} from '../types/security';

export async function getSystemHealth(): Promise<{ status: string; version: string; database?: string }> {
  return request<{ status: string; version: string; database?: string }>('/health');
}

export async function getSecurityTools(): Promise<SecurityToolsResponse> {
  return request<SecurityToolsResponse>('/api/v1/security/tools');
}

export async function getSecurityHealth(): Promise<SecurityHealthResponse> {
  return request<SecurityHealthResponse>('/api/v1/security/health');
}

export async function getSecurityDashboard(): Promise<DashboardSummaryResponse> {
  return request<DashboardSummaryResponse>('/api/v1/security/dashboard');
}
