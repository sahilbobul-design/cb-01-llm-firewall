import { request } from './api';
import { ScanResult, OutputFirewallResult } from '../types/scan';
import { SecurityEventItem } from '../types/security';

export async function executeTextScan(prompt: string, sourceType: string = 'text'): Promise<ScanResult> {
  const result = await request<ScanResult>('/api/v1/scans', {
    method: 'POST',
    body: JSON.stringify({ prompt, source_type: sourceType }),
  });
  return { ...result, original_content: prompt };
}

export async function executeFileScan(file: File | Blob, fileName: string = 'upload.bin'): Promise<ScanResult> {
  const formData = new FormData();
  formData.append('file', file, fileName);

  const result = await request<ScanResult>('/api/v1/scans', {
    method: 'POST',
    body: formData,
  });
  return result;
}

export async function scanOutputFirewall(outputText: string): Promise<OutputFirewallResult> {
  return request<OutputFirewallResult>('/api/v1/scans/output', {
    method: 'POST',
    body: JSON.stringify({ output_text: outputText }),
  });
}

export async function getSecurityEvents(limit: number = 50): Promise<SecurityEventItem[]> {
  return request<SecurityEventItem[]>(`/api/v1/scans/events?limit=${limit}`);
}

export async function getToolResults(limit: number = 50): Promise<any[]> {
  return request<any[]>(`/api/v1/scans/tools-results?limit=${limit}`);
}
