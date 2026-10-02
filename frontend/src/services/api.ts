import {
  TokenResponse,
  DashboardSummary,
  PaginatedEvents,
  EventDetail,
  DetectionItem,
  AlertItem,
  HoneypotServiceItem,
  ReportSummary,
  SystemSettings
} from '../types';

const API_BASE = '/api';

class ApiService {
  private getToken(): string | null {
    return localStorage.getItem('honeypot_token');
  }

  private getHeaders(contentType: string = 'application/json'): HeadersInit {
    const headers: Record<string, string> = {};
    if (contentType) {
      headers['Content-Type'] = contentType;
    }
    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${API_BASE}${endpoint}`;
    const headers = { ...this.getHeaders(), ...(options.headers as Record<string, string>) };
    const response = await fetch(url, { ...options, headers });

    if (response.status === 401) {
      localStorage.removeItem('honeypot_token');
      localStorage.removeItem('honeypot_user');
      window.dispatchEvent(new Event('auth_change'));
      throw new Error('Authentication expired. Please log in again.');
    }

    if (!response.ok) {
      let errorMsg = `Request failed: ${response.statusText}`;
      try {
        const errJson = await response.json();
        if (errJson.detail) errorMsg = errJson.detail;
      } catch {
        // ignore
      }
      throw new Error(errorMsg);
    }

    return response.json();
  }

  // Auth
  async login(username: string, password: string): Promise<TokenResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (!res.ok) {
      let msg = 'Login failed';
      try {
        const j = await res.json();
        if (j.detail) msg = j.detail;
      } catch {}
      throw new Error(msg);
    }

    const data: TokenResponse = await res.json();
    localStorage.setItem('honeypot_token', data.access_token);
    localStorage.setItem('honeypot_user', JSON.stringify({ username: data.username, role: data.role }));
    window.dispatchEvent(new Event('auth_change'));
    return data;
  }

  logout() {
    localStorage.removeItem('honeypot_token');
    localStorage.removeItem('honeypot_user');
    window.dispatchEvent(new Event('auth_change'));
  }

  // Dashboard Summary
  async getDashboardSummary(): Promise<DashboardSummary> {
    return this.request<DashboardSummary>('/dashboard/summary');
  }

  // Events
  async getEvents(params: {
    page?: number;
    page_size?: number;
    search?: string;
    severity?: string;
    service?: string;
    event_type?: string;
    source_ip?: string;
  } = {}): Promise<PaginatedEvents> {
    const q = new URLSearchParams();
    if (params.page) q.append('page', params.page.toString());
    if (params.page_size) q.append('page_size', params.page_size.toString());
    if (params.search) q.append('search', params.search);
    if (params.severity) q.append('severity', params.severity);
    if (params.service) q.append('service', params.service);
    if (params.event_type) q.append('event_type', params.event_type);
    if (params.source_ip) q.append('source_ip', params.source_ip);

    return this.request<PaginatedEvents>(`/events?${q.toString()}`);
  }

  async getEventDetail(eventId: string): Promise<EventDetail> {
    return this.request<EventDetail>(`/events/${eventId}`);
  }

  // Detections
  async getDetections(ruleId?: string, severity?: string): Promise<DetectionItem[]> {
    const q = new URLSearchParams();
    if (ruleId) q.append('rule_id', ruleId);
    if (severity) q.append('severity', severity);
    return this.request<DetectionItem[]>(`/detections?${q.toString()}`);
  }

  // Alerts
  async getAlerts(status?: string, severity?: string): Promise<AlertItem[]> {
    const q = new URLSearchParams();
    if (status) q.append('status', status);
    if (severity) q.append('severity', severity);
    return this.request<AlertItem[]>(`/alerts?${q.toString()}`);
  }

  async updateAlert(alertId: string, status: string, notes?: string): Promise<AlertItem> {
    return this.request<AlertItem>(`/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes })
    });
  }

  // Honeypots
  async getHoneypotServices(): Promise<HoneypotServiceItem[]> {
    return this.request<HoneypotServiceItem[]>('/honeypots');
  }

  async startService(serviceId: number): Promise<{ message: string; status: string }> {
    return this.request<{ message: string; status: string }>(`/honeypots/${serviceId}/start`, {
      method: 'POST'
    });
  }

  async stopService(serviceId: number): Promise<{ message: string; status: string }> {
    return this.request<{ message: string; status: string }>(`/honeypots/${serviceId}/stop`, {
      method: 'POST'
    });
  }

  // Reports
  async getReportSummary(period: string = 'daily', startDate?: string, endDate?: string): Promise<ReportSummary> {
    const q = new URLSearchParams({ period });
    if (startDate) q.append('start_date', startDate);
    if (endDate) q.append('end_date', endDate);
    return this.request<ReportSummary>(`/reports/summary?${q.toString()}`);
  }

  getExportCsvUrl(): string {
    const token = this.getToken();
    return `${API_BASE}/reports/export/csv?token=${token}`;
  }

  getExportJsonUrl(): string {
    const token = this.getToken();
    return `${API_BASE}/reports/export/json?token=${token}`;
  }

  // Settings
  async getSettings(): Promise<SystemSettings> {
    return this.request<SystemSettings>('/settings');
  }

  async toggleRule(ruleId: string, enabled: boolean): Promise<{ message: string }> {
    return this.request<{ message: string }>(`/settings/rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify({ enabled })
    });
  }

  async updateRiskWeights(weights: {
    repeated_attempts: number;
    multi_service: number;
    high_frequency: number;
    suspicious_pattern: number;
    known_indicator: number;
  }): Promise<{ message: string }> {
    return this.request<{ message: string }>('/settings/weights', {
      method: 'PUT',
      body: JSON.stringify(weights)
    });
  }
}

export const api = new ApiService();
