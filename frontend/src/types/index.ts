export interface User {
  id: number;
  username: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  username: string;
  role: string;
}

export interface DetectionItem {
  id: number;
  rule_id: string;
  rule_name: string;
  description: string;
  severity: string;
  score: number;
  evidence?: string;
  event_id: string;
  source_ip: string;
  detection_timestamp: string;
}

export interface EventItem {
  id: number;
  event_id: string;
  timestamp: string;
  source_ip: string;
  source_port?: number;
  destination_port: number;
  protocol: string;
  service: string;
  event_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  session_id?: string;
  metadata_json?: string;
  raw_payload?: string;
  created_at: string;
}

export interface EventDetail extends EventItem {
  detections: DetectionItem[];
}

export interface PaginatedEvents {
  items: EventItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface AlertItem {
  id: number;
  alert_id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  source_ip: string;
  detection_id?: number;
  event_id?: string;
  timestamp: string;
  status: 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED';
  acknowledged_at?: string;
  resolved_at?: string;
  notes?: string;
}

export interface HoneypotServiceItem {
  id: number;
  name: string;
  service_type: string;
  port: number;
  protocol: string;
  status: 'running' | 'stopped' | 'error';
  description?: string;
  enabled: boolean;
  event_count: number;
  last_activity?: string;
  created_at: string;
  updated_at: string;
}

export interface ChartDataPoint {
  name: string;
  value: number;
}

export interface TimelinePoint {
  timestamp: string;
  count: number;
  high_count: number;
}

export interface ServiceTargetMetric {
  service: string;
  count: number;
  percentage: number;
}

export interface TopSourceIP {
  ip: string;
  count: number;
  highest_severity: string;
  highest_score: number;
  services: string[];
}

export interface DashboardSummary {
  total_events: number;
  events_last_24h: number;
  unique_ips: number;
  high_critical_events: number;
  active_services: number;
  total_alerts: number;
  severity_distribution: ChartDataPoint[];
  event_type_distribution: ChartDataPoint[];
  timeline_24h: TimelinePoint[];
  top_services: ServiceTargetMetric[];
  top_source_ips: TopSourceIP[];
  recent_events: EventItem[];
  recent_alerts: AlertItem[];
}

export interface ReportSummary {
  generated_at: string;
  report_period: string;
  start_date: string;
  end_date: string;
  total_events: number;
  unique_sources: number;
  total_alerts: number;
  severity_breakdown: ChartDataPoint[];
  top_targeted_services: ServiceTargetMetric[];
  top_threat_sources: TopSourceIP[];
  triggered_rules: ChartDataPoint[];
  executive_summary: string;
}

export interface SystemSettings {
  app_name: string;
  environment: string;
  detection_rules: {
    rule_id: string;
    name: string;
    description: string;
    severity: string;
    score: number;
    enabled: boolean;
  }[];
  risk_weights: {
    repeated_attempts: number;
    multi_service: number;
    high_frequency: number;
    suspicious_pattern: number;
    known_indicator: number;
  };
  honeypot_ports: {
    ssh: number;
    http: number;
    ftp: number;
    tcp: number;
  };
}
