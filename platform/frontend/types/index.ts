// ============================================================
// Auth Types
// ============================================================

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  organization_id: string;
  created_at: string;
  last_login?: string;
  avatar_url?: string;
}

export type UserRole = "owner" | "admin" | "analyst" | "viewer";

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name: string;
  invite_code: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

// ============================================================
// Organization Types
// ============================================================

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: "free" | "pro" | "enterprise";
  created_at: string;
  member_count: number;
  logo_url?: string;
}

export interface OrgMember {
  user_id: string;
  email: string;
  full_name: string;
  role: UserRole;
  joined_at: string;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  created_at: string;
  last_used?: string;
  expires_at?: string;
  permissions: string[];
}

// ============================================================
// Scan Types
// ============================================================

export type ScanStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type ScanIntensity = "passive" | "normal" | "aggressive";
export type ScanModule = "infrastructure" | "cloud" | "osint" | "web" | "enrichment";

export interface ScanTarget {
  company_name: string;
  domains: string[];
}

export interface ScanConfig {
  intensity: ScanIntensity;
  skip_modules: ScanModule[];
  schedule?: {
    run_at?: string;
    cron?: string;
  };
}

export interface CreateScanRequest {
  target: ScanTarget;
  config: ScanConfig;
}

export interface ScanModuleStatus {
  name: ScanModule;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  findings_count: number;
  assets_count: number;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

export interface ScanPhase {
  name: string;
  description: string;
  status: "pending" | "running" | "completed" | "failed";
  modules: ScanModule[];
}

export interface ScanStats {
  total_assets: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  risk_score: number;
  duration_seconds?: number;
}

export interface Scan {
  id: string;
  org_id: string;
  workspace_id?: string;
  // Flat fields from backend ScanResponse
  target_domains: string[];
  company_name?: string;
  intensity: ScanIntensity;
  modules_to_skip: string[];
  status: ScanStatus;
  session_id?: string;
  celery_task_id?: string;
  findings_count?: { critical: number; high: number; medium: number; low: number; info: number };
  results_summary?: Record<string, unknown>;
  scheduled_at?: string;
  schedule_cron?: string;
  error_message?: string;
  created_at: string;
  updated_at: string;
  started_at?: string;
  completed_at?: string;
  // Legacy nested shape (kept for UI compat — mapped from flat fields where needed)
  target?: ScanTarget;
  config?: ScanConfig;
  stats?: ScanStats;
  module_statuses?: ScanModuleStatus[];
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  page: number;
  per_page: number;
}

export interface ScanSSEEvent {
  type: "phase_update" | "module_update" | "finding" | "progress" | "complete" | "error";
  phase?: string;
  module?: string;
  module_status?: ScanModuleStatus["status"];
  finding?: Finding;
  progress?: number;
  message?: string;
  stats?: ScanStats;
  timestamp: string;
}

// ============================================================
// Asset Types
// ============================================================

export type AssetType =
  | "subdomain"
  | "domain"
  | "ip"
  | "webapp"
  | "cloud";

export interface AssetTag {
  key: string;
  value: string;
}

export interface Asset {
  id: string;
  org_id: string;
  scan_job_id?: string | null;
  asset_type: AssetType;
  value: string;
  risk_score: number;
  first_seen: string;
  last_seen: string;
  tags: string[];
  metadata?: Record<string, unknown> | null;
  is_active: boolean;
  screenshot_url?: string | null;
}

export interface AssetListResponse {
  items: Asset[];
  total: number;
  page: number;
  per_page: number;
}

export interface AssetFilters {
  types?: AssetType[];
  scan_id?: string;
  risk_min?: number;
  risk_max?: number;
  tags?: string[];
  first_seen_after?: string;
  first_seen_before?: string;
  last_seen_after?: string;
  search?: string;
  owner?: string;
  is_active?: boolean;
  has_screenshot?: boolean;
}

// ============================================================
// Finding Types
// ============================================================

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus =
  | "open"
  | "in_progress"
  | "remediated"
  | "accepted_risk"
  | "false_positive";
export type FindingCategory =
  | "vulnerability"
  | "misconfiguration"
  | "exposure"
  | "credential_leak"
  | "outdated_software"
  | "missing_security_header"
  | "weak_cipher"
  | "open_port"
  | "cloud_misconfiguration"
  | "subdomain_takeover";

export interface FindingEvidence {
  type: "screenshot" | "request_response" | "code_snippet" | "log" | "raw";
  title: string;
  content: string;
  url?: string;
}

export interface FindingAITriage {
  severity: FindingSeverity;
  reasoning: string;
  confidence: number;
  suggested_remediation: string;
  false_positive_likelihood: number;
  business_impact: string;
}

export interface FindingComment {
  id: string;
  author: User;
  content: string;
  created_at: string;
  updated_at?: string;
}

export interface AcceptRiskInfo {
  reason: string;
  expires_at?: string;
  approver: string;
  accepted_at: string;
  accepted_by: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  status: FindingStatus;
  category: FindingCategory;
  asset_id: string;
  asset_value: string;
  asset_type: AssetType;
  scan_id: string;
  organization_id: string;
  cve_id?: string;
  cvss_score?: number;
  cwe_id?: string;
  evidence: FindingEvidence[];
  ai_triage?: FindingAITriage;
  remediation_steps: string[];
  references: string[];
  comments: FindingComment[];
  accept_risk_info?: AcceptRiskInfo;
  created_at: string;
  updated_at: string;
  first_seen: string;
  last_seen: string;
  age_days: number;
  assigned_to?: string;
  tags: string[];
  // KEV / EPSS / confidence enrichment fields
  confidence?: 'certain' | 'firm' | 'tentative' | null;
  kev_status?: boolean;
  epss_score?: number | null;
  priority_score?: number | null;
  suppressed?: boolean;
  suppressed_reason?: string | null;
  false_positive?: boolean;
}

export interface FindingListResponse {
  items: Finding[];
  total: number;
  page: number;
  per_page: number;
}

export interface FindingFilters {
  severities?: FindingSeverity[];
  statuses?: FindingStatus[];
  categories?: FindingCategory[];
  asset_types?: AssetType[];
  scan_id?: string;
  search?: string;
  has_cve?: boolean;
  age_min?: number;
  age_max?: number;
  assigned_to?: string;
  // KEV / confidence / suppressed filters
  kev_only?: boolean;
  confidence?: string;
  suppressed?: boolean;
}

export interface UpdateFindingRequest {
  status?: FindingStatus;
  assigned_to?: string;
  accept_risk_info?: Omit<AcceptRiskInfo, "accepted_at" | "accepted_by">;
  tags?: string[];
}

// ============================================================
// Report Types
// ============================================================

export type ReportFormat = "pdf" | "html" | "json" | "csv";

export interface Report {
  id: string;
  scan_id: string;
  format: ReportFormat;
  name: string;
  created_at: string;
  created_by: string;
  size_bytes: number;
  download_url: string;
}

// ============================================================
// AI Types
// ============================================================

export interface AISearchRequest {
  query: string;
  context?: "assets" | "findings";
}

export interface AISearchResponse {
  filters: Record<string, unknown>;
  explanation: string;
  chips: FilterChip[];
}

export interface FilterChip {
  key: string;
  label: string;
  value: string | string[] | number | boolean;
  removable: boolean;
}

export interface AISummarizeRequest {
  scan_id: string;
  include_recommendations?: boolean;
}

export interface AISummarizeResponse {
  summary: string;
  key_findings: string[];
  recommendations: string[];
  risk_level: "low" | "medium" | "high" | "critical";
  generated_at: string;
}

// ============================================================
// Dashboard Types
// ============================================================

export interface RiskScoreDataPoint {
  date: string;
  score: number;
  critical: number;
  high: number;
}

export interface DashboardStats {
  total_assets: number;
  active_assets: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  active_scans: number;
  risk_score: number;
  risk_trend: "up" | "down" | "stable";
  risk_score_history: RiskScoreDataPoint[];
}

// ============================================================
// Pagination & Common
// ============================================================

export interface PaginationParams {
  page?: number;
  per_page?: number;
  sort_by?: string;
  sort_order?: "asc" | "desc";
}

export interface ApiError {
  detail: string;
  status_code: number;
}
