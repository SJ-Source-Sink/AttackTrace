// ============================================================
// Auth Types
// ============================================================

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  org_id?: string;
  organization_id: string;
  created_at: string;
  last_login?: string;
  avatar_url?: string;
  tool_permissions: string[] | null;
  mfa_enabled?: boolean;
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

export interface MfaRequiredResponse {
  mfa_required: true;
  mfa_token: string;
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
  tool_permissions: string[] | null;
}

export const ALL_TOOL_KEYS = [
  "nmap", "nuclei", "ffuf", "attack_suite", "burp_analyzer",
  "test_generator", "ai_triage", "takeover", "attackmapper",
  "mobile", "firewall", "network_graph", "scans", "findings",
  "assets", "reports",
] as const;

export type ToolKey = typeof ALL_TOOL_KEYS[number];

export const TOOL_LABELS: Record<string, string> = {
  nmap: "Nmap Scanner",
  nuclei: "Nuclei Scanner",
  ffuf: "Web Fuzzer (ffuf)",
  attack_suite: "Attack Suite",
  burp_analyzer: "Burp Analyzer",
  test_generator: "Test Case Generator",
  ai_triage: "AI Triage",
  takeover: "Subdomain Takeover",
  attackmapper: "Attack Mapper",
  mobile: "Mobile Security",
  firewall: "Firewall Config",
  network_graph: "Network Graph",
  scans: "Scan Jobs",
  findings: "Findings",
  assets: "Assets",
  reports: "Reports",
};

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
export type ScanIntensity = "passive" | "normal" | "aggressive" | "passive_due_diligence";
export type ScanModule =
  | "seed" | "domain" | "dns" | "infrastructure" | "enrichment"
  | "intel" | "osint" | "web" | "cloud" | "correlation";

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

export interface ScanModuleStatus {
  module: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  findings_count?: number;
  error?: string;
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

export interface ScanDiffAsset {
  type: string;
  value: string;
}

export interface ScanDiffFinding {
  title: string;
  severity: string;
  asset: string;
  dedup_hash?: string;
}

export interface ScanDiff {
  scan_id: string;
  previous_scan_id: string | null;
  new_assets: ScanDiffAsset[];
  removed_assets: ScanDiffAsset[];
  new_findings: ScanDiffFinding[];
  resolved_findings: ScanDiffFinding[];
  diff_summary: {
    new_assets_count: number;
    removed_assets_count: number;
    new_findings_count: number;
    resolved_findings_count: number;
    total_assets: number;
    total_findings: number;
  };
  created_at: string;
}

// ============================================================
// Asset Types
// ============================================================

export type AssetType =
  | "subdomain"
  | "domain"
  | "ip"
  | "webapp"
  | "cloud"
  | "endpoint";

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
  | "subdomain_takeover"
  | "exposed_secret"
  // Standalone Secrets Scanner tool (app/api/v1/secrets.py) uses this
  // category instead of "exposed_secret" — kept distinct from it in the
  // data, so both values need handling wherever "exposed_secret" is checked.
  | "secrets";

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

// Matches the real GET /findings/{id}/comments response shape
// (app/models/schemas/finding.py::FindingCommentResponse) — comments are
// fetched directly via that endpoint (see useFindingComments), not embedded
// on Finding, since the API never actually populates an embedded field.
export interface FindingComment {
  id: string;
  finding_id: string;
  user_id: string;
  body: string;
  created_at: string;
  updated_at?: string | null;
  user_email?: string | null;
  user_full_name?: string | null;
}

export interface FindingCommentListResponse {
  items: FindingComment[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

// Matches the real GET /findings/{id}/history response shape
// (app/api/v1/findings.py::get_finding_history) — audit log entries scoped
// to this finding, newest first.
export interface FindingHistoryEntry {
  id: string;
  action: string;
  before_state: Record<string, unknown> | null;
  after_state: Record<string, unknown> | null;
  created_at: string;
  user_id: string | null;
  user_name: string;
}

export interface FindingHistoryListResponse {
  items: FindingHistoryEntry[];
  total: number;
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
  // A dict at the API level (backend FindingResponse.evidence: Optional[dict]),
  // shape varies by scanner — rendered by components/findings/evidence-block.tsx.
  evidence: Record<string, unknown> | null;
  ai_triage?: FindingAITriage;
  remediation_steps: string[];
  references: string[];
  accept_risk_info?: AcceptRiskInfo;
  created_at: string;
  updated_at: string;
  first_seen: string;
  last_seen: string;
  age_days: number;
  assigned_to?: string;
  tags: string[];
  // KEV / EPSS / confidence enrichment fields
  confidence?: 'certain' | 'high' | 'medium' | 'low' | null;
  // How this finding was actually verified — oracle is the raw machine type
  // (e.g. "pattern-entropy"), confidence_explanation is the full sentence
  // explaining what that oracle proved and didn't. Null when the source
  // scanner didn't report an oracle.
  oracle?: string | null;
  confidence_explanation?: string | null;
  kev_status?: boolean;
  epss_score?: number | null;
  priority_score?: number | null;
  suppressed?: boolean;
  suppressed_reason?: string | null;
  false_positive?: boolean;
  // Source attribution
  source?: string;
  source_scan_id?: string | null;
  // SLA / compliance / risk
  sla_deadline?: string | null;
  compliance_tags?: string[] | null;
  risk_score?: number | null;
  risk_explanation?: string | null;
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
  // SLA filters
  overdue?: boolean;
  sort_by?: string;
}

export interface UpdateFindingRequest {
  status?: FindingStatus;
  severity?: FindingSeverity;
  false_positive?: boolean;
  suppressed?: boolean;
  suppressed_reason?: string;
  ticket_ref?: string;
  remediation?: string;
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
// Executive Dashboard Types
// ============================================================

export interface ExecutiveDashboardData {
  mttr_by_severity: {
    critical: number | null;
    high: number | null;
    medium: number | null;
    low: number | null;
  };
  risk_trend: {
    "30d": number;
    "60d": number;
    "90d": number;
  };
  new_vs_recurring: {
    new: number;
    recurring: number;
  };
  coverage_percent: number;
  open_critical: number;
  sla_compliance_percent: number;
  generated_at: string;
}

// ============================================================
// Nuclei Template Types
// ============================================================

export interface NucleiTemplate {
  id: string;
  name: string;
  severity: string;
  category: string;
  tags: string[];
  enabled: boolean;
  path: string;
}

export interface NucleiTemplateListResponse {
  items: NucleiTemplate[];
  total: number;
  page: number;
  per_page: number;
}

// ============================================================
// Cloud Discovery Types
// ============================================================

export interface CloudAsset {
  value: string;
  asset_type: string;
  provider: string;
  resource_type: string;
  metadata: Record<string, unknown>;
}

export interface CloudDiscoverResult {
  discovered: number;
  assets: CloudAsset[];
  provider: string;
  message?: string;
}

export interface CloudAssetListResponse {
  items: Array<{
    id: string;
    value: string;
    tags: string[];
    is_active: boolean;
    risk_score: number | null;
    first_seen: string | null;
    last_seen: string | null;
    metadata: Record<string, unknown> | null;
  }>;
  total: number;
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

// ============================================================
// Scheduled Scan Types
// ============================================================

export interface ScheduledScan {
  id: string;
  org_id: string;
  workspace_id?: string | null;
  created_by?: string | null;
  name: string;
  target_domains: string[];
  company_name?: string | null;
  scan_config: Record<string, unknown>;
  cron_expression: string;
  is_active: boolean;
  last_run?: string | null;
  next_run?: string | null;
  last_scan_job_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateScheduleRequest {
  name: string;
  target_domains: string[];
  company_name?: string;
  cron_expression: string;
  workspace_id?: string;
  is_active?: boolean;
  scan_config?: Record<string, unknown>;
}

export interface ScheduledScanListResponse {
  items: ScheduledScan[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

// ============================================================
// Notification Channel Types
// ============================================================

export type NotificationChannelType = "slack" | "jira" | "webhook" | "teams";
export type NotificationEvent =
  | "scan.completed"
  | "finding.critical"
  | "sla.breached"
  | "asset.discovered"
  | "port.opened"
  | "cert.expiring";

export interface NotificationChannel {
  id: string;
  org_id: string;
  name: string;
  channel_type: NotificationChannelType;
  config: Record<string, string>;  // masked — secrets replaced with "***"
  is_active: boolean;
  events: NotificationEvent[];
  created_at: string;
  updated_at: string;
}

export interface CreateChannelRequest {
  name: string;
  channel_type: NotificationChannelType;
  config: Record<string, string>;
  is_active?: boolean;
  events: NotificationEvent[];
}

export interface NotificationChannelListResponse {
  items: NotificationChannel[];
}

export interface NotificationFeedItem {
  id: string;
  event_type: string;
  title: string;
  body: string;
  resource_type: string;
  resource_id: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  user_id: string;
  timestamp: string;
  read: string;
}

export interface NotificationFeedResponse {
  items: NotificationFeedItem[];
  unread_count: number;
  last_read_id: string;
}
