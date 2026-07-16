export interface FileInput {
  id: string;
  type: 'file' | 'url';
  file?: File;
  url?: string;
  name: string;
  status: 'pending' | 'uploading' | 'uploaded' | 'analyzing' | 'completed' | 'error';
  archivePassword?: string;
  jobId?: string;
  job?: JobStatusResponse;
  error?: string;
}

export interface UploadResponse {
  job_id: string;
  status: string;
  error?: string;
}

export interface AnalyzerFinding {
  type: string;
  severity: string;
  description: string;
  [key: string]: unknown;
}

export interface IOCCollection {
  urls?: string[];
  ips?: string[];
  domains?: string[];
  [key: string]: unknown;
}

export interface AnalyzerModuleResult {
  analyzer: string;
  category?: string;
  supported?: boolean;
  findings?: AnalyzerFinding[];
  iocs?: IOCCollection;
  errors?: string[];
  metadata?: Record<string, unknown>;
}

export interface AnalyzerResult {
  schema_version?: string;
  analyzers?: string[];
  iocs?: IOCCollection;
  scoring?: {
    rule_score?: number | null;
    ai_score?: number | null;
    final_score?: number | null;
    formula?: string;
    weights?: {
      rule?: number;
      ai?: number;
    };
    ai_model?: Record<string, unknown>;
  };
  results?: AnalyzerModuleResult[];
}

export interface JobStatusResponse {
  id: string;
  source_type: 'upload' | 'url';
  status: string;
  md5_hash?: string | null;
  sha256_hash?: string | null;
  storage_key?: string | null;
  original_storage_key?: string | null;
  quarantine_storage_key?: string | null;
  mime_type?: string | null;
  file_extension?: string | null;
  mime_extension_mismatch: boolean;
  size_bytes?: number | null;
  score?: number | null;
  ai_score?: number | null;
  risk_level?: string | null;
  analysis_result?: AnalyzerResult | null;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AnalysisReport {
  schema_version: string;
  generated_at: string;
  job: {
    id: string;
    source_type: string;
    status: string;
  };
  hashes: {
    md5?: string | null;
    sha256?: string | null;
  };
  yara_hits: unknown[];
  iocs: IOCCollection;
  scores: {
    final?: number | null;
    rule?: number | null;
    ai?: number | null;
    risk_level?: string | null;
  };
  [key: string]: unknown;
}
