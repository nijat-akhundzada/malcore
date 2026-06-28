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
