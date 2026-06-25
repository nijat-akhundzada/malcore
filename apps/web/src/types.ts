export interface FileInput {
  id: string;
  type: 'file' | 'url';
  file?: File;
  url?: string;
  name: string;
  status: 'pending' | 'uploading' | 'uploaded' | 'analyzing' | 'completed' | 'error';
  jobId?: string;
  job?: JobStatusResponse;
  error?: string;
}

export interface UploadResponse {
  job_id: string;
  status: string;
  error?: string;
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
  risk_level?: string | null;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
}
