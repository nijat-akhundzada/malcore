export interface FileInput {
  id: string;
  type: 'file' | 'url';
  file?: File;
  url?: string;
  password?: string;
  name: string;
  status: 'pending' | 'uploading' | 'uploaded' | 'error';
  error?: string;
}

export interface UploadResponse {
  success: boolean;
  fileId?: string;
  message: string;
}
