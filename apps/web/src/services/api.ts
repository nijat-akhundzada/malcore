import axios from 'axios';
import { FileInput, JobStatusResponse, UploadResponse } from '../types';

const API_BASE_URL = '/api';

export const uploadFile = async (fileInput: FileInput): Promise<UploadResponse> => {
  try {
    if (fileInput.type === 'url' && fileInput.url) {
      const response = await axios.post<UploadResponse>(
        `${API_BASE_URL}/v1/urls/submit`,
        {
          url: fileInput.url,
          archive_password: fileInput.archivePassword || undefined,
        }
      );
      return response.data;
    }

    if (fileInput.type !== 'file' || !fileInput.file) {
      throw new Error('File is required');
    }

    const formData = new FormData();
    formData.append('file', fileInput.file);
    if (fileInput.archivePassword) {
      formData.append('archive_password', fileInput.archivePassword);
    }

    const response = await axios.post<UploadResponse>(
      `${API_BASE_URL}/v1/files/upload`,
      formData
    );

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.error || 'Upload failed');
    }
    throw new Error('Upload failed');
  }
};

export const getJobResult = async (jobId: string): Promise<JobStatusResponse> => {
  const response = await axios.get<JobStatusResponse>(`${API_BASE_URL}/v1/jobs/${jobId}/result`);
  return response.data;
};

export const getUploadStatus = getJobResult;

export const getJSONReportURL = (jobId: string) =>
  `${API_BASE_URL}/v1/jobs/${jobId}/report.json`;

export const getPDFReportURL = (jobId: string) =>
  `${API_BASE_URL}/v1/jobs/${jobId}/report.pdf`;
