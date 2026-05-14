import axios from 'axios';
import { FileInput, UploadResponse } from '../types';

const API_BASE_URL = '/api';

export const uploadFile = async (fileInput: FileInput): Promise<UploadResponse> => {
  try {
    if (fileInput.type === 'url' && fileInput.url) {
      const response = await axios.post<UploadResponse>(
        `${API_BASE_URL}/v1/urls/submit`,
        { url: fileInput.url }
      );
      return response.data;
    }

    const formData = new FormData();
    if (fileInput.type === 'file' && fileInput.file) {
      formData.append('file', fileInput.file);
      formData.append('uploadType', 'file');
    }

    if (fileInput.password) {
      formData.append('password', fileInput.password);
    }

    formData.append('fileName', fileInput.name);

    const response = await axios.post<UploadResponse>(
      `${API_BASE_URL}/v1/files/upload`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    );

    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      throw new Error(error.response?.data?.error || 'Upload failed');
    }
    throw new Error('Upload failed');
  }
};

export const getUploadStatus = async (fileId: string) => {
  const response = await axios.get(`${API_BASE_URL}/upload/${fileId}/status`);
  return response.data;
};
