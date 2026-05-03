import axios from 'axios';
import { FileInput, UploadResponse } from '../types';

const API_BASE_URL = '/api';

export const uploadFile = async (fileInput: FileInput): Promise<UploadResponse> => {
  const formData = new FormData();
  
  if (fileInput.type === 'file' && fileInput.file) {
    formData.append('file', fileInput.file);
    formData.append('uploadType', 'file');
  } else if (fileInput.type === 'url' && fileInput.url) {
    formData.append('url', fileInput.url);
    formData.append('uploadType', 'url');
  }
  
  if (fileInput.password) {
    formData.append('password', fileInput.password);
  }
  
  formData.append('fileName', fileInput.name);

  try {
    const response = await axios.post<UploadResponse>(
      `${API_BASE_URL}/upload`,
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
      throw new Error(error.response?.data?.message || 'Upload failed');
    }
    throw new Error('Upload failed');
  }
};

export const getUploadStatus = async (fileId: string) => {
  const response = await axios.get(`${API_BASE_URL}/upload/${fileId}/status`);
  return response.data;
};
