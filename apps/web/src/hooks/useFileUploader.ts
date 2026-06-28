import { useState } from 'react';
import { FileInput, JobStatusResponse } from '../types';

export const useFileUploader = () => {
  const [files, setFiles] = useState<FileInput[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);

  const generateId = () => Math.random().toString(36).substr(2, 9);

  const addFile = (file: File) => {
    const isTooLarge = file.size > 10 * 1024 * 1024;
    const newFileInput: FileInput = {
      id: generateId(),
      type: 'file',
      file,
      name: file.name,
      status: isTooLarge ? 'error' : 'pending',
      error: isTooLarge ? 'File size exceeds 10MB' : undefined,
    };
    setFiles(prev => [...prev, newFileInput]);
  };

  const addUrl = (url: string, archivePassword?: string, name?: string) => {
    const newFileInput: FileInput = {
      id: generateId(),
      type: 'url',
      url,
      name: name || url,
      archivePassword,
      status: 'pending',
    };
    setFiles(prev => [...prev, newFileInput]);
  };

  const removeFile = (id: string) => {
    setFiles(prev => prev.filter(file => file.id !== id));
  };

  const updateFileStatus = (
    id: string,
    status: FileInput['status'],
    error?: string,
    jobId?: string
  ) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === id ? { ...file, status, error, jobId: jobId ?? file.jobId } : file
      )
    );
  };

  const updateFileJob = (id: string, job: JobStatusResponse) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === id ? { ...file, job, jobId: job.id || file.jobId } : file
      )
    );
  };

  const updateArchivePassword = (id: string, archivePassword: string) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === id ? { ...file, archivePassword } : file
      )
    );
  };

  const retryFile = (id: string) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === id
          ? { ...file, status: 'pending', error: undefined, jobId: undefined, job: undefined }
          : file
      )
    );
  };

  const clearAll = () => {
    setFiles([]);
    setIsProcessing(false);
  };

  return {
    files,
    isProcessing,
    setIsProcessing,
    addFile,
    addUrl,
    removeFile,
    updateFileStatus,
    updateFileJob,
    updateArchivePassword,
    retryFile,
    clearAll,
  };
};
