import { useState } from 'react';
import { FileInput } from '../types';

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

  const addUrl = (url: string, name?: string) => {
    const newFileInput: FileInput = {
      id: generateId(),
      type: 'url',
      url,
      name: name || url,
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

  const retryFile = (id: string) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === id ? { ...file, status: 'pending', error: undefined } : file
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
    retryFile,
    clearAll,
  };
};
