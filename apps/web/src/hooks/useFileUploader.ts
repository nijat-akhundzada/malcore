import { useState, useCallback } from 'react';
import { FileInput } from '../types';

export const useFileUploader = () => {
  const [files, setFiles] = useState<FileInput[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);

  const generateId = () => Math.random().toString(36).substr(2, 9);

  const addFile = (file: File) => {
    const newFileInput: FileInput = {
      id: generateId(),
      type: 'file',
      file,
      name: file.name,
      status: 'pending',
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

  const updatePassword = (id: string, password: string) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === id ? { ...file, password } : file
      )
    );
  };

  const removeFile = (id: string) => {
    setFiles(prev => prev.filter(file => file.id !== id));
  };

  const updateFileStatus = (id: string, status: FileInput['status'], error?: string) => {
    setFiles(prev =>
      prev.map(file =>
        file.id === id ? { ...file, status, error } : file
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
    updatePassword,
    removeFile,
    updateFileStatus,
    clearAll,
  };
};
