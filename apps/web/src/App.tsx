import { useState } from 'react';
import { FileUploadZone } from './components/FileUploadZone';
import { UrlInputForm } from './components/UrlInputForm';
import { FileList } from './components/FileList';
import { UploadButton } from './components/UploadButton';
import { useFileUploader } from './hooks/useFileUploader';
import { uploadFile } from './services/api';
import './App.css';

function App() {
  const {
    files,
    isProcessing,
    setIsProcessing,
    addFile,
    addUrl,
    updatePassword,
    removeFile,
    updateFileStatus,
    retryFile,
  } = useFileUploader();

  const [uploadProgress, setUploadProgress] = useState({
    completed: 0,
    total: 0,
  });

  const uploadSingleFile = async (file: any) => {
    try {
      updateFileStatus(file.id, 'uploading');
      const response = await uploadFile(file);

      if (response.job_id) {
        updateFileStatus(file.id, 'uploaded');
      } else {
        updateFileStatus(file.id, 'error', response.error || 'Upload failed');
      }
    } catch (error) {
      updateFileStatus(
        file.id,
        'error',
        error instanceof Error ? error.message : 'Upload failed'
      );
    }
  };

  const handleUploadAll = async () => {
    const pendingFiles = files.filter(f => f.status === 'pending');
    if (pendingFiles.length === 0) return;

    setIsProcessing(true);
    setUploadProgress({ completed: 0, total: pendingFiles.length });

    for (const file of pendingFiles) {
      await uploadSingleFile(file);
      setUploadProgress(prev => ({
        completed: prev.completed + 1,
        total: prev.total,
      }));
    }

    setIsProcessing(false);
  };

  const handleRetry = async (id: string) => {
    const file = files.find(f => f.id === id);
    if (!file) return;

    retryFile(id);
    await uploadSingleFile({ ...file, status: 'pending', error: undefined });
  };

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>🛡️ MALCORE</h1>
          <p className="subtitle">Malware Analysis Sandbox</p>
        </header>

        <main className="main-content">
          <FileUploadZone onFileSelect={addFile} />

          <UrlInputForm onUrlAdd={addUrl} />

          <FileList
            files={files}
            onPasswordChange={updatePassword}
            onRemove={removeFile}
            onRetry={handleRetry}
          />

          {files.length > 0 && (
            <>
              <UploadButton
                onClick={handleUploadAll}
                disabled={files.length === 0}
                isProcessing={isProcessing}
              />

              {isProcessing && (
                <div className="progress-info">
                  Uploading {uploadProgress.completed} of {uploadProgress.total} files
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
