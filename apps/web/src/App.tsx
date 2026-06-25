import { useState } from 'react';
import { FileUploadZone } from './components/FileUploadZone';
import { UrlInputForm } from './components/UrlInputForm';
import { FileList } from './components/FileList';
import { UploadButton } from './components/UploadButton';
import { useFileUploader } from './hooks/useFileUploader';
import { getUploadStatus, uploadFile } from './services/api';
import { FileInput } from './types';
import './App.css';

const JOB_POLL_INTERVAL_MS = 1000;
const JOB_POLL_ATTEMPTS = 60;

const wait = (delay: number) => new Promise(resolve => window.setTimeout(resolve, delay));

function App() {
  const {
    files,
    isProcessing,
    setIsProcessing,
    addFile,
    addUrl,
    removeFile,
    updateFileStatus,
    updateFileJob,
    retryFile,
  } = useFileUploader();

  const [uploadProgress, setUploadProgress] = useState({
    completed: 0,
    total: 0,
  });

  const uploadSingleFile = async (file: FileInput) => {
    try {
      updateFileStatus(file.id, 'uploading');
      const response = await uploadFile(file);

      if (response.job_id) {
        updateFileStatus(file.id, 'analyzing', undefined, response.job_id);
        void pollJobStatus(file.id, response.job_id);
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

  const pollJobStatus = async (fileId: string, jobId: string) => {
    for (let attempt = 0; attempt < JOB_POLL_ATTEMPTS; attempt += 1) {
      try {
        const job = await getUploadStatus(jobId);
        updateFileJob(fileId, job);

        if (job.status === 'completed') {
          updateFileStatus(fileId, 'completed', undefined, jobId);
          return;
        }

        if (job.status === 'failed') {
          updateFileStatus(fileId, 'error', job.error_message || 'Analysis failed', jobId);
          return;
        }
      } catch (error) {
        if (attempt === JOB_POLL_ATTEMPTS - 1) {
          updateFileStatus(
            fileId,
            'error',
            error instanceof Error ? error.message : 'Failed to fetch analysis result',
            jobId
          );
          return;
        }
      }

      await wait(JOB_POLL_INTERVAL_MS);
    }

    updateFileStatus(fileId, 'error', 'Analysis timed out', jobId);
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
