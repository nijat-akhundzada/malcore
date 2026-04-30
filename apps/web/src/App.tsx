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
    clearAll,
  } = useFileUploader();

  const [uploadProgress, setUploadProgress] = useState({
    completed: 0,
    total: 0,
  });

  const handleUploadAll = async () => {
    const pendingFiles = files.filter(f => f.status === 'pending');
    if (pendingFiles.length === 0) return;

    setIsProcessing(true);
    setUploadProgress({ completed: 0, total: pendingFiles.length });

    for (const file of pendingFiles) {
      try {
        updateFileStatus(file.id, 'uploading');
        const response = await uploadFile(file);
        
        if (response.success) {
          updateFileStatus(file.id, 'uploaded');
        } else {
          updateFileStatus(file.id, 'error', response.message);
        }
      } catch (error) {
        updateFileStatus(
          file.id,
          'error',
          error instanceof Error ? error.message : 'Upload failed'
        );
      }
      
      setUploadProgress(prev => ({
        completed: prev.completed + 1,
        total: prev.total,
      }));
    }

    setIsProcessing(false);
  };

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>📦 Zorbox</h1>
          <p className="subtitle">File Upload Platform</p>
        </header>

        <main className="main-content">
          <FileUploadZone onFileSelect={addFile} />
          
          <UrlInputForm onUrlAdd={addUrl} />
          
          <FileList
            files={files}
            onPasswordChange={updatePassword}
            onRemove={removeFile}
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
