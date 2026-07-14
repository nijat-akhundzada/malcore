import { useEffect, useState } from 'react';
import { FileUploadZone } from './components/FileUploadZone';
import { UrlInputForm } from './components/UrlInputForm';
import { FileList } from './components/FileList';
import { UploadButton } from './components/UploadButton';
import { JobStatusPage } from './components/JobStatusPage';
import { ResultsDashboard } from './components/ResultsDashboard';
import { useFileUploader } from './hooks/useFileUploader';
import { getUploadStatus, uploadFile } from './services/api';
import { FileInput } from './types';
import './App.css';

const JOB_POLL_INTERVAL_MS = 1000;
const JOB_POLL_ATTEMPTS = 60;

const wait = (delay: number) => new Promise(resolve => window.setTimeout(resolve, delay));

type AppRoute =
  | { view: 'upload' }
  | { view: 'status'; jobId: string }
  | { view: 'result'; jobId: string };

const parseHashRoute = (hash: string): AppRoute => {
  const match = hash.match(/^#\/jobs\/([^/]+)\/(status|result)$/);
  if (!match) {
    return { view: 'upload' };
  }

  const [, jobId, view] = match;
  return view === 'status' ? { view: 'status', jobId } : { view: 'result', jobId };
};

const navigateTo = (route: AppRoute) => {
  if (route.view === 'upload') {
    window.location.hash = '#/';
    return;
  }

  window.location.hash = `#/jobs/${route.jobId}/${route.view}`;
};

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
    updateArchivePassword,
    retryFile,
  } = useFileUploader();

  const [uploadProgress, setUploadProgress] = useState({
    completed: 0,
    total: 0,
  });
  const [route, setRoute] = useState<AppRoute>(() => parseHashRoute(window.location.hash));

  useEffect(() => {
    const handleHashChange = () => {
      setRoute(parseHashRoute(window.location.hash));
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

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

  if (route.view === 'status') {
    return (
      <div className="app">
        <div className="container page-shell">
          <JobStatusPage
            jobId={route.jobId}
            onBack={() => navigateTo({ view: 'upload' })}
            onOpenResult={(jobId) => navigateTo({ view: 'result', jobId })}
          />
        </div>
      </div>
    );
  }

  if (route.view === 'result') {
    return (
      <div className="app">
        <div className="container page-shell">
          <ResultsDashboard
            jobId={route.jobId}
            onBack={() => navigateTo({ view: 'upload' })}
            onOpenStatus={(jobId) => navigateTo({ view: 'status', jobId })}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <div className="container">
        <header className="header hero">
          <div className="hero-copy">
            <span className="eyebrow">Malware Analysis Pipeline</span>
            <h1>MALCORE</h1>
            <p className="subtitle">
              Submit suspicious files or URLs, watch the queue progress, and export
              analyst-friendly JSON and PDF reports from the same workspace.
            </p>
          </div>

          <div className="hero-stats">
            <div className="hero-stat">
              <strong>Static analyzers</strong>
              <span>PE, script, office, archive, IOC, YARA</span>
            </div>
            <div className="hero-stat">
              <strong>Outputs</strong>
              <span>Status tracking, results dashboard, JSON, PDF</span>
            </div>
          </div>
        </header>

        <main className="main-content">
          <section className="panel input-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Task 29</span>
                <h2>Upload Page</h2>
              </div>
              <p>
                Add local samples, submit remote URLs, and attach archive passwords
                before queueing analysis jobs.
              </p>
            </div>

            <FileUploadZone onFileSelect={addFile} />
            <UrlInputForm onUrlAdd={addUrl} />
          </section>

          <section className="panel queue-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">Session Queue</span>
                <h2>Tracked Jobs</h2>
              </div>
              <p>
                Each session item can open a dedicated status page or results dashboard
                after the worker finishes.
              </p>
            </div>

            <FileList
              files={files}
              onRemove={removeFile}
              onRetry={handleRetry}
              onArchivePasswordChange={updateArchivePassword}
              onOpenStatus={(jobId) => navigateTo({ view: 'status', jobId })}
              onOpenResult={(jobId) => navigateTo({ view: 'result', jobId })}
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
          </section>
        </main>
      </div>
    </div>
  );
}

export default App;
