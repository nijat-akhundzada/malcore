import { FC } from 'react';
import { useJobDetails } from '../hooks/useJobDetails';
import { getJSONReportURL, getPDFReportURL } from '../services/api';
import { formatBytes, formatJobStatus } from '../utils/analysis';
import './JobStatusPage.css';

interface JobStatusPageProps {
  jobId: string;
  onBack: () => void;
  onOpenResult: (jobId: string) => void;
}

const STATUS_STEPS = [
  { id: 'pending', label: 'Job created' },
  { id: 'queued', label: 'Queued for analysis' },
  { id: 'running', label: 'Analyzer running' },
  { id: 'completed', label: 'Completed' },
];

export const JobStatusPage: FC<JobStatusPageProps> = ({
  jobId,
  onBack,
  onOpenResult,
}) => {
  const { job, isLoading, error, refresh } = useJobDetails(jobId, {
    pollUntilTerminal: true,
  });

  if (isLoading && !job) {
    return <div className="job-page loading-state">Loading job status...</div>;
  }

  if (error || !job) {
    return (
      <div className="job-page error-state">
        <p>{error || 'Job not found'}</p>
        <div className="job-page-actions">
          <button onClick={onBack} className="secondary-action">Back to upload</button>
          <button onClick={() => refresh()} className="primary-action">Retry</button>
        </div>
      </div>
    );
  }

  const currentStepIndex = Math.max(
    STATUS_STEPS.findIndex(step => step.id === job.status),
    0
  );
  const isCompleted = job.status === 'completed';

  return (
    <section className="job-page">
      <div className="job-page-header">
        <div>
          <span className="eyebrow">Job Status</span>
          <h2>{job.id}</h2>
          <p>Track queue progress, file metadata, and report readiness.</p>
        </div>

        <div className="job-page-actions">
          <button onClick={onBack} className="secondary-action">Back to upload</button>
          <button onClick={() => refresh()} className="secondary-action">Refresh</button>
          {isCompleted && (
            <button onClick={() => onOpenResult(job.id)} className="primary-action">
              Open results
            </button>
          )}
        </div>
      </div>

      <div className="status-banner">
        <div>
          <strong>{formatJobStatus(job.status)}</strong>
          <span>{job.error_message || 'The job will keep refreshing until it reaches a terminal state.'}</span>
        </div>
        <span className={`status-pill ${job.status}`}>{job.status}</span>
      </div>

      <div className="status-timeline">
        {STATUS_STEPS.map((step, index) => {
          const state =
            index < currentStepIndex ? 'done' :
            index === currentStepIndex ? 'active' :
            'pending';

          return (
            <div key={step.id} className={`timeline-step ${state}`}>
              <div className="timeline-marker">{index + 1}</div>
              <div className="timeline-copy">
                <strong>{step.label}</strong>
                <span>{state === 'active' ? 'Current stage' : state === 'done' ? 'Completed' : 'Waiting'}</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="status-grid">
        <article className="status-card">
          <h3>File Metadata</h3>
          <dl>
            <div><dt>MIME</dt><dd>{job.mime_type || 'Pending'}</dd></div>
            <div><dt>Extension</dt><dd>{job.file_extension || 'Pending'}</dd></div>
            <div><dt>Size</dt><dd>{formatBytes(job.size_bytes)}</dd></div>
            <div><dt>Mismatch</dt><dd>{job.mime_extension_mismatch ? 'Flagged' : 'No mismatch'}</dd></div>
          </dl>
        </article>

        <article className="status-card">
          <h3>Timing</h3>
          <dl>
            <div><dt>Created</dt><dd>{new Date(job.created_at).toLocaleString()}</dd></div>
            <div><dt>Updated</dt><dd>{new Date(job.updated_at).toLocaleString()}</dd></div>
            <div><dt>Source</dt><dd>{job.source_type}</dd></div>
            <div><dt>Risk</dt><dd>{job.risk_level || 'Pending'}</dd></div>
          </dl>
        </article>

        <article className="status-card hashes-card">
          <h3>Hashes</h3>
          <dl>
            <div><dt>MD5</dt><dd><code>{job.md5_hash || 'Pending'}</code></dd></div>
            <div><dt>SHA256</dt><dd><code>{job.sha256_hash || 'Pending'}</code></dd></div>
          </dl>
        </article>
      </div>

      {isCompleted && (
        <div className="report-actions">
          <a href={getJSONReportURL(job.id)} className="secondary-action">Download JSON report</a>
          <a href={getPDFReportURL(job.id)} className="primary-action">Download PDF report</a>
        </div>
      )}
    </section>
  );
};
