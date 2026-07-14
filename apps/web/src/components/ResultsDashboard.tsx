import { FC } from 'react';
import { useJobDetails } from '../hooks/useJobDetails';
import { getJSONReportURL, getPDFReportURL } from '../services/api';
import {
  collectFindings,
  collectIOCs,
  collectYaraHits,
  formatBytes,
  formatJobStatus,
  isTerminalStatus,
} from '../utils/analysis';
import './ResultsDashboard.css';

interface ResultsDashboardProps {
  jobId: string;
  onBack: () => void;
  onOpenStatus: (jobId: string) => void;
}

export const ResultsDashboard: FC<ResultsDashboardProps> = ({
  jobId,
  onBack,
  onOpenStatus,
}) => {
  const { job, isLoading, error, refresh } = useJobDetails(jobId, {
    pollUntilTerminal: true,
  });

  if (isLoading && !job) {
    return <div className="results-page loading-state">Loading analysis results...</div>;
  }

  if (error || !job) {
    return (
      <div className="results-page error-state">
        <p>{error || 'Results are unavailable.'}</p>
        <div className="results-toolbar">
          <button onClick={onBack} className="secondary-action">Back to upload</button>
          <button onClick={() => refresh()} className="primary-action">Retry</button>
        </div>
      </div>
    );
  }

  if (!isTerminalStatus(job.status) || job.status !== 'completed') {
    return (
      <div className="results-page pending-state">
        <span className="eyebrow">Results Pending</span>
        <h2>{job.id}</h2>
        <p>The analysis is still in progress. You can watch the live status page while the worker finishes.</p>
        <div className="results-toolbar">
          <button onClick={onBack} className="secondary-action">Back to upload</button>
          <button onClick={() => onOpenStatus(job.id)} className="primary-action">
            Open status page
          </button>
        </div>
      </div>
    );
  }

  const findings = collectFindings(job);
  const iocs = collectIOCs(job);
  const yaraHits = collectYaraHits(job);

  return (
    <section className="results-page">
      <div className="results-hero">
        <div>
          <span className="eyebrow">Analysis Results</span>
          <h2>{job.id}</h2>
          <p>Final analyst-facing summary with scores, signatures, indicators, and evidence.</p>
        </div>

        <div className="results-toolbar">
          <button onClick={onBack} className="secondary-action">Back to upload</button>
          <button onClick={() => onOpenStatus(job.id)} className="secondary-action">Status page</button>
          <button onClick={() => refresh()} className="secondary-action">Refresh</button>
          <a href={getJSONReportURL(job.id)} className="secondary-action">JSON report</a>
          <a href={getPDFReportURL(job.id)} className="primary-action">PDF report</a>
        </div>
      </div>

      <div className="score-strip">
        <article className={`score-card risk-${job.risk_level || 'pending'}`}>
          <span>Risk</span>
          <strong>{job.risk_level || 'pending'}</strong>
        </article>
        <article className="score-card">
          <span>Final score</span>
          <strong>{job.score ?? 'pending'}</strong>
        </article>
        <article className="score-card">
          <span>AI score</span>
          <strong>{job.ai_score ?? 'pending'}</strong>
        </article>
        <article className="score-card">
          <span>Status</span>
          <strong>{formatJobStatus(job.status)}</strong>
        </article>
      </div>

      <div className="results-grid">
        <article className="result-panel">
          <h3>Sample Details</h3>
          <dl className="detail-list">
            <div><dt>MIME type</dt><dd>{job.mime_type || 'Unknown'}</dd></div>
            <div><dt>Extension</dt><dd>{job.file_extension || 'Unknown'}</dd></div>
            <div><dt>Size</dt><dd>{formatBytes(job.size_bytes)}</dd></div>
            <div><dt>MIME mismatch</dt><dd>{job.mime_extension_mismatch ? 'Flagged' : 'No'}</dd></div>
            <div><dt>MD5</dt><dd><code>{job.md5_hash || 'Pending'}</code></dd></div>
            <div><dt>SHA256</dt><dd><code>{job.sha256_hash || 'Pending'}</code></dd></div>
          </dl>
        </article>

        <article className="result-panel">
          <h3>YARA Hits</h3>
          {yaraHits.length === 0 ? (
            <p className="empty-copy">No YARA signatures matched this sample.</p>
          ) : (
            <div className="chip-list">
              {yaraHits.map(hit => (
                <div key={`${hit.rule}-${hit.severity}`} className="result-chip">
                  <strong>{hit.rule}</strong>
                  <span>{hit.severity}</span>
                  {hit.description && <p>{hit.description}</p>}
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="result-panel full-span">
          <h3>Indicators of Compromise</h3>
          {iocs.length === 0 ? (
            <p className="empty-copy">No network indicators were extracted.</p>
          ) : (
            <div className="ioc-grid">
              {iocs.map(ioc => (
                <div key={`${ioc.type}-${ioc.value}`} className="ioc-card">
                  <span>{ioc.label}</span>
                  <code>{ioc.value}</code>
                </div>
              ))}
            </div>
          )}
        </article>

        <article className="result-panel full-span">
          <h3>Findings</h3>
          {findings.length === 0 ? (
            <p className="empty-copy">No analyzer findings were reported.</p>
          ) : (
            <div className="findings-grid">
              {findings.map((finding, index) => (
                <div key={`${finding.analyzer}-${finding.type}-${index}`} className="finding-card">
                  <div className="finding-meta">
                    <span className={`severity severity-${finding.severity.toLowerCase()}`}>
                      {finding.severity}
                    </span>
                    <span>{finding.analyzer}</span>
                    <span>{finding.type}</span>
                  </div>
                  <p>{finding.description}</p>
                </div>
              ))}
            </div>
          )}
        </article>
      </div>
    </section>
  );
};
