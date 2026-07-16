import { FC } from 'react';
import { AnalyzerFinding, FileInput, IOCCollection } from '../types';
import './FileListItem.css';

interface FileListItemProps {
  file: FileInput;
  onRemove: (id: string) => void;
  onRetry: (id: string) => void;
  onArchivePasswordChange: (id: string, archivePassword: string) => void;
  onDownloadReport: (jobId: string) => void;
  onDownloadPDFReport: (jobId: string) => void;
}

export const FileListItem: FC<FileListItemProps> = ({
  file,
  onRemove,
  onRetry,
  onArchivePasswordChange,
  onDownloadReport,
  onDownloadPDFReport,
}) => {
  const getStatusIcon = () => {
    switch (file.status) {
      case 'completed':
        return 'OK';
      case 'analyzing':
        return '...';
      case 'uploaded':
        return 'OK';
      case 'uploading':
        return '...';
      case 'error':
        return '!';
      default:
        return '...';
    }
  };

  const getTypeIcon = () => {
    return file.type === 'file' ? 'FILE' : 'URL';
  };

  const getStatusText = () => {
    switch (file.status) {
      case 'completed':
        return 'Analysis complete';
      case 'analyzing':
        return file.job?.status ? formatJobStatus(file.job.status) : 'Queued for analysis';
      case 'uploading':
        return 'Uploading';
      case 'uploaded':
        return 'Uploaded';
      case 'error':
        return 'Error';
      default:
        return 'Ready';
    }
  };

  const riskLevel = file.job?.risk_level?.toLowerCase() || 'pending';
  const passwordLocked = ['uploading', 'analyzing', 'completed'].includes(file.status);
  const findings = collectFindings(file);
  const iocGroups = collectIOCGroups(file);
  const yaraHits = collectYARAHits(file);
  const scoreDisplay = getScoreDisplay(file);
  const iocTotal = countIOCs(iocGroups);
  const progressSteps = getProgressSteps(file);

  return (
    <div className={`file-list-item ${file.status}`}>
      <div className="file-info">
        <span className="file-icon">{getTypeIcon()}</span>
        <div className="file-details">
          <span className="file-name">{file.name}</span>
          <span className="file-type">
            {file.type === 'file' ? 'Local File' : 'URL'}
          </span>
        </div>
      </div>

      <div className="file-status">
        <span className="status-label">{getStatusText()}</span>
      </div>

      <div className="file-actions">
        <button
          onClick={() => onRemove(file.id)}
          className="remove-btn"
          title="Remove file"
        >
          ✕
        </button>

        {file.status === 'error' && (
          <button
            onClick={() => onRetry(file.id)}
            className="retry-btn"
            title="Retry upload"
          >
            🔄
          </button>
        )}

        {file.status === 'completed' && file.jobId && (
          <>
            <button
              onClick={() => onDownloadReport(file.jobId as string)}
              className="report-btn"
              title="Download JSON report"
            >
              JSON
            </button>
            <button
              onClick={() => onDownloadPDFReport(file.jobId as string)}
              className="report-btn"
              title="Download PDF report"
            >
              PDF
            </button>
          </>
        )}

        <span className="status-icon">{getStatusIcon()}</span>
      </div>

      {file.error && (
        <div className="error-message">{file.error}</div>
      )}

      {!file.jobId && (
        <label className="archive-password-field">
          <span>Archive password</span>
          <input
            type="password"
            value={file.archivePassword || ''}
            onChange={(event) => onArchivePasswordChange(file.id, event.target.value)}
            disabled={passwordLocked}
            placeholder="Optional"
            autoComplete="off"
          />
        </label>
      )}

      {file.jobId && (
        <div className="job-id">Job ID: {file.jobId}</div>
      )}

      {(file.jobId || file.status !== 'pending') && (
        <div className="job-progress" aria-label="Job progress">
          {progressSteps.map(step => (
            <div className={`progress-step ${step.state}`} key={step.key}>
              <span className="progress-dot" aria-hidden="true" />
              <span>{step.label}</span>
            </div>
          ))}
        </div>
      )}

      {file.jobId && (
        <div className="analysis-details">
          <div className="results-dashboard">
            <div className="dashboard-overview">
              <div className="score-panel">
                <span className="dashboard-label">Final Score</span>
                <div className="score-readout">
                  <strong>{scoreDisplay.final ?? 'Pending'}</strong>
                  {typeof scoreDisplay.final === 'number' && <span>/100</span>}
                </div>
                <div className="score-meter" aria-label="Final score">
                  <span style={{ width: `${scoreDisplay.percent}%` }} />
                </div>
                <div className="score-breakdown">
                  <span>Rule {formatScore(scoreDisplay.rule)}</span>
                  <span>AI {formatScore(scoreDisplay.ai)}</span>
                </div>
              </div>

              <div className={`risk-panel ${riskLevel}`}>
                <span className="dashboard-label">Risk</span>
                <strong>{file.job?.risk_level ? file.job.risk_level : 'Pending'}</strong>
                <span>{file.job ? formatJobStatus(file.job.status) : 'Waiting'}</span>
              </div>
            </div>

            <div className="dashboard-metrics">
              <div className="dashboard-metric">
                <span>YARA</span>
                <strong>{yaraHits.length}</strong>
              </div>
              <div className="dashboard-metric">
                <span>IOCs</span>
                <strong>{iocTotal}</strong>
              </div>
              <div className="dashboard-metric">
                <span>Findings</span>
                <strong>{findings.length}</strong>
              </div>
            </div>

            <div className="dashboard-sections">
              <section className="dashboard-section">
                <div className="dashboard-section-title">YARA Hits</div>
                {yaraHits.length > 0 ? (
                  <div className="yara-hit-list">
                    {yaraHits.slice(0, 6).map((hit, index) => (
                      <div className="yara-hit" key={`${hit.rule}-${index}`}>
                        <div className="yara-hit-heading">
                          <span className={`finding-severity ${hit.severity.toLowerCase()}`}>
                            {hit.severity}
                          </span>
                          <strong>{hit.rule}</strong>
                        </div>
                        {hit.description && (
                          <div className="yara-hit-description">{hit.description}</div>
                        )}
                        {hit.tags.length > 0 && (
                          <div className="yara-tags">
                            {hit.tags.slice(0, 5).map(tag => (
                              <span key={`${hit.rule}-${tag}`}>{tag}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                    {yaraHits.length > 6 && (
                      <div className="dashboard-more">{yaraHits.length - 6} more YARA hits</div>
                    )}
                  </div>
                ) : (
                  <div className="dashboard-empty">No YARA hits</div>
                )}
              </section>

              <section className="dashboard-section">
                <div className="dashboard-section-title">IOCs</div>
                {iocTotal > 0 ? (
                  <div className="ioc-groups">
                    {renderIOCGroup('URLs', iocGroups.urls)}
                    {renderIOCGroup('IPs', iocGroups.ips)}
                    {renderIOCGroup('Domains', iocGroups.domains)}
                  </div>
                ) : (
                  <div className="dashboard-empty">No IOCs found</div>
                )}
              </section>
            </div>
          </div>

          <div className="analysis-grid">
            <div className="analysis-field">
              <span>MIME</span>
              <strong>{file.job?.mime_type || 'Pending'}</strong>
            </div>
            <div className="analysis-field">
              <span>Size</span>
              <strong>{formatBytes(file.job?.size_bytes)}</strong>
            </div>
            <div className="analysis-field">
              <span>MD5</span>
              <code>{file.job?.md5_hash || 'Pending'}</code>
            </div>
            <div className="analysis-field">
              <span>SHA256</span>
              <code>{file.job?.sha256_hash || 'Pending'}</code>
            </div>
          </div>

          {findings.length > 0 && (
            <div className="findings-panel">
              <div className="findings-title">Analyzer Findings ({findings.length})</div>
              <div className="findings-list">
                {findings.slice(0, 8).map((finding, index) => (
                  <div className="finding-item" key={`${finding.analyzer}-${finding.type}-${index}`}>
                    <div className="finding-heading">
                      <span className={`finding-severity ${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </span>
                      <span className="finding-analyzer">{finding.analyzer}</span>
                      <span className="finding-type">{finding.type}</span>
                    </div>
                    <div className="finding-description">{finding.description}</div>
                  </div>
                ))}
              </div>
              {findings.length > 8 && (
                <div className="findings-more">{findings.length - 8} more findings</div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface DisplayFinding extends AnalyzerFinding {
  analyzer: string;
}

interface DisplayIOCGroups {
  urls: string[];
  ips: string[];
  domains: string[];
}

interface DisplayYARAHit {
  rule: string;
  severity: string;
  description: string;
  tags: string[];
}

interface ScoreDisplay {
  final: number | null;
  rule: number | null;
  ai: number | null;
  percent: number;
}

type ProgressState = 'done' | 'active' | 'pending' | 'error';

interface ProgressStep {
  key: string;
  label: string;
  state: ProgressState;
}

const renderIOCGroup = (label: string, values: string[]) => {
  if (values.length === 0) {
    return null;
  }

  return (
    <div className="ioc-group" key={label}>
      <span>{label}</span>
      <div className="ioc-chip-list">
        {values.slice(0, 6).map(value => (
          <code key={`${label}-${value}`}>{value}</code>
        ))}
      </div>
      {values.length > 6 && (
        <div className="dashboard-more">{values.length - 6} more</div>
      )}
    </div>
  );
};

const getProgressSteps = (file: FileInput): ProgressStep[] => {
  const jobStatus = file.job?.status;
  const hasJob = Boolean(file.jobId || file.job);
  const isUploading = file.status === 'uploading';
  const isQueued = hasJob && (!jobStatus || jobStatus === 'pending' || jobStatus === 'queued');
  const isRunning = file.status === 'analyzing' && jobStatus === 'running';
  const isComplete = file.status === 'completed' || jobStatus === 'completed';
  const isFailed = file.status === 'error' || jobStatus === 'failed';
  const needsPassword = jobStatus === 'needs_password';

  if (isFailed) {
    if (!hasJob) {
      return [
        { key: 'upload', label: 'Uploaded', state: 'error' },
        { key: 'queued', label: 'Queued', state: 'pending' },
        { key: 'analysis', label: 'Analysis', state: 'pending' },
        { key: 'result', label: 'Result', state: 'pending' },
      ];
    }

    return [
      { key: 'upload', label: 'Uploaded', state: hasJob ? 'done' : 'error' },
      { key: 'queued', label: 'Queued', state: hasJob ? 'done' : 'pending' },
      { key: 'analysis', label: 'Analysis', state: 'error' },
      { key: 'result', label: 'Result', state: 'pending' },
    ];
  }

  return [
    {
      key: 'upload',
      label: 'Uploaded',
      state: hasJob || isQueued || isRunning || isComplete ? 'done' : isUploading ? 'active' : 'pending',
    },
    {
      key: 'queued',
      label: needsPassword ? 'Password' : 'Queued',
      state: isComplete || isRunning ? 'done' : needsPassword || isQueued ? 'active' : 'pending',
    },
    {
      key: 'analysis',
      label: 'Analysis',
      state: isComplete ? 'done' : isRunning ? 'active' : 'pending',
    },
    {
      key: 'result',
      label: 'Result',
      state: isComplete ? 'done' : 'pending',
    },
  ];
};

const collectFindings = (file: FileInput): DisplayFinding[] => {
  const modules = file.job?.analysis_result?.results || [];

  return modules.flatMap(module =>
    (module.findings || [])
      .filter(finding => normalizeToken(finding.type) !== 'yara_match')
      .map(finding => ({
        ...finding,
        analyzer: module.analyzer,
      }))
  );
};

const collectYARAHits = (file: FileInput): DisplayYARAHit[] => {
  const modules = file.job?.analysis_result?.results || [];
  const hits: DisplayYARAHit[] = [];

  modules
    .filter(module => normalizeToken(module.analyzer) === 'yara')
    .forEach(module => {
      const matches = module.metadata?.matches;

      if (Array.isArray(matches) && matches.length > 0) {
        matches.forEach(match => {
          if (!isRecord(match)) {
            return;
          }

          const rule = stringValue(match.rule);
          if (!rule) {
            return;
          }

          hits.push({
            rule,
            severity: stringValue(match.severity) || 'info',
            description: stringValue(match.description),
            tags: stringArray(match.tags),
          });
        });
        return;
      }

      (module.findings || [])
        .filter(finding => normalizeToken(finding.type) === 'yara_match')
        .forEach(finding => {
          const rule = stringValue(finding.rule) || finding.description || 'YARA match';

          hits.push({
            rule,
            severity: finding.severity || 'info',
            description: finding.description || '',
            tags: stringArray(finding.tags),
          });
        });
    });

  return uniqueYARAHits(hits);
};

const collectIOCGroups = (file: FileInput): DisplayIOCGroups => {
  const topLevel = normalizeIOCCollection(file.job?.analysis_result?.iocs);
  if (countIOCs(topLevel) > 0) {
    return topLevel;
  }

  const modules = file.job?.analysis_result?.results || [];
  const groups: DisplayIOCGroups = {
    urls: [],
    ips: [],
    domains: [],
  };

  modules.forEach(module => {
    const moduleGroups = normalizeIOCCollection(module.iocs);
    groups.urls.push(...moduleGroups.urls);
    groups.ips.push(...moduleGroups.ips);
    groups.domains.push(...moduleGroups.domains);
  });

  return normalizeIOCGroups(groups);
};

const normalizeIOCCollection = (collection?: IOCCollection | null): DisplayIOCGroups => {
  if (!collection) {
    return {
      urls: [],
      ips: [],
      domains: [],
    };
  }

  return normalizeIOCGroups({
    urls: stringArray(collection.urls),
    ips: stringArray(collection.ips),
    domains: stringArray(collection.domains),
  });
};

const normalizeIOCGroups = (groups: DisplayIOCGroups): DisplayIOCGroups => ({
  urls: uniqueStrings(groups.urls),
  ips: uniqueStrings(groups.ips),
  domains: uniqueStrings(groups.domains),
});

const countIOCs = (groups: DisplayIOCGroups) =>
  groups.urls.length + groups.ips.length + groups.domains.length;

const getScoreDisplay = (file: FileInput): ScoreDisplay => {
  const final = numericScore(file.job?.score ?? file.job?.analysis_result?.scoring?.final_score);
  const rule = numericScore(file.job?.analysis_result?.scoring?.rule_score);
  const ai = numericScore(file.job?.ai_score ?? file.job?.analysis_result?.scoring?.ai_score);

  return {
    final,
    rule,
    ai,
    percent: final === null ? 0 : clampScore(final),
  };
};

const formatJobStatus = (status: string) =>
  status
    .split('_')
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');

const formatBytes = (value?: number | null) => {
  if (typeof value !== 'number') {
    return 'Pending';
  }

  if (value < 1024) {
    return `${value} B`;
  }

  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
};

const formatScore = (value: number | null) =>
  typeof value === 'number' ? `${value}/100` : 'Pending';

const numericScore = (value: unknown): number | null => {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return null;
  }

  return Math.round(value);
};

const clampScore = (value: number) => Math.max(0, Math.min(100, value));

const uniqueYARAHits = (hits: DisplayYARAHit[]) => {
  const seen = new Set<string>();
  const unique: DisplayYARAHit[] = [];

  hits.forEach(hit => {
    const key = `${hit.rule}:${hit.description}`;
    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    unique.push(hit);
  });

  return unique;
};

const uniqueStrings = (values: string[]) => {
  const seen = new Set<string>();
  const unique: string[] = [];

  values.forEach(value => {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      return;
    }

    seen.add(trimmed);
    unique.push(trimmed);
  });

  return unique;
};

const stringArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === 'string' && item.length > 0);
};

const stringValue = (value: unknown) =>
  typeof value === 'string' ? value : '';

const normalizeToken = (value: unknown) =>
  typeof value === 'string' ? value.toLowerCase().replace(/[\s-]+/g, '_') : '';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
