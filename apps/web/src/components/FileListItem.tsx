import { FC } from 'react';
import { AnalyzerFinding, FileInput, IOCCollection } from '../types';
import './FileListItem.css';

interface FileListItemProps {
  file: FileInput;
  onRemove: (id: string) => void;
  onRetry: (id: string) => void;
  onArchivePasswordChange: (id: string, archivePassword: string) => void;
}

export const FileListItem: FC<FileListItemProps> = ({
  file,
  onRemove,
  onRetry,
  onArchivePasswordChange,
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
  const iocs = collectIOCs(file);

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

      {file.jobId && (
        <div className="analysis-details">
          <div className="analysis-summary">
            <span className={`risk-badge ${riskLevel}`}>
              {file.job?.risk_level ? file.job.risk_level : 'pending'}
            </span>
            <span className="score-value">
              Score {file.job?.score ?? 'pending'}
              {typeof file.job?.score === 'number' ? '/100' : ''}
            </span>
            <span className="ai-score-value">
              AI {file.job?.ai_score ?? 'pending'}
              {typeof file.job?.ai_score === 'number' ? '/100' : ''}
            </span>
            <span className="job-status">{file.job ? formatJobStatus(file.job.status) : 'Waiting'}</span>
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

          {iocs.length > 0 && (
            <div className="iocs-panel">
              <div className="iocs-title">Indicators ({iocs.length})</div>
              <div className="iocs-list">
                {iocs.slice(0, 12).map((ioc, index) => (
                  <div className="ioc-item" key={`${ioc.type}-${ioc.value}-${index}`}>
                    <span className={`ioc-type ${ioc.type}`}>{ioc.label}</span>
                    <code>{ioc.value}</code>
                  </div>
                ))}
              </div>
              {iocs.length > 12 && (
                <div className="iocs-more">{iocs.length - 12} more indicators</div>
              )}
            </div>
          )}

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

type IOCKey = 'urls' | 'ips' | 'domains';

interface DisplayIOC {
  type: IOCKey;
  label: string;
  value: string;
}

const IOC_LABELS: Record<IOCKey, string> = {
  urls: 'URL',
  ips: 'IP',
  domains: 'DOMAIN',
};

const collectFindings = (file: FileInput): DisplayFinding[] => {
  const modules = file.job?.analysis_result?.results || [];

  return modules.flatMap(module =>
    (module.findings || []).map(finding => ({
      ...finding,
      analyzer: module.analyzer,
    }))
  );
};

const collectIOCs = (file: FileInput): DisplayIOC[] => {
  const topLevel = collectIOCCollection(file.job?.analysis_result?.iocs);
  if (topLevel.length > 0) {
    return topLevel;
  }

  const modules = file.job?.analysis_result?.results || [];
  const seen = new Set<string>();
  const values: DisplayIOC[] = [];

  modules.forEach(module => {
    collectIOCCollection(module.iocs).forEach(ioc => {
      const key = `${ioc.type}:${ioc.value}`;
      if (seen.has(key)) {
        return;
      }

      seen.add(key);
      values.push(ioc);
    });
  });

  return values;
};

const collectIOCCollection = (collection?: IOCCollection | null): DisplayIOC[] => {
  if (!collection) {
    return [];
  }

  return (Object.keys(IOC_LABELS) as IOCKey[]).flatMap(type => {
    const values = collection[type];
    if (!Array.isArray(values)) {
      return [];
    }

    return values
      .filter((value): value is string => typeof value === 'string' && value.length > 0)
      .map(value => ({
        type,
        label: IOC_LABELS[type],
        value,
      }));
  });
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
