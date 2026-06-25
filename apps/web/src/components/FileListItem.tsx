import { FC } from 'react';
import { FileInput } from '../types';
import './FileListItem.css';

interface FileListItemProps {
  file: FileInput;
  onRemove: (id: string) => void;
  onRetry: (id: string) => void;
}

export const FileListItem: FC<FileListItemProps> = ({
  file,
  onRemove,
  onRetry,
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
        </div>
      )}
    </div>
  );
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
