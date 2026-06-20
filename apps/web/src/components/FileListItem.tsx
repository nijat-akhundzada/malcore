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
      case 'uploaded':
        return '✅';
      case 'uploading':
        return '⏳';
      case 'error':
        return '❌';
      default:
        return '⏳';
    }
  };

  const getTypeIcon = () => {
    return file.type === 'file' ? '📁' : '🌐';
  };

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
    </div>
  );
};
