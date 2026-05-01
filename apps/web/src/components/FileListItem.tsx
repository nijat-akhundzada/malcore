import { FC } from 'react';
import { FileInput } from '../types';
import './FileListItem.css';

interface FileListItemProps {
  file: FileInput;
  onPasswordChange: (id: string, password: string) => void;
  onRemove: (id: string) => void;
}

export const FileListItem: FC<FileListItemProps> = ({
  file,
  onPasswordChange,
  onRemove,
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
        <div className="password-input-wrapper">
          <input
            type="password"
            placeholder="Password (if protected)"
            value={file.password || ''}
            onChange={(e) => onPasswordChange(file.id, e.target.value)}
            className="password-input"
          />
          <span className="password-icon">🔒</span>
        </div>
        
        <button
          onClick={() => onRemove(file.id)}
          className="remove-btn"
          title="Remove file"
        >
          ✕
        </button>
        
        <span className="status-icon">{getStatusIcon()}</span>
      </div>
      
      {file.error && (
        <div className="error-message">{file.error}</div>
      )}
    </div>
  );
};
