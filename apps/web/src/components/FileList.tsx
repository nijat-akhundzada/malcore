import { FC } from 'react';
import { FileInput } from '../types';
import { FileListItem } from './FileListItem';
import './FileList.css';

interface FileListProps {
  files: FileInput[];
  onRemove: (id: string) => void;
  onRetry: (id: string) => void;
  onArchivePasswordChange: (id: string, archivePassword: string) => void;
  onDownloadReport: (jobId: string) => void;
  onDownloadPDFReport: (jobId: string) => void;
}

export const FileList: FC<FileListProps> = ({
  files,
  onRemove,
  onRetry,
  onArchivePasswordChange,
  onDownloadReport,
  onDownloadPDFReport,
}) => {
  if (files.length === 0) {
    return null;
  }

  const pendingCount = files.filter(file => file.status === 'pending').length;
  const activeCount = files.filter(file => ['uploading', 'uploaded', 'analyzing'].includes(file.status)).length;
  const completedCount = files.filter(file => file.status === 'completed').length;
  const errorCount = files.filter(file => file.status === 'error').length;

  return (
    <div className="file-list-container">
      <div className="file-list-header">
        <h3>Jobs ({files.length})</h3>
        <div className="job-counts" aria-label="Job status summary">
          <span>Ready {pendingCount}</span>
          <span>Active {activeCount}</span>
          <span>Done {completedCount}</span>
          <span>Failed {errorCount}</span>
        </div>
      </div>
      <div className="file-list">
        {files.map(file => (
          <FileListItem
            key={file.id}
            file={file}
            onRemove={onRemove}
            onRetry={onRetry}
            onArchivePasswordChange={onArchivePasswordChange}
            onDownloadReport={onDownloadReport}
            onDownloadPDFReport={onDownloadPDFReport}
          />
        ))}
      </div>
    </div>
  );
};
