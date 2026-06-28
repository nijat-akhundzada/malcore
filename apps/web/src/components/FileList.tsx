import { FC } from 'react';
import { FileInput } from '../types';
import { FileListItem } from './FileListItem';
import './FileList.css';

interface FileListProps {
  files: FileInput[];
  onRemove: (id: string) => void;
  onRetry: (id: string) => void;
  onArchivePasswordChange: (id: string, archivePassword: string) => void;
}

export const FileList: FC<FileListProps> = ({
  files,
  onRemove,
  onRetry,
  onArchivePasswordChange,
}) => {
  if (files.length === 0) {
    return null;
  }

  return (
    <div className="file-list-container">
      <div className="file-list-header">
        <h3>Files ({files.length})</h3>
      </div>
      <div className="file-list">
        {files.map(file => (
          <FileListItem
            key={file.id}
            file={file}
            onRemove={onRemove}
            onRetry={onRetry}
            onArchivePasswordChange={onArchivePasswordChange}
          />
        ))}
      </div>
    </div>
  );
};
