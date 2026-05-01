import { FC } from 'react';
import { FileInput } from '../types';
import { FileListItem } from './FileListItem';
import './FileList.css';

interface FileListProps {
  files: FileInput[];
  onPasswordChange: (id: string, password: string) => void;
  onRemove: (id: string) => void;
}

export const FileList: FC<FileListProps> = ({
  files,
  onPasswordChange,
  onRemove,
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
            onPasswordChange={onPasswordChange}
            onRemove={onRemove}
          />
        ))}
      </div>
    </div>
  );
};
