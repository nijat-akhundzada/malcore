import { FC, useRef, useState } from 'react';
import { FileInput } from '../types';
import './FileUploadZone.css';

interface FileUploadZoneProps {
  onFileSelect: (file: File) => void;
}

export const FileUploadZone: FC<FileUploadZoneProps> = ({ onFileSelect }) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    
    const droppedFiles = Array.from(e.dataTransfer.files);
    droppedFiles.forEach(file => onFileSelect(file));
  };

  const handleClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || []);
    selectedFiles.forEach(file => onFileSelect(file));
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div
      className={`upload-zone ${isDragOver ? 'drag-over' : ''}`}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={handleClick}
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={handleFileInput}
        style={{ display: 'none' }}
      />
      <div className="upload-icon">📁</div>
      <div className="upload-text">
        <p className="primary-text">
          {isDragOver ? 'Drop files here' : 'Drag & drop files here'}
        </p>
        <p className="secondary-text">or click to browse</p>
      </div>
      <p className="supported-types">Supports all file types</p>
    </div>
  );
};
