import { FC, useState } from 'react';
import { FileInput } from '../types';
import './UrlInputForm.css';

interface UrlInputFormProps {
  onUrlAdd: (url: string, name?: string) => void;
}

export const UrlInputForm: FC<UrlInputFormProps> = ({ onUrlAdd }) => {
  const [url, setUrl] = useState('');
  const [fileName, setFileName] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    
    onUrlAdd(url.trim(), fileName.trim() || undefined);
    setUrl('');
    setFileName('');
  };

  return (
    <form className="url-input-form" onSubmit={handleSubmit}>
      <div className="form-title">🌐 Add File from URL</div>
      <div className="form-group">
        <input
          type="url"
          placeholder="https://example.com/file.pdf"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="url-input"
          required
        />
      </div>
      <div className="form-group">
        <input
          type="text"
          placeholder="File name (optional)"
          value={fileName}
          onChange={(e) => setFileName(e.target.value)}
          className="name-input"
        />
      </div>
      <button type="submit" className="add-url-btn">
        Add URL
      </button>
    </form>
  );
};
