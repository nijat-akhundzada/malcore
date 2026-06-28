import { FC, useState } from 'react';
import './UrlInputForm.css';

interface UrlInputFormProps {
  onUrlAdd: (url: string, archivePassword?: string) => void;
}

export const UrlInputForm: FC<UrlInputFormProps> = ({ onUrlAdd }) => {
  const [url, setUrl] = useState('');
  const [archivePassword, setArchivePassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    onUrlAdd(url.trim(), archivePassword || undefined);
    setUrl('');
    setArchivePassword('');
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
          type="password"
          placeholder="Archive password"
          value={archivePassword}
          onChange={(e) => setArchivePassword(e.target.value)}
          className="url-input"
          autoComplete="off"
        />
      </div>
      <button type="submit" className="add-url-btn">
        Add URL
      </button>
    </form>
  );
};
