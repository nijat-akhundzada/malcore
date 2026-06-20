import { FC, useState } from 'react';
import './UrlInputForm.css';

interface UrlInputFormProps {
  onUrlAdd: (url: string) => void;
}

export const UrlInputForm: FC<UrlInputFormProps> = ({ onUrlAdd }) => {
  const [url, setUrl] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    
    onUrlAdd(url.trim());
    setUrl('');
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
      <button type="submit" className="add-url-btn">
        Add URL
      </button>
    </form>
  );
};
