import { FC } from 'react';
import './UploadButton.css';

interface UploadButtonProps {
  onClick: () => void;
  disabled: boolean;
  isProcessing: boolean;
}

export const UploadButton: FC<UploadButtonProps> = ({
  onClick,
  disabled,
  isProcessing,
}) => {
  return (
    <button
      className="upload-button"
      onClick={onClick}
      disabled={disabled || isProcessing}
    >
      {isProcessing ? (
        <>
          <span className="spinner"></span>
          Uploading...
        </>
      ) : (
        <>
          <span className="upload-icon">🚀</span>
          Upload All Files
        </>
      )}
    </button>
  );
};
