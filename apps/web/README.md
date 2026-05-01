# Zorbox - File Upload Platform

A modern web platform for uploading and managing files from various sources.

## Features

- **File Upload**: Drag & drop or browse to upload local files
- **URL Input**: Add files from remote URLs
- **Password Protection**: Support for password-protected files
- **Modern UI**: Clean, responsive interface built with React
- **TypeScript**: Full type safety

## Tech Stack

- **Frontend**: React 18 + TypeScript + Vite
- **Backend**: Go (to be implemented)
- **Styling**: Custom CSS

## Getting Started

### Prerequisites

- Node.js 18+
- Go 1.21+ (for backend)

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend will run on `http://localhost:3000`

### Backend Setup (Coming Soon)

```bash
cd backend
go run main.go
```

The backend will run on `http://localhost:8080`

## Project Structure

```
zorbox/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── FileUploadZone.tsx
│   │   │   ├── UrlInputForm.tsx
│   │   │   ├── FileList.tsx
│   │   │   ├── FileListItem.tsx
│   │   │   └── UploadButton.tsx
│   │   ├── hooks/
│   │   │   └── useFileUploader.ts
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── types.ts
│   ├── package.json
│   └── vite.config.ts
└── backend/ (to be created)
```

## API Endpoints (Planned)

- `POST /api/upload` - Upload file or URL
- `GET /api/upload/:id/status` - Get upload status

## Next Steps

1. ✅ Frontend UI completed
2. ⏳ Backend implementation with Go
3. ⏳ File processing sandbox environments
4. ⏳ File type validation
5. ⏳ Download manager for URLs
