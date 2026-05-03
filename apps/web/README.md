# MALCORE Web

Frontend for the MALCORE malware analysis sandbox.

## Features

- **File Upload**: Drag and drop or browse to submit local files for analysis
- **URL Input**: Add remote file URLs for analysis workflows
- **Password Protection**: Support for password-protected samples
- **Modern UI**: Clean, responsive interface built with React
- **TypeScript**: Full type safety

## Tech Stack

- **Frontend**: React 18 + TypeScript + Vite
- **Backend**: Go API service in `services/api`
- **Styling**: Custom CSS

## Getting Started

### Prerequisites

- Node.js 18+
- Go 1.21+

### Frontend Setup

```bash
cd apps/web
npm install
npm run dev
```

The frontend runs on `http://localhost:5173` by default.

### Backend Setup

```bash
cd services/api
go run ./cmd/api
```

The backend runs on `http://localhost:8080`.

## Project Structure

```text
malcore/
└── apps/
    └── web/
        ├── src/
        │   ├── components/
        │   ├── hooks/
        │   ├── services/
        │   ├── App.tsx
        │   ├── main.tsx
        │   └── types.ts
        ├── index.html
        ├── package.json
        └── vite.config.ts
```

## API Endpoints

- `POST /api/upload` - Upload a file or URL for analysis
- `GET /api/upload/:id/status` - Get analysis job status

## Next Steps

1. Improve analyst workflow and branding consistency
2. Connect frontend flows to live API endpoints
3. Add richer job status and report views
4. Expand sample validation and analysis feedback
