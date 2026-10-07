# Ghost Trackers — AegisSOC Defensive Operations Suite

[![Security Standards](https://img.shields.io/badge/Security-Defensive%20Only-emerald.svg)](#safety-standard)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg?logo=react)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.0+-646CFF.svg?logo=vite)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4+-38B2AC.svg?logo=tailwind-css)](https://tailwindcss.com)

The project source code and full file tree are located in [`aegissoc/`](./aegissoc/):

```text
aegissoc/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   ├── core/
│   │   ├── models/
│   │   ├── services/
│   │   └── main.py
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   ├── package.json
│   ├── tailwind.config.js
│   └── vite.config.js
├── docker-compose.yml
└── README.md
```

To run the application, navigate to `aegissoc/` or use the quickstart scripts:
- Backend: `cd aegissoc/backend && uvicorn app.main:app --port 8000`
- Frontend: `cd aegissoc/frontend && npm run dev`
- Tests: `cd aegissoc/backend && pytest tests -v`
