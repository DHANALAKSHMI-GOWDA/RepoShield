
from backend.database import initialize_database
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.upload import router as upload_router

app = FastAPI(
    title="RepoShield API",
    description="Automated Repository Security Scanner",
    version="1.0.0"
)
@app.on_event("startup")
def startup_event():
    initialize_database()

# Allow the frontend to communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(upload_router)

@app.get("/")
def home():
    return {
        "message": "Welcome to RepoShield",
        "project": "Automated Repository Security Scanner",
        "status": "Running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": "RepoShield"
    }
