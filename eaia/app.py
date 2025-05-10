from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from typing import Dict, Any
# from eaia.controllers.setup_controller import router as setup_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Executive AI Assistant API",
    description="API for Executive AI Assistant",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
# app.include_router(setup_router)

class StatusResponse(BaseModel):
    status: str
    version: str
    details: Dict[str, Any]

@app.get("/")
async def root():
    """Root endpoint that returns a welcome message."""
    return {"message": "Welcome to Executive AI Assistant API"}

@app.get("/status", response_model=StatusResponse)
async def get_status():
    """
    Get the current status of the API and its components.
    
    Returns:
        StatusResponse: Object containing status information
    """
    try:
        # You can add more detailed status checks here
        status_info = {
            "status": "operational",
            "version": "1.0.0",
            "details": {
                "api": "running",
                "gmail_connection": "connected",
                "last_check": "2024-03-19T00:00:00Z"
            }
        }
        return StatusResponse(**status_info)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error retrieving status information"
        )

@app.get("/health")
async def health_check():
    """
    Simple health check endpoint.
    
    Returns:
        dict: Health status
    """
    return {"status": "healthy"}

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)
