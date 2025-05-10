from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from typing import Dict, Any
from datetime import datetime
import uvicorn

from eaia.controllers.setup_controller import router as setup_router
from eaia.repository.store_init import user_config_store, user_token_store, user_preference_store

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StatusResponse(BaseModel):
    """Model for API status response."""
    status: str
    version: str
    details: Dict[str, Any]

class AppConfig:
    """Configuration class for the FastAPI application."""
    
    TITLE = "Executive AI Assistant API"
    DESCRIPTION = "API for Executive AI Assistant"
    VERSION = "1.0.0"
    
    CORS_CONFIG = {
        "allow_origins": ["*"],  # In production, replace with specific origins
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }

class AppController:
    """Controller class for handling main application endpoints."""
    
    def __init__(self, app: FastAPI):
        """Initialize the controller with the FastAPI app instance."""
        self.app = app
        self._register_routes()
        self._configure_middleware()
    
    def _configure_middleware(self) -> None:
        """Configure middleware for the application."""
        self.app.add_middleware(
            CORSMiddleware,
            **AppConfig.CORS_CONFIG
        )
    
    def _register_routes(self) -> None:
        """Register all routes for the application."""
        self.app.include_router(setup_router)
        
        self.app.add_api_route(
            "/",
            self.root,
            methods=["GET"],
            summary="Root endpoint",
            description="Returns a welcome message."
        )
        
        self.app.add_api_route(
            "/status",
            self.get_status,
            methods=["GET"],
            response_model=StatusResponse,
            summary="Get API status",
            description="Get the current status of the API and its components."
        )
        
        self.app.add_api_route(
            "/health",
            self.health_check,
            methods=["GET"],
            summary="Health check",
            description="Simple health check endpoint."
        )
    
    async def root(self) -> Dict[str, str]:
        """
        Root endpoint that returns a welcome message.
        
        Returns:
            Dict[str, str]: Welcome message
        """
        return {"message": f"Welcome to {AppConfig.TITLE}"}
    
    async def get_status(self) -> StatusResponse:
        """
        Get the current status of the API and its components.
        
        Returns:
            StatusResponse: Object containing status information
            
        Raises:
            HTTPException: If status retrieval fails
        """
        try:
            status_info = {
                "status": "operational",
                "version": AppConfig.VERSION,
                "details": {
                    "api": "running",
                    "gmail_connection": "connected",
                    "last_check": datetime.utcnow().isoformat() + "Z"
                }
            }
            return StatusResponse(**status_info)
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            raise HTTPException(
                status_code=500,
                detail="Error retrieving status information"
            )
    
    async def health_check(self) -> Dict[str, str]:
        """
        Simple health check endpoint.
        
        Returns:
            Dict[str, str]: Health status
        """
        return {"status": "healthy"}

def create_app() -> FastAPI:
    """
    Create and configure the FastAPI application.
    
    Returns:
        FastAPI: Configured FastAPI application instance
    """
    app = FastAPI(
        title=AppConfig.TITLE,
        description=AppConfig.DESCRIPTION,
        version=AppConfig.VERSION
    )
    
    # Initialize controller
    AppController(app)
    
    return app

app = create_app()

def run_app() -> None:
    """Run the FastAPI application using uvicorn."""
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    run_app()
