from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel, EmailStr
import logging
from typing import Dict, Any, Optional

from eaia.gmail_manager.auth import auth_service

# Configure logging
logger = logging.getLogger(__name__)

class CallbackController:
    """Controller class for handling setup-related endpoints."""
    
    def __init__(self):
        """Initialize the setup controller with its router."""
        self.router = APIRouter(
            prefix="/setup",
            tags=["setup"],
            responses={
                404: {"description": "Not found"},
                500: {"description": "Internal server error"}
            },
        )
        self._register_routes()

    def _register_routes(self) -> None:
        """Register all routes for the setup controller."""
    
        self.router.add_api_route(
            "/oauth2callback",
            self.oauth2callback,
            methods=["GET"],
            summary="OAuth2 callback",
            description="Handle OAuth2 callback from Google.",
            responses={
                200: {
                    "description": "Successful OAuth2 callback",
                    "content": {
                        "application/json": {
                            "example": {
                                "status": "success",
                                "message": "Gmail connected successfully!"
                            }
                        }
                    }
                }
            }
        )

    async def oauth2callback(self, request: Request) -> Dict[str, Any]:
        """
        Handle OAuth2 callback from Google.
        """
        try:
            return auth_service.handle_oauth2callback(
                state=request.query_params.get('state'),
                code=request.query_params.get('code'),
                url=str(request.url)
            )
        except Exception as e:
            logger.error(f"Error handling OAuth2 callback: {e}")
            raise HTTPException(
                status_code=500,
                detail=str(e)
            )

# Create controller instance
callback_controller = CallbackController()

# Export router
router = callback_controller.router
