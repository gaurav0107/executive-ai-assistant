from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel, EmailStr
import logging
from typing import Dict, Any, Optional

from eaia.gmail_manager.setup import (
    UserSetupRequest,
    UserSetupResponse,
    setup_service
)

# Configure logging
logger = logging.getLogger(__name__)

class SetupController:
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
            "/users/{email}",
            self.get_user_setup,
            methods=["GET"],
            response_model=UserSetupResponse,
            summary="Retrieve user setup status",
            description="Retrieve the setup status for a user.",
            responses={
                200: {
                    "description": "Successful operation",
                    "content": {
                        "application/json": {
                            "example": {
                                "status": "success",
                                "message": "User setup completed successfully",
                                "details": {
                                    "email": "user@example.com",
                                    "ea_email": "ea@example.com",
                                    "setup_complete": True
                                }
                            }
                        }
                    }
                },
                404: {
                    "description": "User not found",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "User not found"
                            }
                        }
                    }
                }
            }
        )
        
        # POST endpoint for creating/updating user setup
        self.router.add_api_route(
            "/users/{email}",
            self.create_user_setup,
            methods=["POST"],
            response_model=UserSetupResponse,
            summary="Create or update user setup",
            description="Create or update user setup with email preferences and credentials.",
            responses={
                200: {
                    "description": "Successful operation",
                    "content": {
                        "application/json": {
                            "example": {
                                "status": "success",
                                "message": "User setup completed successfully",
                                "details": {
                                    "email": "user@example.com",
                                    "ea_email": "ea@example.com",
                                    "setup_complete": True
                                }
                            }
                        }
                    }
                },
                400: {
                    "description": "Bad request",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "Email in path must match email in request body"
                            }
                        }
                    }
                }
            }
        )

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

    async def get_user_setup(
        self,
        email: EmailStr
    ) -> UserSetupResponse:
        """
        Retrieve the setup status for a user.
        """
        try:
            return setup_service.get_user_status(email)
        except Exception as e:
            logger.error(f"Error retrieving setup status: {e}")
            raise HTTPException(
                status_code=500,
                detail=str(e)
            )

    async def create_user_setup(
        self,
        email: EmailStr,
        request: UserSetupRequest,
        background_tasks: BackgroundTasks
    ) -> UserSetupResponse:
        """
        Create or update user setup with email preferences and credentials.
        """
        try:
            if email != request.email:
                raise HTTPException(
                    status_code=400,
                    detail="Email in path must match email in request body"
                )
            return setup_service.setup_user(request, background_tasks)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating/updating user setup: {e}")
            raise HTTPException(
                status_code=500,
                detail=str(e)
            )

    async def oauth2callback(self, request: Request) -> Dict[str, Any]:
        """
        Handle OAuth2 callback from Google.
        """
        try:
            return setup_service.handle_oauth2callback(
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
setup_controller = SetupController()

# Export router
router = setup_controller.router
