"""User controller module for handling user operations."""
from fastapi import APIRouter, HTTPException
from pydantic import EmailStr
import logging
from typing import Dict, Any

from eaia.models.user import User

# Configure logging
logger = logging.getLogger(__name__)

class UserController:
    """Controller class for handling user-related endpoints."""
    
    def __init__(self):
        """Initialize the user controller with its router."""
        self.router = APIRouter(
            prefix="/users",
            tags=["users"],
            responses={
                404: {"description": "User not found"},
                500: {"description": "Internal server error"}
            },
        )
        self._register_routes()

    def _register_routes(self) -> None:
        """Register all routes for the user controller."""
        self.router.add_api_route(
            "/{email}",
            self.get_user,
            methods=["GET"],
            response_model=User,
            summary="Get user details",
            description="Retrieve user details by email address."
        )
        
        self.router.add_api_route(
            "/{email}",
            self.create_user,
            methods=["POST"],
            response_model=User,
            summary="Create new user",
            description="Create a new user. Returns error if user already exists."
        )

    async def get_user(self, email: EmailStr) -> Dict[str, Any]:
        """Get user details by email address."""
        try:
            user = User.get_by_email(email)
            if not user:
                raise HTTPException(
                    status_code=404,
                    detail=f"User with email {email} not found"
                )
            return user
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error retrieving user: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Error retrieving user: {str(e)}"
            )

    async def create_user(
        self,
        email: EmailStr,
        user_request: User
    ) -> Dict[str, Any]:
        """Create new user. Returns error if user already exists."""
        try:
            if email != user_request.email:
                raise HTTPException(
                    status_code=400,
                    detail="Email in path must match email in request body"
                )
         
            # Create new user
            user_request.save()
            return user_request
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Error creating user: {str(e)}"
            )

# Create controller instance
user_controller = UserController()

# Export router
router = user_controller.router
