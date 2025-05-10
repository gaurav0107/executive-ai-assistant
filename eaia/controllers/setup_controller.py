from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from typing import Optional
import logging
from eaia.gmail_manager.setup import (
    UserSetupRequest,
    UserSetupResponse,
    setup_user as setup_user_func,
    get_user_setup_status
)

# Configure logging
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(
    prefix="/setup",
    tags=["setup"],
    responses={404: {"description": "Not found"}},
)

@router.post("/user", response_model=UserSetupResponse)
async def setup_user(request: UserSetupRequest):
    """
    Setup a new user with their email preferences and credentials.
    
    Args:
        request: UserSetupRequest containing user setup information
        
    Returns:
        UserSetupResponse: Setup status and details
    """
    try:
        # Validate ESP
        if request.esp.lower() not in ["gmail"]:
            raise HTTPException(
                status_code=400,
                detail="Unsupported email service provider. Currently only Gmail is supported."
            )

        # Setup user
        return setup_user_func(request)

    except Exception as e:
        logger.error(f"Unexpected error during user setup: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.get("/status/{email}", response_model=UserSetupResponse)
async def get_setup_status(email: EmailStr):
    """
    Get the setup status for a user.
    
    Args:
        email: Email address of the user
        
    Returns:
        UserSetupResponse: Current setup status and details
    """
    try:
        return get_user_setup_status(email)
    except Exception as e:
        logger.error(f"Error retrieving setup status: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
