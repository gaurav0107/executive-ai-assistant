from fastapi import APIRouter, HTTPException, BackgroundTasks, Request
from pydantic import BaseModel, EmailStr
from typing import Optional
import logging
from eaia.gmail_manager.setup import (
    UserSetupRequest,
    UserSetupResponse,
    setup_user as setup_user_func,
    get_user_setup_status,
    handle_oauth2callback_func
)
from google_auth_oauthlib.flow import Flow
import json
from eaia.repository.store_init import user_token_store
import traceback
# Configure logging
logger = logging.getLogger(__name__)



# Create router
router = APIRouter(
    prefix="/setup",
    tags=["setup"],
    responses={404: {"description": "Not found"}},
)

@router.post("", response_model=UserSetupResponse)
def setup_user(request: UserSetupRequest, background_tasks: BackgroundTasks):
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
        return setup_user_func(request, background_tasks)

    except Exception as e:
        logger.error(f"Unexpected error during user setup: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.get("/status/{email}", response_model=UserSetupResponse)
def get_setup_status(email: EmailStr):
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

@router.get('/oauth2callback')
def oauth2callback(request: Request):
    state = request.query_params.get('state')
    code = request.query_params.get('code')
    url = request.url
    try:    
        return handle_oauth2callback_func(state=state, code=code, url=url)
    except Exception as e:
        logger.error(f"Error handling OAuth2 callback: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
