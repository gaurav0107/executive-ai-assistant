# from eaia.gmail_manager.auth import get_credentials
from eaia.repository.store_init import user_config_store, user_preference_store
import logging
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
from eaia.gmail_manager.auth import get_user_credentials
import traceback
logger = logging.getLogger(__name__)


class UserSetupRequest(BaseModel):
    esp: str
    email: EmailStr
    ea_email: EmailStr
    name: str
    ea_name: str

class UserSetupResponse(BaseModel):
    status: str
    message: str
    details: Dict[str, Any]


def setup_user(user_setup_request: UserSetupRequest) -> UserSetupResponse:
    """Setup user configuration and store it."""
    try:

        user_config_store.put(user_setup_request.email, user_setup_request.json())

        # Setup user credentials
        get_user_credentials(user_setup_request.email)

        # Setup EA credentials
        get_user_credentials(user_setup_request.ea_email)
       
        
        return UserSetupResponse(
            status="success",
            message="User setup completed successfully",
            details={
                "esp": user_setup_request.esp,
                "email": user_setup_request.email,
                "ea_email": user_setup_request.ea_email,
                "name": user_setup_request.name,
                "ea_name": user_setup_request.ea_name
            }
        )
    except Exception as e:
        traceback.print_exc()
        raise Exception(f"Error during user setup: {str(e)}")

def get_user_setup_status(email: str) -> UserSetupResponse:
    """Get user setup status from store."""
    try:
        config = user_config_store.get(f"config:{email}")
        if not config:
            return UserSetupResponse(
                status="error",
                message="User not found",
                details={"email": email, "setup_complete": False}
            )
            
        return UserSetupResponse(
            status="success",
            message="Setup status retrieved successfully",
            details=config
        )
    except Exception as e:
        raise Exception(f"Error retrieving setup status: {str(e)}")
