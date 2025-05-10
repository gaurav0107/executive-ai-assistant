# from eaia.gmail_manager.auth import get_credentials
from eaia.repository.store_init import user_config_store, user_preference_store, user_token_store
import logging
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
from eaia.gmail_manager.auth import auth_service
import traceback
logger = logging.getLogger(__name__)
from fastapi import BackgroundTasks
import json
from enum import Enum



class UserSetupRequest(BaseModel):
    """Model for user setup request."""
    email: EmailStr
    esp: str
    ea_email: EmailStr
    name: str
    ea_name: str

class UserSetupResponse(BaseModel):
    """Model for user setup response."""
    status: str
    message: str
    user: UserSetupRequest
    user_auth_status: str
    ea_auth_status: str


class SetupService:
    """Service class for handling user setup operations."""
    
    @staticmethod
    def _store_user_config(user_setup_request: UserSetupRequest) -> None:
        """Store user configuration in the config store."""
        logger.info(f"creating user config for {user_setup_request.email}")
        try:
            user_config_store.put(
                user_setup_request.email,
                user_setup_request.json()
            )
        except Exception as e:
            logger.error(f"Error storing user config: {e}")
            raise Exception(f"Failed to store user configuration: {str(e)}")

    @staticmethod
    def _schedule_auth_emails(
        background_tasks: BackgroundTasks,
        user_email: EmailStr,
        ea_email: EmailStr
    ) -> None:
        """Schedule authentication emails to be sent in the background."""
        try:
            # Schedule user auth email
            background_tasks.add_task(
                auth_service.send_auth_email,
                user_email
            )
            
            # Schedule EA auth email
            background_tasks.add_task(
                auth_service.send_auth_email,
                ea_email
            )
        except Exception as e:
            logger.error(f"Error scheduling auth emails: {e}")
            raise Exception(f"Failed to schedule authentication emails: {str(e)}")

    @classmethod
    def setup_user(
        cls,
        user_setup_request: UserSetupRequest,
        background_tasks: BackgroundTasks
    ) -> UserSetupResponse:
        """
        Setup a new user with their email preferences and credentials.
        
        Args:
            user_setup_request: User setup information
            background_tasks: FastAPI background tasks
            
        Returns:
            UserSetupResponse: Setup status and details
        """
        try:
            # Store user configuration
            cls._store_user_config(user_setup_request)
            
            # Schedule authentication emails
            cls._schedule_auth_emails(
                background_tasks,
                user_setup_request.email,
                user_setup_request.ea_email
            )
            
            return UserSetupResponse(
                status="success",
                message="User setup completed successfully",
                user=user_setup_request
            )
            
        except Exception as e:
            logger.error(f"Error during user setup: {e}")
            traceback.print_exc()
            raise Exception(f"Error during user setup: {str(e)}")

    @classmethod
    def get_user_status(cls, email: str) -> UserSetupResponse:
        """
        Get the setup status for a user.
        
        Args:
            email: User's email address
            
        Returns:
            UserSetupResponse: Current setup status and details
        """
        try:
            config = user_config_store.get(email)
            if not config:
                return UserSetupResponse(
                    status="error",
                    message="User not found",
                    user=UserSetupRequest(
                        email=email,
                        setup_complete=False
                    )
                )
            
            
            config = json.loads(config)
            
            user_auth_status = auth_service.check_auth_status(email)
            ea_auth_status = auth_service.check_auth_status(config["ea_email"])
            return UserSetupResponse(
                status="success",
                message="Setup status retrieved successfully",
                user=UserSetupRequest(**config),
                user_auth_status=user_auth_status,
                ea_auth_status=ea_auth_status
            )
            
        except Exception as e:
            logger.error(f"Error retrieving setup status: {e}")
            raise Exception(f"Error retrieving setup status: {str(e)}")

    @classmethod
    def handle_oauth2callback(cls, state: str, code: str, url: str) -> Dict:
        """
        Handle OAuth2 callback and store credentials.
        
        Args:
            state: OAuth state parameter
            code: Authorization code
            url: Callback URL
            
        Returns:
            Dict: Response containing status and message
        """
        try:
            return auth_service.handle_oauth2callback(
                state=state,
                code=code,
                url=url
            )
        except Exception as e:
            logger.error(f"Error handling OAuth2 callback: {e}")
            traceback.print_exc()
            raise Exception(f"Error handling OAuth2 callback: {str(e)}")

# Export the service instance
setup_service = SetupService()
