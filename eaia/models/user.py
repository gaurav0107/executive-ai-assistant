"""User model module for handling user business logic."""
from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr
import logging
import json

from eaia.repository.store_init import user_config_store, user_token_store
from eaia.gmail_manager.auth import auth_service

logger = logging.getLogger(__name__)


class EA(BaseModel):
    """Executive Assistant model."""
    ea_email: EmailStr
    ea_name: str

class User(BaseModel):
    """User model for business logic."""
    email: EmailStr
    name: str
    esp: str
    ea: EA
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    user_staus: Optional[str] = None
    ea_satus: Optional[str] = None

    @classmethod
    def get_by_email(cls, email: EmailStr) -> Optional['User']:
        """Get user by email address."""
        try:
            user_data = user_config_store.get(email)
            if not user_data:
                return None
            
            # Parse JSON string from Redis
            user_dict = json.loads(user_data)
            
            # Convert datetime strings back to datetime objects
            if 'created_at' in user_dict:
                user_dict['created_at'] = datetime.fromisoformat(user_dict['created_at'])
            if 'updated_at' in user_dict:
                user_dict['updated_at'] = datetime.fromisoformat(user_dict['updated_at'])
            user = cls(**user_dict)
            user.user_staus = user.user_status
            user.ea_satus = user.user_ea_status
            return user
        except Exception as e:
            logger.error(f"Error retrieving user {email}: {e}")
            return None

    def save(self) -> None:
        """Save user to store."""
        try:
            current_time = datetime.utcnow()
            
            if not self.created_at:
                self.created_at = current_time
            self.updated_at = current_time
            
            existing_user = self.get_by_email(self.email)
            if existing_user:
                return existing_user

            # Convert to dict and handle datetime serialization
            user_dict = self.dict()
            user_dict['created_at'] = user_dict['created_at'].isoformat()
            user_dict['updated_at'] = user_dict['updated_at'].isoformat()
            # Store as JSON string in Redis
            user_config_store.put(self.email, json.dumps(user_dict))
            auth_service.init_gmail_user(self.email)
            auth_service.init_gmail_user(self.ea.ea_email)
        except Exception as e:
            logger.error(f"Error saving user {self.email}: {e}")
            raise

    @property
    def user_status(self) -> str:
        """Get Gmail user credentials."""
        return auth_service.get_gmail_user_status(self.email)

    @property
    def user_ea_status(self) -> str:
        """Get Gmail user credentials."""
        return auth_service.get_gmail_user_status(self.ea.ea_email)

    @property
    def auth_status(self) -> str:
        """Get user authentication status."""
        return "authenticated" if user_token_store.get(self.email) else "pending"