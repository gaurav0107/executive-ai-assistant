import json
import logging
from typing import Any, Optional, Dict
import redis
from datetime import datetime
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class ConfigStore:
    """Redis-powered configuration store for user settings and credentials."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        prefix: str = "eaia:config:"
    ):
        """
        Initialize the config store with Redis connection.
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            prefix: Key prefix for all stored configurations
        """
        self.redis = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=True  # Automatically decode responses to strings
        )
        self.prefix = prefix
        self._test_connection()

    def _test_connection(self) -> None:
        """Test Redis connection and log status."""
        try:
            self.redis.ping()
            logger.info("Successfully connected to Redis")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    def _get_key(self, key: str) -> str:
        """Get the full Redis key with prefix."""
        return f"{self.prefix}{key}"

    def put(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """
        Store a configuration value.
        
        Args:
            key: Configuration key
            value: Configuration value (must be JSON serializable)
            ttl: Time to live in seconds (optional)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Add metadata to the stored value
            stored_value = {
                "value": value,
                "updated_at": datetime.utcnow().isoformat(),
                "metadata": {
                    "type": type(value).__name__
                }
            }
            
            # Serialize to JSON
            serialized = json.dumps(stored_value)
            
            # Store in Redis
            full_key = self._get_key(key)
            if ttl:
                self.redis.setex(full_key, ttl, serialized)
            else:
                self.redis.set(full_key, serialized)
                
            logger.info(f"Successfully stored configuration for key: {key}")
            return True
            
        except (TypeError, json.JSONDecodeError) as e:
            logger.error(f"Failed to serialize value for key {key}: {e}")
            return False
        except redis.RedisError as e:
            logger.error(f"Redis error while storing key {key}: {e}")
            return False

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve a configuration value.
        
        Args:
            key: Configuration key
            
        Returns:
            The stored value or None if not found
        """
        try:
            full_key = self._get_key(key)
            stored_data = self.redis.get(full_key)
            
            if not stored_data:
                logger.debug(f"No configuration found for key: {key}")
                return None
                
            # Deserialize from JSON
            data = json.loads(stored_data)
            return data["value"]
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to deserialize value for key {key}: {e}")
            return None
        except redis.RedisError as e:
            logger.error(f"Redis error while retrieving key {key}: {e}")
            return None

    def delete(self, key: str) -> bool:
        """
        Delete a configuration value.
        
        Args:
            key: Configuration key
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            full_key = self._get_key(key)
            self.redis.delete(full_key)
            logger.info(f"Successfully deleted configuration for key: {key}")
            return True
        except redis.RedisError as e:
            logger.error(f"Redis error while deleting key {key}: {e}")
            return False

    def get_all(self, pattern: str = "*") -> Dict[str, Any]:
        """
        Get all configurations matching a pattern.
        
        Args:
            pattern: Pattern to match keys (default: "*")
            
        Returns:
            Dict of key-value pairs
        """
        try:
            full_pattern = self._get_key(pattern)
            keys = self.redis.keys(full_pattern)
            
            result = {}
            for key in keys:
                # Remove prefix from key
                clean_key = key[len(self.prefix):]
                value = self.get(clean_key)
                if value is not None:
                    result[clean_key] = value
                    
            return result
            
        except redis.RedisError as e:
            logger.error(f"Redis error while retrieving pattern {pattern}: {e}")
            return {}

    def exists(self, key: str) -> bool:
        """
        Check if a configuration exists.
        
        Args:
            key: Configuration key
            
        Returns:
            bool: True if exists, False otherwise
        """
        try:
            full_key = self._get_key(key)
            return bool(self.redis.exists(full_key))
        except redis.RedisError as e:
            logger.error(f"Redis error while checking key {key}: {e}")
            return False

# Example usage:
if __name__ == "__main__":
    # Initialize config store
    config_store = ConfigStore(
        host="localhost",
        port=6379,
        password="your_password",  # Optional
        prefix="eaia:config:"
    )
    
    # Store configuration
    config_store.put(
        "user:123",
        {
            "email": "user@example.com",
            "preferences": {"theme": "dark"}
        }
    )
    
    # Retrieve configuration
    user_config = config_store.get("user:123")
    
    # Check if configuration exists
    if config_store.exists("user:123"):
        print("Configuration exists")
    
    # Get all user configurations
    all_configs = config_store.get_all("user:*")
    
    # Delete configuration
    config_store.delete("user:123")
