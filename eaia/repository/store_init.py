from eaia.repository.config_store import ConfigStore
from eaia.config import USER_CONFIG, USER_TOKEN_STORE, USER_PREFERENCE_STORE
# Initialize stores
user_config_store = ConfigStore(**USER_CONFIG)
user_token_store = ConfigStore(**USER_TOKEN_STORE)
user_preference_store = ConfigStore(**USER_PREFERENCE_STORE) 