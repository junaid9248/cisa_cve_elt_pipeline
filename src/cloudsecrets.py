from google.cloud import secretmanager
from google.oauth2 import service_account
import os
from typing import Optional
from functools import lru_cache
import argparse
import os

GCLOUD_PROJECTNAME = os.environ.get('GCLOUD_PROJECTNAME')
GOOGLE_APPLICATION_CREDENTIALS = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
@lru_cache(maxsize=None)
def get_secret_manager_client(credentials: str = None) -> secretmanager.SecretManagerServiceClient:
    return secretmanager.SecretManagerServiceClient(credentials=credentials)

@lru_cache(maxsize=None)
def get_env_variable_from_secrets(secret_id: str = 'None', version: Optional[str] = 'latest') -> str:

    credentials = service_account.Credentials.from_service_account_file(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))

    gc_secretmanager = get_secret_manager_client(credentials)
    name = f'projects/{GCLOUD_PROJECTNAME}/secrets/{secret_id}/versions/{version}'

    try: 
        response = gc_secretmanager.access_secret_version(request={'name': name})
        retsecret = response.payload.data.decode('UTF-8')
        print(f'For the {secret_id} the secret value retrieved is: {retsecret}')
        return retsecret
    
    except Exception as e:
        print(f"Error retrieving secret: {e}")
        return None
    
if __name__ == '__main__':

    argparser = argparse.ArgumentParser(description='Take secret name and retrieve it')

    # Define arguments for the argument parser

