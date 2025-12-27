import os
from dotenv import load_dotenv
from src.cloudsecrets import get_env_variable_from_secrets
from typing import Optional

# load_dotenv() reads a .env file and injects those key-value pairs into os.environ to mimic prod behaviour
load_dotenv()

# Setting all the locally passed env variables
IS_LOCAL = os.environ.get('IS_LOCAL', 'true').lower() == 'true'
GCLOUD_PROJECTNAME = os.environ.get('GCLOUD_PROJECTNAME')
PYTHONPATH = os.environ.get('PYTHONPATH')

# Either fetch the env variables from the .env file 
# or use the secrets manager to fetch the secrets
# NOTE: This function only FETCHES the env variables and does not set them in the os.environ 
def fetch_env_or_secret(env_var: Optional[str] = None):
    if IS_LOCAL:
        return_env = os.environ.get(env_var)
        if return_env:
            print(f'Successfully retrieved {env_var} from .env file')
            return return_env
  
    return_secret_env = get_env_variable_from_secrets(env_var)
    if return_secret_env:
        print(f'Successfully retrieved {env_var} from secrets manager')
        os.environ[env_var] = return_secret_env 
        return return_secret_env

'''
GH_TOKEN = fetch_env_or_secret('GH_TOKEN')
GCLOUD_BUCKETNAME= fetch_env_or_secret('GCLOUD_BUCKETNAME')
MY_EMAIL = fetch_env_or_secret('MY_EMAIL')
AIRFLOW__WEBSERVER__SECRET_KEY= fetch_env_or_secret('AIRFLOW__WEBSERVER__SECRET_KEY')
'''













