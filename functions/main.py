import os
import base64
import json
import logging


import boto3


REGION = os.getenv('REGION', 'us-west-2')
CERT_PATH_TEMPLATE = '/tmp/cert/{}/'


session = boto3.session.Session(
    region_name=REGION
    )

secretsmanager_client = session.client('secretsmanager')


def decode_and_save_file(data: str, file_path: str):
    try:
        with open(file_path, 'wb') as file:
            file.write(base64.standard_b64decode(data))
    except Exception as e:
        logging.exception('Error trying to save the cert %s: %s', file_path, e)
        raise


def retrieve_credentials(credentials:dict, cert_name:str):
    try:
        if isinstance(credentials, str):
            credentials = json.loads(credentials)

        if 'SecretString' in credentials:
            credentials = credentials['SecretString']

        path_folder_cert = f'/tmp/cert/{cert_name}'
        path_cer = os.path.join(path_folder_cert, '/crt.crt')
        path_key = os.path.join(path_folder_cert, '/key.key')
        path_pfx = os.path.join(path_folder_cert, '/pfx.pfx')

        os.makedirs(path_folder_cert, exist_ok=True)
        decode_and_save_file(credentials["crt"], path_cer)
        decode_and_save_file(credentials["key"], path_key)
        decode_and_save_file(credentials["pfx"], path_pfx)

        return {
            "crt": path_cer,
            "key": path_key,
            "pfx": path_pfx,
            "credentials": credentials
        }
    except Exception as E:
        logging.exception('retrieving credentials, %s', E)
        return None


def verify_crt_files(cert_name:str):
    try:
        cert_folder = CERT_PATH_TEMPLATE.format(cert_name.lower())
        paths = {
            "crt": os.path.join(cert_folder, 'crt.crt'),
            "key": os.path.join(cert_folder, 'key.key'),
            "pfx": os.path.join(cert_folder, 'pfx.pfx')
        }

        if not all(os.path.exists(path) for path in paths.values()):
            credentials = secretsmanager_client.get_secret_value(SecretId='your-secret-name')
            credentials = json.loads(credentials['SecretString'])
            return retrieve_credentials(credentials, cert_name.lower())

        return paths
    except Exception as exception:
        logging.exception('verifying crt files, %s', exception)
        return None


def handler(event, context):
    try:
        # Your code
        verify_crt_files(cert_name='Your-Secret-Name')
        # Your code
    except Exception as exception:
        logging.exception('main, %s', exception)
        return None