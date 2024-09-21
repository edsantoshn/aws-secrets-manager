import os
import base64
import json
import logging


import boto3


REGION = os.getenv('REGION', 'us-west-2')


session = boto3.session.Session(
    region_name=REGION
    )

secretsmanager_client = session.client('secretsmanager')


def retrieve_credentials(credentials:dict, cert_name:str):
    try:
        if type(credentials) == str:
            credentials = json.loads(credentials)

        if 'SecretString' in credentials:
            credentials = credentials['SecretString']

        path_folder_cert = f'/tmp/cert/{cert_name}'
        path_cer = path_folder_cert + '/crt.crt'
        path_key = path_folder_cert + '/key.key'
        path_pfx = path_folder_cert + '/pfx.pfx'

        os.makedirs(path_folder_cert, exist_ok=True)
        with open(path_cer, 'wb') as cer_file:
            decode = base64.standard_b64decode(credentials["crt"])
            cer_file.write(decode)

        with open(path_key, 'wb') as key_file:
            decode = base64.standard_b64decode(credentials["key"])
            key_file.write(decode)

        with open(path_pfx, 'wb') as pfx_file:
            decode = base64.standard_b64decode(credentials["pfx"])
            pfx_file.write(decode)

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
        cert_file_path_crt = f'./tmp/cert/{cert_name.lower()}/crt.crt'
        cert_file_path_key = f'./tmp/cert/{cert_name.lower()}/key.key'
        cert_file_path_pfx = f'./tmp/cert/{cert_name.lower()}/pfx.pfx'
        if not os.path.exists(cert_file_path_crt) or not os.path.exists(cert_file_path_key) or not os.path.exists(cert_file_path_pfx):
            credentials = secretsmanager_client.get_secret_value(SecretId='your-secret-name')
            credentials = json.loads(credentials['SecretString'])
            path_file = retrieve_credentials(credentials, cert_name.lower())
        else:
            path_file = {"crt":cert_file_path_crt, "key":cert_file_path_key, "pfx":cert_file_path_pfx}
        return path_file
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