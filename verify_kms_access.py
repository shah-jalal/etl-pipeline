import boto3

def create_kms_client(region, access_key, secret_key, role_arn):
    sts_client = boto3.client('sts', region_name=region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName='AssumedRoleSession')

    # Extract temporary credentials from the assumed role
    assumed_role_credentials = response['Credentials']
    # Create a KMS client
    return boto3.client('kms', 
                        region_name=region, 
                        aws_access_key_id=assumed_role_credentials['AccessKeyId'], 
                        aws_secret_access_key=assumed_role_credentials['SecretAccessKey'],
                        aws_session_token=assumed_role_credentials['SessionToken'])


def encrypt_string(kms_client, key_id, plaintext):
    encrypted_string = kms_client.encrypt(
        KeyId=key_id,
        Plaintext=plaintext
    )

    return encrypted_string['CiphertextBlob']

def decrypt_string(kms_client, key_id, encrypted_string):

    decrypted_string = kms_client.decrypt(
        CiphertextBlob=encrypted_string
    )['Plaintext'].decode()

    return decrypted_string

def main():
    access_key = 'ACCESS_KEY' # replace with your AWS Access Key
    secret_key = 'SECRET_KEY' # replace with your AWS Secret Access Key
    region = 'us-east-1'
    role_arn = 'ROLE_ARN' # replace with your IAM Role arn
    key_id = 'KEY_ID' # Replace 'KEY_ID' with the ARN or alias of your KMS key

    # Replace 'YOUR_STRING' with the string you want to encrypt and decrypt
    plaintext_string = 'YOUR_STRING'

    # Create a KMS client
    kms_client = create_kms_client(region, access_key, secret_key, role_arn)

    # Encrypt the string
    encrypted_string = encrypt_string(kms_client, key_id, plaintext_string)

    # Decrypt the string
    decrypted_string = decrypt_string(kms_client, key_id, encrypted_string)

    # Print results
    print(f'Original String: {plaintext_string}')
    print(f'Encrypted String: {encrypted_string}')
    print(f'Decrypted String: {decrypted_string}')

if __name__ == '__main__':
    main()