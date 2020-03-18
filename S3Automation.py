import boto3
from botocore.exceptions 
import ClientError
import json
import logging
import sys
log = logging.getLogger()
log.setLevel(logging.DEBUG)

log = logging.getLogger()
log.setLevel(logging.DEBUG)
print('Loading function')
sts_client = boto3.client('sts')
def validate_instance(rec_event):
    sns_msg = json.loads(rec_event['Records'][0]['Sns']['Message'])
    account_id = sns_msg['account']
    event_region = sns_msg['region']
    assumedRoleObject = sts_client.assume_role(
        RoleArn="arn:aws:iam::{}:role/{}".format(account_id, 'Execution-Role-Name'),
        RoleSessionName="AssumeRoleSession1"
    )
    credentials = assumedRoleObject['Credentials']
    print(credentials)
    s3_client = boto3.client('s3', event_region, aws_access_key_id=credentials['AccessKeyId'],
                              aws_secret_access_key=credentials['SecretAccessKey'],
                              aws_session_token=credentials['SessionToken'],
                              )
    s3_bucketName = sns_msg['detail']['requestParameters']['bucketName']

    public_block = s3_client.put_public_access_block(Bucket = s3_bucketName,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': true,
                'IgnorePublicAcls':false,
                'BlockPublicPolicy':true,
                'RestrictPublicBuckets':true
                })        
    enableacl = s3_client.put_bucket_acl(Bucket = s3_bucketName,
                 ACL='private'
                 )


    put_public_access_block
    try:
        checkencryption=s3_client.get_bucket_encryption(Bucket=s3_bucketName)
        print("checking the encrytption")
        rules = checkencryption['ServerSideEncryptionConfiguration']['Rules']
        print('Bucket: %s, Encryption: %s' % (s3_bucketName, rules))
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            response = s3_client.put_bucket_encryption(Bucket = s3_bucketName,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault':{
                            'SSEAlgorithm': 'AES256'
                        }
                    },]
            })

        else:
            print("Bucket: %s, unexpected error: %s" % (s3_bucketName, e))


def lambda_handler(event, context):
    log.info("Here is the Received Event")
    log.info(json.dumps(event))
    validate_instance(event)