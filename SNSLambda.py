#Author: Amogh Nagalla

from __future__ import print_function
import boto3
import json
import datetime


s3 = boto3.resource('s3')
formattxt= "snslog_" + datetime.datetime.now().strftime("%Y%m%d%I") + ".txt"

config = s3.meta.client.get_object(Bucket='bucketname',Key="whitelist.txt")['Body'].read().decode('utf-8') 
config_white_list= [ line.strip() for line in config.split('\n') ]

buckets=[]
for bucket in s3.buckets.all():
    buckets.append(bucket.name)
    
if not 'bucketname' in buckets:
    s3.create_bucket(Bucket='bucketname',CreateBucketConfiguration={'LocationConstraint': 'us-east-2'})
    print('Creating bucketname is already in S3')

lines = {}
accounts = ['account1ID','account2ID']
for account_number in accounts:
    try:
        s3.meta.client.put_object(Bucket='bucketname',Key=account_number +"/"+ formattxt)
        print('Log file created under account :: '+account_number)
    except:
        print('Log file already available for account :: '+account_number)
    fileobj = s3.meta.client.get_object(Bucket='bucketname',Key=account_number +"/"+ formattxt)['Body'].read().decode('utf-8') 
    lines[account_number] = [ line for line in fileobj.split('\n') ]

print("Lines :: ", str(lines))

def lambda_handler(event, context):

    print("Received event: ", event)
    try:
        config_rule_list =gmail [ json.loads( a["Sns"]["Message"])["detail"]["additionalEventData"]["configRuleName"] for a in event["Records"] ]
    except Exception as e:
        print("Exception 11 :: ", e)
        try:
            config_rule_list = json.loads(event['Records'][0]['Sns']['Message'])['configRuleNames']
        except Exception as e:
            config_rule_list = []
            print("Exception 12 :: ", e)

    print(config_rule_list)

    try:
        for config_rule in config_rule_list:
            if config_rule in config_white_list:
                message = json.loads(event['Records'][0]['Sns']['Message'])
                if 'account' in message:
                    account_number = message['account']
                elif 'awsAccountId' in message:
                    account_number = message['awsAccountId']
                else:
                    print("Unable to parse Account Number")
                try:
                    converted_message = """{}""".format(str(message))
                    lines[account_number].append(converted_message)
                    body = '\n'.join(map(str, lines[account_number]))
                    print("Pushing {} to account {}".format(converted_message,account_number))
                    resp = s3.Object('bucketname', account_number +"/"+ formattxt).put(Body=body, ContentType='text')
                    print(resp)
                    return converted_message
                except Exception as e:
                    print("Exception 13" + str(e))
            else:
                print(config_rule + " Not configured in white list")
    except Exception as e:
        print("Exception 14", e)

    return None