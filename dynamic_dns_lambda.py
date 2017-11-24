# Dynamic DNS via AWS API Gateway, Lambda & Route 53
from __future__ import print_function

import json
import re
import hmac
import boto3

# Tell the script where to find the configuration file.
config_s3_region = 'us-west-2'
config_s3_bucket = 'my_bucket_name'
config_s3_key = 'config.json'

def lambda_handler(event, context):
    # Set event data from the API Gateway to variables.
    source_ip = event['source_ip']
    given_secret = event['given_secret']
    set_hostname = event['set_hostname']
    set_ip = event['set_ip']

    # Use the source ip if none is provided
    if set_ip is None or set_ip == '':
        set_ip = source_ip

    # Define the S3 client.
    s3_client = boto3.client('s3', config_s3_region)

    # Try to read the config, and error if you can't.
    try:
        # Grab the s3 object content
        s3_object = s3_client.get_object(config_s3_bucket, config_s3_key)

        # Parse the content as JSON into a dict
        full_config = json.loads(s3_object['Body'].read())
    except:
        return {'return_status': 'fail',
                'return_message': 'There was an issue finding or reading the S3 config file.'}

    # Try to read the config, and error if you can't.
    if not set_hostname in full_config:
        return {'return_status': 'fail',
                'return_message': 'The host ' + set_hostname + ' does not exist in the config file.'}

    # Get the section of the config related to the requested hostname.
    record_config_set = full_config[set_hostname]
    aws_region = record_config_set['aws_region']
    # the Route 53 Zone you created for the script
    route_53_zone_id = record_config_set['route_53_zone_id']
    # record TTL (Time To Live) in seconds tells DNS servers how long to cache
    # the record.
    route_53_record_ttl = record_config_set['route_53_record_ttl']
    route_53_record_type = record_config_set['route_53_record_type']
    shared_secret = record_config_set['shared_secret']

    # Check the secret is correct (avoiding timing attacks).
    # If they don't match, error out.
    if not hmac.compare_digest(given_secret, shared_secret):
        return_status = 'fail'
        return_message = 'Secret is not correct.'
        return {'return_status': return_status,
                'return_message': return_message}

    # Define the Route 53 client
    route53_client = boto3.client(
        'route53',
        region_name=aws_region
    )

    # Get the current ip address associated with the hostname DNS record from Route 53.
    current_route53_record_set = route53_client.list_resource_record_sets(
        HostedZoneId=route_53_zone_id,
        StartRecordName=set_hostname,
        StartRecordType=route_53_record_type,
        MaxItems='2'
    )
    # boto3 returns a dictionary with a nested list of dictionaries:
    # http://boto3.readthedocs.org/en/latest/reference/services/route53.html#Route53.Client.list_resource_record_sets
    # If the ip is already correct, don't change it.
    if current_route53_record_set['ResourceRecordSets'][0]['Name'] == set_hostname and \
       current_route53_record_set['ResourceRecordSets'][0]['Type'] == route_53_record_type and \
       current_route53_record_set['ResourceRecordSets'][0]['ResourceRecords'][0]['Value'] == set_ip:
        return {'return_status': 'success',
                'return_message': 'Your hostname record ' + set_hostname + ' is already set to ' + set_ip}

    # If the IP addresses do not match or if the record does not exist, tell
    # Route 53 to set the DNS record.
    else:
        change_route53_record_set = route53_client.change_resource_record_sets(
            HostedZoneId=route_53_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': set_hostname,
                            'Type': route_53_record_type,
                            'TTL': route_53_record_ttl,
                            'ResourceRecords': [
                                {
                                    'Value': set_ip
                                }
                            ]
                        }
                    }
                ]
            }
        )

        return {'return_status': 'success',
                'return_message': 'Your hostname record ' + set_hostname + ' has been set to ' + set_ip}
