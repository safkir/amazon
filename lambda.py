import boto3
import json
import logging
from botocore.exceptions import ClientError

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # Replace 'your-region' with your AWS region
    region = 'us-east-1'
    # Replace 'EKS' with your desired description prefix
    description_prefix = 'Amazon EKS'
    # Replace 'your-target-group-arn' with the actual ARN of your ALB target group
    target_group_arn = 'arn:aws:elasticloadbalancing:us-east-1:294290754746:targetgroup/my-target/0fb16260f40c790d'

    # Create an EC2 client
    ec2_client = boto3.client('ec2', region_name=region)

    # Create an ELBv2 client
    elb_client = boto3.client('elbv2', region_name=region)

    # Describe network interfaces based on the description prefix
    enis_response = ec2_client.describe_network_interfaces(
        Filters=[{'Name': 'description', 'Values': [f'{description_prefix}*']}]
    )

    # Extract private IPs and ENI IDs
    private_ips = []
    eni_ids = []
    for eni in enis_response['NetworkInterfaces']:
        eni_id = eni['NetworkInterfaceId']
        private_ips.extend(private_ip['PrivateIpAddress'] for private_ip in eni['PrivateIpAddresses'])
        eni_ids.append(eni_id)

    # Log relevant information
    log_message = f"ENI IDs: {eni_ids}, Private IPs: {private_ips}"
    logger.info(log_message)
    print(log_message)

    # Register new targets (private IPs) with the target group
    new_targets = [{'Id': new_ip, 'Port': 443} for new_ip in private_ips]

    try:
        elb_client.register_targets(TargetGroupArn=target_group_arn, Targets=new_targets)
    except ClientError as e:
        error_message = e.response['Error']['Message']
        logger.error(f"Error registering targets: {error_message}")
        print(f"Error registering targets: {error_message}")

    # Return a response
    return {
        'statusCode': 200,
        'body': json.dumps('Target group updated successfully!')
    }
