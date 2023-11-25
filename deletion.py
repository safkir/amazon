import boto3

def lambda_handler(event, context):
    # Replace 'your_target_group_arn' with the actual ARN of your target group
    target_group_arn = 'arn:aws:elasticloadbalancing:'

    # Create an EC2 and Elastic Load Balancing client
    ec2_client = boto3.client('ec2')
    elbv2_client = boto3.client('elbv2')

    # Get the IP addresses of ENIs with a description starting with "Amazon EKS"
    eni_response = ec2_client.describe_network_interfaces(
        Filters=[
            {'Name': 'description', 'Values': ['Amazon EKS*']}
        ]
    )
    
    eni_ips = [private_ip['PrivateIpAddress'] for eni in eni_response['NetworkInterfaces'] for private_ip in eni['PrivateIpAddresses']]

    # Get the IP addresses of targets in the target group
    targets_response = elbv2_client.describe_target_health(TargetGroupArn=target_group_arn)
    target_ips = [target['Target']['Id'] for target in targets_response['TargetHealthDescriptions']]

    # Compare the two lists
    ips_to_remove = list(set(target_ips) - set(eni_ips))

    # Deregister IPs from the target group that do not match ENI IPs
    for ip_to_remove in ips_to_remove:
        elbv2_client.deregister_targets(TargetGroupArn=target_group_arn, Targets=[{'Id': ip_to_remove}])
        print(f"IP Address {ip_to_remove} deregistered from the target group")

    return {
        'statusCode': 200,
        'body': f"Non-matching IP addresses deregistered from the target group: {ips_to_remove}"
    }
