import boto3

sts = boto3.client("sts")
identity = sts.get_caller_identity()

print(identity["Arn"])