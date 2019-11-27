---
client: "Simplon"
title: "AWS formation"
subtitle: "AWS from scratch"
author: [Matthieu Fatrez, Simplon students] 
date: "21/11/2019"
subject: "Useful commands for AWS formation"
keywords: [formation, simplon, aws, course]
papersize: a4
titletype: gekko
language: "english"
versionHistory:
  - version: 1.0
    date: 21/11/2019
    author: Matthieu Fatrez
    comment: Initial creation

...

# IAM

## Commands

Create group
```
aws iam create-group --group-name "mongroupe"
```

List groups
```
aws iam list-groups
```

Attach Policy to group
```
aws iam attach-group-policy --group-name "mongroupe" --policy-arn "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
```

List Policies
```
aws iam list-attached-group-policies --group-name "mongroupe"
```

Create user
```
aws iam create-user --user-name "matthieu"
```

Create login profile
```
aws iam create-login-profile --user-name "matthieu" --password "monpasswdcompliqué"
```

Programmatic access
```
aws iam create-access-key --user-name "matthieu"
```

Add user to group
```
aws iam add-user-to-group --group-name "mongroupe" --user-name "matthieu"
```

## Useful links

* [https://policysim.aws.amazon.com](https://policysim.aws.amazon.com)
* [https://awspolicygen.s3.amazonaws.com/policygen.html](https://awspolicygen.s3.amazonaws.com/policygen.html)

* [https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)
* [https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
* [https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_examples.html)


## Policies examples

### Example 1

Policy to deny IP Range

AuthorizedIpRanges.json
```
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "NotIpAddress": {
        "aws:SourceIp": [
          "81.254.217.1/32",
          "213.215.37.182/32",
          "192.168.1.0/24"
        ]
      }
    }
  }
}
```

```
aws iam create-policy --policy-name AuthorizedIpRanges --description "Restrict by IP Ranges" --policy-document file://AuthorizedIpRanges.json
```

```
aws iam attach-user-policy --user-name "mfaS3" --policy-arn "arn:aws:iam::065332230902:policy/AuthorizedIpRanges"
```

### Example 2

Do nothing if MFA is not set
```
{
  'Version': '2012-10-17',
  'Statement': {
    'Sid': 'AllowAllUsersToListAccounts',
    'Effect': 'Allow',
    'Action': [
      'iam:ListAccountAliases',
      'iam:ListUsers',
      'iam:ListVirtualMFADevices',
      'iam:GetAccountPasswordPolicy',
      'iam:GetAccountSummary'
    ],
    'Resource': '*'
  },
  {
    'Sid': 'AllowIndividualUserToSeeAndManageOnlyTheirOwnAccountInformation',
    'Effect': 'Allow',
    'Action': [
      'iam:ChangePassword',
      'iam:CreateAccessKey',
      'iam:CreateLoginProfile',
      'iam:DeleteAccessKey',
      'iam:DeleteLoginProfile',
      'iam:GetLoginProfile',
      'iam:ListAccessKey',
      'iam:UpdateAccessKey',
      'iam:UpdateLoginProfile',
      'iam:ListSigningCertificates',
      'iam:DeleteSigningCertificates',
      'iam:UploadSigningCertificates',
      'iam:ListSSHPublicKeys',
      'iam:GetSSHPublicKeys',
      'iam:DeleteSSHPublicKeys',
      'iam:UpdateSSHPublicKeys',
      'iam:UploadSSHPublicKeys'
    ],
    'Resource': 'arn:aws:iam::*:user/${aws:username}'
  },
  {
    'Sid': 'AllowIndividualUserToListOnlyTheirOwnMFA',
    'Effect': 'Allow',
    'Action': [
      "iam:ListMFADevices"
    ],
    'Resource': [
      'arn:aws:iam::*:mfa/*',
      'arn:aws:iam::*:user/${aws:username}'
    ]
  },
  {
    'Sid': 'AllowIndividualUserToManageTheirOwnMFA',
    'Effect': 'Allow',
    'Action': [
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice"
    ],
    'Resource': [
      'arn:aws:iam::*:mfa/*',
      'arn:aws:iam::*:user/${aws:username}'
    ]
  },
  {
    'Sid': 'AllowIndividualUserToDeactivateOnlyTheirOwnMFAWhenUsingMFA',
    'Effect': 'Allow',
    'Action': [
      "iam:DeactivateVirtualMFADevice"
    ],
    'Resource': [
      'arn:aws:iam::*:mfa/*',
      'arn:aws:iam::*:user/${aws:username}'
    ],
    'Condition': {
      'Bool': {
        'aws:MultifactorAuthPresent': 'true'
      }
    }
  },
  {
    'Sid': 'BlockMostAccessUnlessSignedInWithMFA',
    'Effect': 'Deny',
    'NotAction': [
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:ListVirtualMFADevices",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      'iam:ListAccountAliases',
      'iam:ListUsers',
      'iam:ListSSHPublicKeys',
      'iam:ListAccessKey',
      'iam:ListServiceSpecificCredentials',
      'iam:ListMFADevices',
      'iam:GetAccountSummary',
      'iam:GetSessionToken'
    ],
    'Resource': '*',
    'Condition': {
      'BoolIfExists': {
        'aws:MultifactorAuthPresent': 'false'
      }
    }
  }
}
```

### Example 3

MyProjectLimitedAdminAccess.json
```
{
  'Version': '2012-10-17',
  'Statement': {
    'Sid': 'ManageUserPermissions',
    'Effect': 'Allow',
    'Action': [
      'iam:ChangePassword',
      'iam:CreateAccessKey',
      'iam:CreateLoginProfile',
      'iam:CreateUser',
      'iam:DeleteAccessKey',
      'iam:DeleteLoginProfile',
      'iam:DeleteUser',
      'iam:UpdateAccessKey',
      'iam:ListAttachedUserPolicies',
      'iam:ListPolicies',
      'iam:ListUserPolicies',
      'iam:ListGroups',
      'iam:ListGroupsForUsers',
      'iam:GetPolicies',
      'iam:GetAccountSummary'
    ],
    'Resource': '*'
  },
  {
    'Sid': 'LimitedAttachementPolicies',
    'Effect': 'Allow',
    'Action': [
      'iam:AttachUserPolicies',
      'iam:DetachUserPolicies'
    ],
    'Resource': '*',
    'Condition': {
      'ArnEquals': {
        'iam:PoliciyArn': [
          'arn:aws:iam::123456789:policy/MyProjectS3Access',
          'arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess'
        ]
      }
    }
  }
}
```

Create policy

```
aws iam create-policy --policy-name MyProjectLimitedAdminAccess --description "Grants Limited IAM administrator access" --policy-document file://MyProjectLimitedAdminAccess.json
```

Create user
```
aws iam create-user --user-name "limitedAdmin"
```

Create Access Key for user
```
aws iam create-access-key --user-name "limitedAdmin"
```

Create password
```
aws iam create-login-profile --user-name "limitedAdmin" --password "MDPCompliqué"
```

Attach policy
```
aws iam attach-user-policy --user-name "limitedAdmin" --policy-arn "arn:aws:iam::123456789:policy/MyProjectLimitedAdminAccess"
aws iam attach-user-policy --user-name "limitedAdmin" --policy-arn "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
```

### Example 4

```
aws iam create-user --user-name "mfaS3"
aws iam create-access-key --user-name "mfaS3"
aws iam create-login-profile --user-name "mfaS3" --password "MDPCompliquéMFAS3"
```

ListBucketAndRootAccessLevel.json "MonDirectory"
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GetBucketLocation",
      "Effect": "Allow",
      "Action": "s3:GetBucketLocation",
      "Resource": "*"
    },
    {
      "Sid": "ListBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::mondirectoryquepersonnena",
      "Condition": {
        "StringEquals": {
          "s3:delimiter": "/",
          "s3:prefix": ""
        }
      }
    },
    {
      "Sid": "ListAllMyBuckets",
      "Effect": "Allow",
      "Action": "s3:ListAllMyBuckets",
      "Resource": "*"
    }
  ]
}
```

```
aws iam create-policy --policy-name ListBucketAndRootAccessLevel --description "Grants Limited IAM administrator access" --policy-document file://ListBucketAndRootAccessLevel.json
```

ListTotoAccessLevel.json
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadMonDirectorySubdir",
      "Action": "s3:ListBucket",
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::mondirectoryquepersonnena",
      "Condition": {
        "StringLike": {
          "s3:prefix": [
            "toto/*"
          ]
        }
      }
    },
    {
      "Sid": "AllowReadWriteInModDirectorySubdir",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::mondirectoryquepersonnena/toto/*"
      ]
    }
  ]
}
```

```
aws iam create-policy --policy-name ListTotoAccessLevel --description "Grants Limited IAM administrator access" --policy-document file://ListTotoAccessLevel.json
```

```
aws iam attach-user-policy --user-name "mfaS3" --policy-arn "arn:aws:iam::065332230902:policy/ListBucketAndRootAccessLevel"
aws iam attach-user-policy --user-name "mfaS3" --policy-arn "arn:aws:iam::065332230902:policy/ListTotoAccessLevel"
```

# EC2

## LoadBalancer

[https://docs.aws.amazon.com/fr_fr/elasticloadbalancing/latest/application/tutorial-application-load-balancer-cli.html](https://docs.aws.amazon.com/fr_fr/elasticloadbalancing/latest/application/tutorial-application-load-balancer-cli.html)

Create VPC

```
aws ec2 create-vpc --cidr-block 10.0.0.0/16
aws ec2 create-tags --resources "$vpcId" --tags Key=Name,Value="Simplon VPC"
```

Create subnet

```
aws ec2 create-subnet --vpc-id vpc-065121481416d3d6d --availability-zone=eu-west-1a --cidr-block 10.0.1.0/24
aws ec2 create-tags --resources "subnet-06dd60661043fc274" --tags Key=Name,Value="Simplon Public AZa"

aws ec2 create-subnet --vpc-id vpc-065121481416d3d6d --availability-zone=eu-west-1b --cidr-block 10.0.2.0/24
aws ec2 create-tags --resources "subnet-0210102fc9a4b3ab8" --tags Key=Name,Value="Simplon Public AZb"

aws ec2 create-subnet --vpc-id vpc-065121481416d3d6d --availability-zone=eu-west-1a --cidr-block 10.0.3.0/24
aws ec2 create-tags --resources "subnet-0733cfe7c80098812" --tags Key=Name,Value="Simplon Private AZa"

aws ec2 create-subnet --vpc-id vpc-065121481416d3d6d --availability-zone=eu-west-1b --cidr-block 10.0.4.0/24
aws ec2 create-tags --resources "subnet-07238300b7b6ee637" --tags Key=Name,Value="Simplon Private AZb"
```

List VPCs

```
aws ec2 describe-vpcs
```
res vpc-065121481416d3d6d

Create key

```
ssh-keygen -t rsa -b 2048 -C "aws_simplon_test" -f ~/.ssh/aws_simplon_test
```

Import key

```
aws ec2 import-key-pair --key-name "aws_simplon_test" --public-key-material file://~/.ssh/aws_simplon_test.pub
```

Create internet gateway

```
aws ec2 create-internet-gateway
```
res: igw-09e3a5a91ea85f4f5

Attach IGW to VPC

```
aws ec2 attach-internet-gateway --vpc-id vpc-065121481416d3d6d --internet-gateway-id igw-09e3a5a91ea85f4f5
```

Create routing table

```
aws ec2 create-route-table --vpc-id vpc-065121481416d3d6d
```
res: rtb-0b3a7062d900aa4e8


```
aws ec2 create-route --route-table-id rtb-0b3a7062d900aa4e8 --destination-cidr-block 0.0.0.0/0 --gateway-id igw-09e3a5a91ea85f4f5
```

Verification :

```
aws ec2 describe-route-tables --route-table-id rtb-0b3a7062d900aa4e8
{
    "RouteTables": [
        {
            "Associations": [],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-0b3a7062d900aa4e8",
            "Routes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                },
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-09e3a5a91ea85f4f5",
                    "Origin": "CreateRoute",
                    "State": "active"
                }
            ],
            "Tags": [],
            "VpcId": "vpc-065121481416d3d6d",
            "OwnerId": "065332230902"
        }
    ]
}
```

List subnets

```
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-065121481416d3d6d" --query 'Subnets[*].{ID:SubnetId,CIDR:CidrBlock}'
[
    {
        "ID": "subnet-0210102fc9a4b3ab8",
        "CIDR": "10.0.2.0/24"
    },
    {
        "ID": "subnet-0733cfe7c80098812",
        "CIDR": "10.0.3.0/24"
    },
    {
        "ID": "subnet-06dd60661043fc274",
        "CIDR": "10.0.1.0/24"
    },
    {
        "ID": "subnet-07238300b7b6ee637",
        "CIDR": "10.0.4.0/24"
    }
]
```

```
aws ec2 associate-route-table  --subnet-id subnet-06dd60661043fc274 --route-table-id rtb-0b3a7062d900aa4e8
aws ec2 associate-route-table  --subnet-id subnet-0210102fc9a4b3ab8 --route-table-id rtb-0b3a7062d900aa4e8
```

Map public IP in public network

```
aws ec2 modify-subnet-attribute --subnet-id subnet-06dd60661043fc274 --map-public-ip-on-launch
aws ec2 modify-subnet-attribute --subnet-id subnet-0210102fc9a4b3ab8 --map-public-ip-on-launch
```

Create security group

```
aws ec2 create-security-group --group-name MySecurityGroup4LB --description "My security group for Load Balancer" --vpc-id vpc-065121481416d3d6d
aws ec2 create-tags --resources "sg-0ece3dd882dc7fc5b" --tags Key=Name,Value="Simplon SG"
```
res : sg-0ece3dd882dc7fc5b

Récupération du SG en dernière commande

```
aws ec2 authorize-security-group-ingress --group-id sg-0ece3dd882dc7fc5b --protocol tcp --port 22 --cidr 78.40.53.90/32
aws ec2 authorize-security-group-ingress --group-id sg-0ece3dd882dc7fc5b --protocol tcp --port 22 --cidr 213.215.37.182/32
aws ec2 authorize-security-group-ingress --group-id sg-0ece3dd882dc7fc5b --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-0ece3dd882dc7fc5b --protocol tcp --port 443 --cidr 0.0.0.0/0
```

List subnets from a specific VPC
```
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-065121481416d3d6d"
```

User data declaration /!\ "base64 my_script.txt >my_script_base64.txt"

[https://docs.aws.amazon.com/fr_fr/AWSEC2/latest/UserGuide/user-data.html](https://docs.aws.amazon.com/fr_fr/AWSEC2/latest/UserGuide/user-data.html)

```
cat <<EOF > tuning_ec2_as_lb.txt
#!/bin/bash
yum update -y
yum install -y httpd
systemctl start httpd
systemctl enable httpd
usermod -a -G apache ec2-user
chown -R ec2-user:apache /var/www
chmod 2775 /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod 0664 {} \;
curl http://169.254.169.254/latest/meta-data/instance-id > /var/www/html/index.html
EOF
```

Create instance in public AZa

```
aws ec2 run-instances --image-id ami-040ba9174949f6de4 --count 1 --instance-type t2.micro --key-name aws_simplon_test --security-group-ids sg-0ece3dd882dc7fc5b --subnet-id subnet-06dd60661043fc274 --user-data file://tuning_ec2_as_lb.txt
aws ec2 create-tags --resources "i-09ed1ce5a322cabfe" --tags Key=Name,Value="node1 AZa"
```
res:i-09ed1ce5a322cabfe

Create instance in public AZb

```
aws ec2 run-instances --image-id ami-040ba9174949f6de4 --count 1 --instance-type t2.micro --key-name aws_simplon_test --security-group-ids sg-0ece3dd882dc7fc5b --subnet-id subnet-0210102fc9a4b3ab8 --user-data file://tuning_ec2_as_lb.txt
aws ec2 create-tags --resources "i-0b72662e6d3481bbc" --tags Key=Name,Value="node2 AZb"
```
res:i-0b72662e6d3481bbc

Create load balancer

```
aws elbv2 create-load-balancer --name my-load-balancer  --subnets subnet-06dd60661043fc274 subnet-0210102fc9a4b3ab8 --security-groups sg-0ece3dd882dc7fc5b

aws elbv2 create-target-group --name my-targets --protocol HTTP --port 80 --vpc-id vpc-065121481416d3d6d
```
res: arn:aws:elasticloadbalancing:eu-west-1:065332230902:targetgroup/my-targets/5d68a137ae5c0e0d

Register instance to Load balancer

```
aws elbv2 register-targets --target-group-arn arn:aws:elasticloadbalancing:eu-west-1:065332230902:targetgroup/my-targets/5d68a137ae5c0e0d --targets Id=i-09ed1ce5a322cabfe Id=i-0b72662e6d3481bbc
```

```
aws elbv2 create-listener --load-balancer-arn arn:aws:elasticloadbalancing:eu-west-1:065332230902:loadbalancer/app/my-load-balancer/5a2de841b98e1db3 \
--protocol HTTP --port 80  \
--default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:eu-west-1:065332230902:targetgroup/my-targets/5d68a137ae5c0e0d
```


## Autoscaling

```
aws autoscaling create-auto-scaling-group --auto-scaling-group-name my-asg-from-instance \
  --instance-id i-0b72662e6d3481bbc --min-size 1 --max-size 1 --desired-capacity 1
```

```
aws autoscaling create-auto-scaling-group --auto-scaling-group-name my-asg-from-instance \
  --instance-id i-0b72662e6d3481bbc --min-size 1 --max-size 1 --desired-capacity 1 --target-group-arns arn:aws:elasticloadbalancing:eu-west-1:065332230902:targetgroup/my-targets/428ee679fef7aa05
```


```
aws autoscaling describe-auto-scaling-groups --auto-scaling-group-name my-asg-from-instance
```

```
aws autoscaling attach-load-balancers --auto-scaling-group-name my-asg-from-instance --load-balancer-names my-load-balancer
```

# Account / Organization

Parler de la landing zone et de towercontrol

# AWS Control tower

* [https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html](https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html)
* [https://docs.aws.amazon.com/controltower/latest/userguide/best-practices.html](https://docs.aws.amazon.com/controltower/latest/userguide/best-practices.html)

# Route53

## DNS constraints and behaviors

[https://docs.aws.amazon.com/fr_fr/Route53/latest/DeveloperGuide/DNSBehavior.html](https://docs.aws.amazon.com/fr_fr/Route53/latest/DeveloperGuide/DNSBehavior.html)

# Cloudwatch

* [https://docs.aws.amazon.com/cloudwatch/](https://docs.aws.amazon.com/cloudwatch/)
* [https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html)

Monitoring based on metrics returned by the infrastructure or even application if configured.

CloudWatch retrieves logs from servers and / or application logs, metrics (hypervisor / CPU / memory / ...) and other events, all in a single console. Information can be graphed and exploited.

# Cloudtrail

* [https://docs.aws.amazon.com/cloudtrail/](https://docs.aws.amazon.com/cloudtrail/)

* [https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)

Event manager. A kind of linux syslog but applicable to the AWS console.

# Boto3

* [https://boto3.amazonaws.com/v1/documentation/api/latest/index.html](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

Boto est le SDK Amazon Web Services (AWS) pour Python. Il permet aux développeurs Python de créer, configurer et gérer des services AWS, tels que EC2 et S3. Boto fournit une API orientée objet facile à utiliser, ainsi qu'un accès de bas niveau aux services AWS.

Example script pour créer un VPC:

```buildoutcfg
import json
import boto3

ec2_client = boto3.client('ec2')
ec2_resource = boto3.resource('ec2')


def createvpc(vpcname, vpccidr):

    # test if vpc exists
    response = ec2_client.describe_vpcs(
        Filters=[
            {
                'Name': 'tag:Name',
                'Values': [vpcname]
            },
            {
                'Name': 'cidr-block-association.cidr-block',
                'Values': [vpccidr]
            },
        ]
    )
    resp = response['Vpcs']
    if resp:
        print("VPC exists:")
        print(json.dumps(resp, indent=4, sort_keys=True, default=str))
    else:
        # create vpc network
        vpc = ec2_resource.create_vpc(CidrBlock=vpccidr)
        print(json.dumps(vpc, indent=4, sort_keys=True, default=str))
        vpc.create_tags(
            Tags=[
                {
                    "Key": "Name",
                    "Value": vpcname
                }
            ]
        )
        vpc.wait_until_available()

        # check create target-group returned successfully
        if vpc:
            print("Successfully created VPC")
        else:
            print("Create target group failed")
            exit()


if __name__ == '__main__':
    my_vpcname = 'vpc-simplon'
    my_vpccidr = '172.168.0.0/16'
    createvpc(my_vpcname, my_vpccidr)

```