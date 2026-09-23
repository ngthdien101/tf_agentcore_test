# • Create-time guard (EC2, RDS, ELBv2, FSx, ECR, ECS, EKS, EBS create)
#   Deny if any compulsory tag missing/empty
# • Runtime start guard (EC2 + RDS)
#   Deny Start if mandatory tags missing/invalid
# • Untag protection
#   Deny untagging only airnz:ops:applicationid

data "aws_iam_policy_document" "airnz_tagging_ec2_enforcement" {
  # 1) EC2 RunInstances — requestTag at creation
  dynamic "statement" {
    for_each = toset(local.mandatory_tags_presence_ec2)
    content {
      sid       = "EC2${upper(regex("[^:]+$", statement.value))}" #Shorten SID to save space
      effect    = "Deny"
      actions   = ["ec2:RunInstances"]
      resources = ["arn:aws:ec2:*:*:instance/*"]

      condition {
        test     = "StringNotLike"
        variable = "aws:RequestTag/${statement.value}"
        values   = ["?*"]
      }
    }
  }
  # 2) Security group — requestTag at creation
  dynamic "statement" {
    for_each = toset(local.mandatory_tags_presence_non_ec2)
    content {
      sid       = "SG${upper(regex("[^:]+$", statement.value))}" #Shorten SID to save space
      effect    = "Deny"
      actions   = ["ec2:CreateSecurityGroup"]
      resources = ["arn:aws:ec2:*:*:security-group/*"]

      condition {
        test     = "StringNotLike"
        variable = "aws:RequestTag/${statement.value}"
        values   = ["?*"]
      }
    }
  }
  dynamic "statement" {
    for_each = toset(local.mandatory_tags_presence_non_ec2)
    content {
      # This is a temp exemptions for bedrock agent core identity
      sid     = "SM${upper(regex("[^:]+$", statement.value))}" #Shorten SID to save space
      effect  = "Deny"
      actions = ["secretsmanager:CreateSecret"]
      not_resources = [
        "arn:aws:secretsmanager:*:*:secret:bedrock-agentcore-identity!*",
        "arn:aws:secretsmanager:ap-southeast-2:383856007354:secret:ecs-sc!*",
        "arn:aws:secretsmanager:ap-southeast-2:743002303648:secret:ecs-sc!*",
      ]
      condition {
        test     = "StringNotLike"
        variable = "aws:RequestTag/${statement.value}"
        values   = ["?*"]
      }
    }
  }
}

data "aws_iam_policy_document" "airnz_tagging_non_ec2_scp" {
  # 1) Create-time tag enforcement for non-ec2 resources
  dynamic "statement" {
    for_each = toset(local.mandatory_tags_presence_non_ec2)
    content {
      sid       = "DenyOtherMissing${upper(regex("[^:]+$", statement.value))}Tag"
      effect    = "Deny"
      actions   = local.other_create_actions
      resources = ["*"]

      condition {
        test     = "StringNotLike"
        variable = "aws:RequestTag/${statement.value}"
        values   = ["?*"]
      }
    }
  }
}

data "aws_iam_policy_document" "airnz_tagging_runtime_values_scp" {
  # 1) EC2 StartInstances — resourceTag at runtime
  dynamic "statement" {
    for_each = local.mandatory_tag_values_ec2
    content {
      sid       = "DenyEC2StartWhen${upper(regex("[^:]+$", statement.key))}ValueInvalid"
      effect    = "Deny"
      actions   = ["ec2:StartInstances"]
      resources = ["arn:aws:ec2:*:*:instance/*"]

      condition {
        test     = "StringNotEquals"
        variable = "aws:ResourceTag/${statement.key}"
        values   = statement.value
      }
    }
  }

  # 2) RDS: Deny Start if ANY enumerated tag has WRONG VALUE
  dynamic "statement" {
    for_each = local.mandatory_tag_values_non_ec2
    content {
      sid    = "DenyRDSInstanceStartWhen${upper(regex("[^:]+$", statement.key))}ValueInvalid"
      effect = "Deny"
      actions = [
        "rds:StartDBInstance",
        "rds:RebootDBInstance",
      ]
      resources = [
        "arn:aws:rds:*:*:db:*",
      ]

      condition {
        test     = "StringNotEquals"
        variable = "aws:ResourceTag/${statement.key}"
        values   = statement.value
      }
    }
  }
  dynamic "statement" {
    for_each = local.mandatory_tag_values_non_ec2
    content {
      sid    = "DenyRDSClusterStartWhen${upper(regex("[^:]+$", statement.key))}ValueInvalid"
      effect = "Deny"
      actions = [
        "rds:StartDBCluster",
        "rds:RebootDBCluster",
      ]
      resources = [
        "arn:aws:rds:*:*:cluster:*",
      ]

      condition {
        test     = "StringNotEquals"
        variable = "aws:ResourceTag/${statement.key}"
        values   = statement.value
      }
    }
  }
}

# Protect applicationid tag from untag
data "aws_iam_policy_document" "airnz_cloudplatform_tagprotection_scp" {
  statement {
    sid       = "ProtectApplicationIdFromUntag"
    effect    = "Deny"
    actions   = local.untag_actions
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/airnz:ops:applicationid"
      values   = ["SNSVC0011092"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }
  # 1) Only Platform principals can modify ANY tags on CP-managed resources (EC2 tag APIs)
  # merge the statements for ec2:CreateTags", "ec2:DeleteTags" and "tag:TagResources", "tag:UntagResources" if SCP length becomes issue.
  statement {
    sid       = "DenyEC2TagModificationOnCloudPlatformResources"
    effect    = "Deny"
    actions   = ["ec2:CreateTags", "ec2:DeleteTags"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/airnz:ops:managedby"
      values   = ["Cloud Platform Support"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values = concat(
        local.core_roles,
        ["arn:aws:iam::*:role/automated-backup-role*"]
      )
    }
  }
  statement {
    sid       = "DenyTagApiModificationOnCloudPlatformResources"
    effect    = "Deny"
    actions   = ["tag:TagResources", "tag:UntagResources"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/airnz:ops:managedby"
      values   = ["Cloud Platform Support"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }
  # 2) Protect VPC constructs from tag changes
  statement {
    sid     = "DenyVPCTagModificationsEc2API"
    effect  = "Deny"
    actions = ["ec2:CreateTags", "ec2:DeleteTags", "tag:TagResources", "tag:UntagResources"]
    resources = [
      "arn:aws:ec2:*:*:vpc/*",
      "arn:aws:ec2:*:*:subnet/*",
      "arn:aws:ec2:*:*:internet-gateway/*",
      "arn:aws:ec2:*:*:route-table/*",
      "arn:aws:ec2:*:*:network-acl/*",
      "arn:aws:ec2:*:*:vpc-peering-connection/*",
      "arn:aws:ec2:*:*:transit-gateway/*",
      "arn:aws:ec2:*:*:transit-gateway-attachment/*",
    ]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values = [
        "132226143350", // airnz-innovation01
        "320466445907", // airnz-innovation02
        "146609405994", // airnz-learning-sandpit
      ]
    }
  }
}

### DENY general + outside-apse2 + unencrypted redis
### The combination to reduce the no of attachment against the 5 limit
data "aws_iam_policy_document" "airnz_deny_general_scp" {
  # original deny general
  statement {
    effect = "Deny"
    actions = [
      "ec2:ModifyAvailabilityZoneGroup",
      "redshift:CreateCluster",
    ]
    resources = ["*"]
  }

  # original deny unencrypted redis
  statement {
    effect    = "Deny"
    actions   = ["elasticache:CreateReplicationGroup", ]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "elasticache:AtRestEncryptionEnabled"
      values   = ["false"]
    }
  }

  # original deny outside-apse2
  statement {
    not_actions = [
      "access-analyzer:*",
      "account:ListRegions",
      "acm:*",
      "aoss:*",
      "apigateway:*",
      "arsenal:*",
      "aws-marketplace:*",
      "aws-marketplace:ViewSubscriptions",
      "aws-portal:*",
      "bedrock:*",
      "budgets:*",
      "ce:*",
      "cloudformation:*",
      "cloudfront:*",
      "cloudtrail:*",
      "cloudwatch:*",
      "cur:*",
      "devicefarm:*",
      "directconnect:Describe*",
      "dynamodb:*",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeRegions",
      "ec2:DescribeTransitGateways",
      "ec2:DescribeVpnGateways",
      "ec2:EnableImageDeprecation",
      "elasticloadbalancing:DescribeLoadBalancers",
      "es:*",
      "events:*",
      "firehose:*",
      "fms:*",
      "globalaccelerator:*",
      "health:*",
      "iam:*",
      "importexport:*",
      "kms:*",
      "lambda:*",
      "license-manager:ListReceivedLicenses",
      "logs:*",
      "mgh:*",
      "migrationhub-orchestrator:*",
      "migrationhub-strategy:*",
      "organizations:*",
      "osis:*",
      "pricing:*",
      "q:*",
      "refactor-spaces:*",
      "route53:*",
      "route53domains:*",
      "route53resolver:*",
      "s3:*",
      "servicequotas:*",
      "ses:*",
      "shield:*",
      "sms:*",
      "sns:*",
      "sqs:*",
      "ssm:*",
      "sts:*",
      "support:*",
      "supportapp:*",
      "sustainability:GetCarbonFootprintSummary",
      "synthetics:*",
      "tag:*",
      "trustedadvisor:*",
      "waf-regional:*",
      "waf:*",
      "wafv2:*",
    ]
    effect    = "Deny"
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-southeast-2"]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }

  statement {
    actions = [
      "aoss:*",
      "apigateway:*",
      "ec2:DescribeRegions",
      "es:*",
      "fms:*",
      "osis:*",
      "servicequotas:*",
      "sqs:*",
      "waf-regional:*",
    ]
    effect    = "Deny"
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values = [
        "ap-southeast-2",
        "us-east-1",
        "us-west-2",
      ]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }

  statement {
    actions = [
      "bedrock:*",
    ]
    effect    = "Deny"
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values = [
        "ap-southeast-2",
        "us-west-2",
        "us-east-1",
        "us-east-2",
      ]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }

  statement {
    actions = [
      "bedrock:*",
    ]
    effect    = "Deny"
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values = [
        "583282395765", # kea-non-prod
        "557713916509", # kea-prod
        "074779643705", # ai-prod
        "648041021691", # ai-non-prod
        "225934517438", # Workload gamma dev org
      ]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }

  statement {
    actions = [
      "s3:CreateBucket",
    ]
    effect    = "Deny"
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values = [
        "ap-southeast-2",
        "us-east-1",
      ]
    }
  }

  statement {
    actions = [
      "devicefarm:*",
    ]
    effect    = "Deny"
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values = [
        "174550113169",
      ]
    }
  }

  statement {
    actions = [
      "q:*",
    ]
    effect    = "Deny"
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values = [
        "583282395765",
        "425514365948",
      ]
    }
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values = [
        "us-west-2",
      ]
    }
  }
}

module "mandatory_deny_general_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-deny-general-scp"
  policy_description = "General enforcement against outside apse2 and others"
  policy_document    = data.aws_iam_policy_document.airnz_deny_general_scp.json
  tags_common        = local.resource_tags_common
}
###

#TODO: Cleanup: fix this rollout note and capture explicit migration criteria before applying the GA services SCP to v1.
#Policy to replace automated AWSFullAccess policy, needs gradual rollout and through testing before applying to v1
data "aws_iam_policy_document" "airnz_ga_services_scp" {
  # STATEMENT: Allow all permitted services
  statement {
    sid    = "AllowPermittedServices"
    effect = "Allow"
    actions = [
      "trustedadvisor:*",
      "tag:*",
      "sustainability:*",
      "support:*",
      "sts:*",
      "states:*",
      "sso:*",
      "sso-directory:*",
      "ssm:*",
      "sqs:*",
      "sns:*",
      "sms:*",
      "signer:*",
      "shield:*",
      "ses:*",
      "servicequotas:*",
      "servicecatalog:*",
      "securityhub:*",
      "secretsmanager:*",
      "scheduler:*",
      "sagemaker:*",
      "s3:*",
      "rum:*",
      "route53resolver:*",
      "route53domains:*",
      "route53:*",
      "rolesanywhere:*",
      "resource-groups:*",
      "resource-explorer-2:*",
      "rds:*",
      "ram:*",
      "quicksight:*",
      "qldb:*",
      "pipes:*",
      "osis:*",
      "opensearch:*",
      "oam:*",
      "networkmanager:*",
      "mq:*",
      "logs:*",
      "license-manager:*",
      "lambda:*",
      "lakeformation:*",
      "kms:*",
      "kinesis:*",
      "kafka:*",
      "inspector2:*",
      "importexport:*",
      "identitystore:*",
      "iam:*",
      "health:*",
      "guardduty:*",
      "glue:*",
      "globalaccelerator:*",
      "glacier:*",
      "fsx:*",
      "fms:*",
      "firehose:*",
      "evidently:*",
      "events:*",
      "es:*",
      "elasticloadbalancing:*",
      "elasticfilesystem:*",
      "elasticache:*",
      "eks:*",
      "ecs:*",
      "ecr:*",
      "ec2:*",
      "ebs:*",
      "dynamodb:*",
      "docdb-elastic:*",
      "directconnect:*",
      "dax:*",
      "config:*",
      "cognito-idp:*",
      "cognito-identity:*",
      "codeartifact:*",
      "cloudwatch:*",
      "cloudtrail:*",
      "cloudfront:*",
      "cloudformation:*",
      "budgets:*",
      "bedrock:*",
      "batch:*",
      "backup:*",
      "aws-portal:*",
      "aws-marketplace:*",
      "autoscaling:*",
      "athena:*",
      "applicationinsights:*",
      "apigateway:*",
      "aoss:*",
      "aidevops:*",
      "acm:*",
      "acm-pca:*",
      "account:*",
      "access-analyzer:*",
      "artifact:*",
      "application-autoscaling:*",
      "autoscaling-plans:*",
      "bedrock-agentcore:*",
      "billing:*",
      "connect:*",
      "resource-explorer:*",
      "bcm-pricing-calculator:*",
      "organizations:*",
      "ce:*",
      "cur:*",
      "waf:*",
      "waf-regional:*",
      "wafv2:*",
      "vpce:*",
      "supportplans:*",
      "support-console:*",
      "savingsplans:*",
      "sms-voice:*",
      "bcm-recommended-actions:*",
      "cost-optimization-hub:*",
    ]
    resources = ["*"]
  }
}

module "mandatory_airnz_ga_services_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-ga-services-scp"
  policy_description = "Allow access to whitelist Services"
  policy_document    = data.aws_iam_policy_document.airnz_ga_services_scp.json
  tags_common        = local.resource_tags_common
}

#Below policy to allow NZ region - This will replace all general deny policies from v2 and below (can't be applied to V1 yet)
data "aws_iam_policy_document" "airnz_deny_outside_apse2_apse6_scp" {
  statement {
    sid    = "DenyAllOutsideApprovedRegions"
    effect = "Deny"
    not_actions = [
      # Global services — no regional endpoint
      "access-analyzer:*",
      "account:*",
      "acm:*",
      #      "aoss:*",
      #      "apigateway:*",
      #      "arsenal:*",
      "aws-marketplace-management:*",
      "aws-marketplace:*",
      "aws-portal:*",
      "budgets:*",
      "ce:*",
      "cloudformation:*",
      "cloudfront:*",
      "cloudtrail:*",
      "config:*",
      "cloudwatch:*",
      "cur:*",
      #      "devicefarm:*",
      "directconnect:*",
      #      "dynamodb:*",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeRegions",
      "ec2:DescribeTransitGateways",
      "ec2:DescribeVpnGateways",
      "ec2:EnableImageDeprecation",
      "elasticloadbalancing:DescribeLoadBalancers",
      #      "es:*",
      "events:*",
      #      "firehose:*",
      "fms:*",
      "globalaccelerator:*",
      "health:*",
      "iam:*",
      "importexport:*",
      "kms:*",
      #      "lambda:*",
      "license-manager:ListReceivedLicenses",
      "logs:*",
      #      "mgh:*",
      #      "migrationhub-orchestrator:*",
      #      "migrationhub-strategy:*",
      "organizations:*",
      #      "osis:*",
      "pricing:*",
      #      "q:*",
      #      "refactor-spaces:*",
      "route53:*",
      "route53domains:*",
      "route53resolver:*",
      "s3:GetAccountPublic*",
      "s3:ListAllMyBuckets",
      "s3:PutAccountPublic*",
      "servicequotas:*",
      "ses:*",
      "shield:*",
      #      "sms:*",
      #      "sns:*",
      #      "sqs:*",
      "ssm:*",
      "sts:*",
      "support:*",
      "supportapp:*",
      "sustainability:GetCarbonFootprintSummary",
      #      "synthetics:*",
      "tag:*",
      "trustedadvisor:*",
      "waf-regional:*",
      "waf:*",
      "wafv2:*",
      "wellarchitected:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-southeast-2", "ap-southeast-6"]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }
  # STATEMENT 2: allow outside ap-southeast-2, ap-southeast-6, us-east-1
  statement {
    sid    = "DenyMultiRegionServicesOutsideApprovedRegions"
    effect = "Deny"
    actions = [
      "aoss:*",
      "apigateway:*",
      "es:*",
      "osis:*",
      "sqs:*",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-southeast-2", "ap-southeast-6", "us-east-1"]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }
  # Bedrock — approved regions only ap-southeast-2, ap-southeast-4, us-east-1, us-east-2
  statement {
    sid       = "DenyBedrockOutsideApprovedRegions"
    effect    = "Deny"
    actions   = ["bedrock:*", "bedrock-agentcore:*"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-southeast-2", "ap-southeast-4", "us-east-1", "us-east-2"]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }
  # STATEMENT: Bedrock — approved accounts only
  statement {
    sid       = "DenyBedrockForNonApprovedAccounts"
    effect    = "Deny"
    actions   = ["bedrock:*", "bedrock-agentcore:*"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values = [
        "583282395765", # kea-non-prod
        "557713916509", # kea-prod
        "074779643705", # ai-prod
        "648041021691", # ai-non-prod
        "225934517438", # Workload gamma dev org
      ]
    }
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:role/WizAccess-Role"]
    }
  }
  #STATEMENT: S3 CreateBucket — ap-southeast-2 + us-east-1
  statement {
    sid       = "DenyS3CreateBucketOutsideApprovedRegions"
    effect    = "Deny"
    actions   = ["s3:CreateBucket"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-southeast-2", "ap-southeast-6", "us-east-1"]
    }
  }
  # STATEMENT: General Deny specific actions
  statement {
    sid    = "DenyActions"
    effect = "Deny"
    actions = [
      "ec2:ModifyAvailabilityZoneGroup",
      "redshift:CreateCluster",
    ]
    resources = ["*"]
  }
  # STATEMENT: Deny unencrypted ElastiCache at rest
  statement {
    sid       = "DenyUnencryptedElastiCache"
    effect    = "Deny"
    actions   = ["elasticache:CreateReplicationGroup"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "elasticache:AtRestEncryptionEnabled"
      values   = ["false"]
    }
  }
  # STATEMENT: Deny unencrypted EBS volumes
  statement {
    sid    = "DenyUnencryptedEBSVolumes"
    effect = "Deny"
    actions = [
      "ec2:CreateVolume",
      "ec2:RunInstances",
    ]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"
      values   = ["false"]
    }
  }
  # STATEMENT : Deny unencrypted EFS file systems
  statement {
    sid       = "DenyUnencryptedEFS"
    effect    = "Deny"
    actions   = ["elasticfilesystem:CreateFileSystem"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "elasticfilesystem:Encrypted"
      values   = ["false"]
    }
  }
  # STATEMENT : Deny unencrypted RDS
  statement {
    sid       = "DenyUnencryptedRDSInstances"
    effect    = "Deny"
    actions   = ["rds:CreateDBInstance"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "rds:StorageEncrypted"
      values   = ["false"]
    }
  }
  # STATEMENT : Deny IAM user creation without a valid airnz email tag
  statement {
    sid       = "DenyIAMUserCreationWithoutEmailTag"
    effect    = "Deny"
    actions   = ["iam:CreateUser"]
    resources = ["arn:aws:iam::*:user/*"]
    condition {
      test     = "StringNotLike"
      variable = "aws:RequestTag/airnz:iam:email"
      values   = ["*@airnz.co.nz"]
    }
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }
  statement {
    sid    = "DenyCostOptimizationHubEnrollmentOutsideFinOpsBilling"
    effect = "Deny"
    actions = [
      "cost-optimization-hub:UpdateEnrollmentStatus",
      "cost-optimization-hub:UpdatePreferences"
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values = [
        "079693644268", # Finops prod org
        "145808484722", # blling prod org
        "202403774779", # Finops dev org
        "537124933978", # billing dev org
      ]
    }
  }
}

module "mandatory_airnz_deny_outside_apse2_apse6_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz_deny_outside_apse2_apse6_scp"
  policy_description = "Whitelist Services with deny outside apse2 and others"
  policy_document    = data.aws_iam_policy_document.airnz_deny_outside_apse2_apse6_scp.json
  tags_common        = local.resource_tags_common
}

# Innovation guardrails
data "aws_iam_policy_document" "airnz_innovation_scp" {
  statement {
    sid    = "DenyOutsideApprovedRegions"
    effect = "Deny"
    not_actions = [
      # Global / account / identity / governance
      "iam:*",
      "sts:*",
      "organizations:*",
      "account:*",

      # Billing / support / quotas / marketplace
      "aws-portal:*",
      "billing:*",
      "budgets:*",
      "ce:*",
      "cur:*",
      "pricing:*",
      "servicequotas:*",
      "support:*",
      "supportapp:*",
      "trustedadvisor:*",

      # Security / audit / core platform
      "access-analyzer:*",
      "cloudtrail:*",
      "config:*",
      "cloudformation:*",
      "cloudwatch:*",
      "logs:*",
      "events:*",
      "kms:*",
      "ssm:*",
      "tag:*",

      # Core discovery APIs
      "ec2:DescribeRegions",
      "ec2:DescribeAccountAttributes",
      "ec2:DescribeTransitGateways",
      "ec2:DescribeVpnGateways",

      # AI/ML services allowed separately in us-east-1
      "bedrock:*",
      "bedrock-agentcore:*",
      "sagemaker:*",
    ]

    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-southeast-2"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "DenyAIMLOutsideApprovedRegions"
    effect = "Deny"

    actions = [
      "bedrock:*",
      "bedrock-agentcore:*",
      "sagemaker:*",
    ]

    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-southeast-2", "us-east-1"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid       = "DenyAllCrossAccountToProd"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "ForAnyValue:StringLike"
      variable = "aws:ResourceOrgPaths"
      values = [
        "o-312ak153nt/r-ycxz/ou-ycxz-5xr5b116/*",                  # DevOrg - V1
        "o-312ak153nt/r-ycxz/ou-ycxz-pcrknjxj/ou-ycxz-v3v3tv87/*", # DevOrg - V2/Workloads
        "o-fuqa77ts24/r-b3lz/ou-b3lz-099ee4xl/*",                  # ProdOrg - V1
        "o-fuqa77ts24/r-b3lz/ou-b3lz-3px18a7u/ou-b3lz-8tn5key6/"   # ProdOrg - V2/Workloads
      ]
    }

    condition {
      test     = "Null"
      variable = "aws:ResourceOrgPaths"
      values   = ["false"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "DenyCrossAccountAssumeRole"
    effect = "Deny"

    actions = [
      "sts:AssumeRole"
    ]

    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "aws:ResourceAccount"

      values = [
        "$${aws:PrincipalAccount}"
      ]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "DenyCredsAndIdp"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:DeleteUser",
      "iam:*AccessKey",
      "iam:*LoginProfile",
      "iam:*SSHPublicKey",
      "iam:*ServiceSpecificCredential",
      "iam:*SigningCertificate",
      "iam:Create*Provider",
      "iam:Delete*Provider",
      "iam:Update*Provider*",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "RestrictRoleWritesToInnovationPath"
    effect = "Deny"

    actions = [
      "iam:AttachRolePolicy",
      "iam:CreateRole",
      "iam:CreateServiceLinkedRole",
      "iam:DeleteRole",
      "iam:DeleteRolePermissionsBoundary",
      "iam:DeleteRolePolicy",
      "iam:DeleteServiceLinkedRole",
      "iam:DetachRolePolicy",
      "iam:PassRole",
      "iam:PutRolePermissionsBoundary",
      "iam:PutRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:UpdateRole",
      "iam:UpdateRoleDescription"
    ]

    not_resources = [
      "arn:aws:iam::*:role/innovation/*"
    ]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "RestrictPolicyWritesToInnovationPath"
    effect = "Deny"

    actions = [
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:TagPolicy",
      "iam:UntagPolicy"
    ]

    not_resources = [
      "arn:aws:iam::*:policy/innovation/*"
    ]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "DenyBaselineStacks"
    effect = "Deny"
    actions = [
      "cloudformation:*ChangeSet",
      "cloudformation:*Update*",
      "cloudformation:DeleteStack",
      "cloudformation:SetStackPolicy",
    ]
    resources = [
      "arn:aws:cloudformation:*:*:stack/StackSet-*/*",
    ]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "DenyNetworkSharing"
    effect = "Deny"
    actions = [
      "directconnect:*",
      "networkmanager:*",
      "ram:*",
      "vpc-lattice:*",
      "route53resolver:*",
      "ec2:*TransitGateway*",
      "ec2:*VpcPeeringConnection*",
      "ec2:*Vpn*",
      "ec2:CreateCustomerGateway",
      "ec2:CreateNetworkInterfacePermission",
      "ec2:CreateVpcEndpointServiceConfiguration",
      "ec2:ModifyVpcEndpointService*",
      "ec2:EnableVgwRoutePropagation",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid       = "DenyNonAmazonVpcEndpoints"
    effect    = "Deny"
    actions   = ["ec2:CreateVpcEndpoint"]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "ec2:VpceServiceOwner"
      values   = ["amazon"]
    }

    # Don't deny actions that don't support ec2:VpceServiceOwner
    condition {
      test     = "Null"
      variable = "ec2:VpceServiceOwner"
      values   = ["false"]
    }

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "DenyAuditTamper"
    effect = "Deny"
    actions = [
      "access-analyzer:Delete*",
      "access-analyzer:Update*",
      "cloudtrail:Delete*",
      "cloudtrail:Put*",
      "cloudtrail:Stop*",
      "cloudtrail:Update*",
      "config:Delete*",
      "config:Put*",
      "config:Stop*",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }

  statement {
    sid    = "ServiceBlacklist"
    effect = "Deny"
    actions = [
      "braket:*",
      "groundstation:*",
      "outposts:*",
      "panorama:*",
      "robomaker:*",
      "snowball:*",
      "organizations:*",
      "account:*",
      "sso:*",
      "identitystore:*",
      "aws-portal:*",
      "billingconductor:*",
      "cur:*",
      "freetier:*",
      "invoicing:*",
      "payments:*",
      "purchase-orders:*",
      "servicequotas:*ServiceQuotaIncrease*",
      "supportplans:*",
      "tax:*",
    ]
    resources = ["*"]

    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.core_roles
    }
  }
}

module "mandatory_innovation_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-innovation-guardrail"
  policy_description = "Guardrails for the Innovation OU"
  policy_document    = data.aws_iam_policy_document.airnz_innovation_scp.json
  tags_common        = local.resource_tags_common
}

# TODO - To be deleted when the DB OU is deleted
# DB/Storage creation denial enforcement
data "aws_iam_policy_document" "airnz_database_creation_scp" {
  statement {
    sid       = "DenyDatabaseAndStorageProvisioning"
    effect    = "Deny"
    actions   = local.deny_db_storage_actions
    resources = ["*"]
  }
}


module "mandatory_tagging_ec2_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-tagging-ec2-guardrail"
  policy_description = "Enforcement and protection against untagging mandatory keys at EC2 creation"
  policy_document    = data.aws_iam_policy_document.airnz_tagging_ec2_enforcement.json
  tags_common        = local.resource_tags_common
}

module "mandatory_tagging_non_ec2_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-tagging-non-ec2-guardrail"
  policy_description = "Enforcement and protection against untagging mandatory keys at resource creation (non-EC2)"
  policy_document    = data.aws_iam_policy_document.airnz_tagging_non_ec2_scp.json
  tags_common        = local.resource_tags_common
}

module "mandatory_tagging_runtime_values_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-tagging-runtime-values-guardrail"
  policy_description = "Enforcement and protection against invalid values at EC2 and RDS runtime"
  policy_document    = data.aws_iam_policy_document.airnz_tagging_runtime_values_scp.json
  tags_common        = local.resource_tags_common
}

module "mandatory_cloudplatform_tagprotection_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-cloudplatform-tagprotection-guardrail"
  policy_description = "Enforcement and protection against mandatory tag from untag"
  policy_document    = data.aws_iam_policy_document.airnz_cloudplatform_tagprotection_scp.json
  tags_common        = local.resource_tags_common
}

# TODO - To be deleted when the DB OU is deleted
module "db_creation_scp" {
  source             = "./modules/scp"
  policy_name        = "airnz-deny-db-storage-guardrail"
  policy_description = "Deny provisioning of main persistent datastore/storage services"
  policy_document    = data.aws_iam_policy_document.airnz_database_creation_scp.json
  tags_common        = local.resource_tags_common
}
