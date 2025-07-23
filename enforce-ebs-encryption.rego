package aws.ebs

import future.keywords.in

aws_regions := [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "af-south-1", "ap-east-1", "ap-south-1", "ap-northeast-1",
    "ap-northeast-2", "ap-northeast-3", "ap-southeast-1",
    "ap-southeast-2", "ca-central-1", "eu-central-1",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-south-1",
    "eu-north-1", "me-south-1", "sa-east-1"
]

default allow = false

allow {
    count(violation) == 0
}

violation[msg] {
    some region in aws_regions
    some volume in input.aws_ebs_volumes[region]
    not volume.encrypted
    msg := sprintf("EBS volume %v in region %v is not encrypted", [volume.id, region])
}

deny[msg] {
    some msg in violation
}





Add policy to enforce EBS volume encryption
