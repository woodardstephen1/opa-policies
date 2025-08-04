package aws.ebs

import future.keywords.in

# Define the default rule to deny
default allow = false

# Allow if the EBS volume is encrypted
allow {
    input.resource.aws_ebs_volume[_].encrypted == true
}

# Deny if any EBS volume is not encrypted
deny[msg] {
    volume := input.resource.aws_ebs_volume[name]
    not volume.encrypted
    msg := sprintf("EBS volume '%v' is not encrypted", [name])
}

# Violation if any EBS volume is not encrypted
violation[result] {
    volume := input.resource.aws_ebs_volume[name]
    not volume.encrypted
    result := {
        "resource_type": "aws_ebs_volume",
        "resource_name": name,
        "violation_type": "EBS Volume Encryption",
        "description": sprintf("EBS volume '%v' is not encrypted", [name])
    }
}