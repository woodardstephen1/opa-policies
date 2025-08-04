package aws.ebs

# Import the future keywords
import future.keywords

# Define the default rule to deny
default allow := false

# Allow the resource if it meets the encryption requirements
allow {
    input.resource_type == "aws_ebs_volume"
    input.encrypted == true
}

# Deny with a violation message if the volume is not encrypted
deny[msg] {
    input.resource_type == "aws_ebs_volume"
    not input.encrypted
    msg := sprintf("EBS volume '%v' is not encrypted. All EBS volumes must be encrypted.", [input.id])
}

# Rule to check if all EBS volumes are encrypted
ebs_volumes_encrypted {
    count([res |
        res := input.resources[_]
        res.type == "aws_ebs_volume"
        not res.values.encrypted
    ]) == 0
}

# Violation rule that returns a message for each unencrypted volume
violations[msg] {
    resource := input.resources[_]
    resource.type == "aws_ebs_volume"
    not resource.values.encrypted
    msg := sprintf("EBS volume '%v' is not encrypted. All EBS volumes must be encrypted.", [resource.address])
}