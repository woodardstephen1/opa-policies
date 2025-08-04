package aws.ebs

# Import the future keywords
import future.keywords

# Define the default rule to deny
default allow := false

# Allow the resource if it meets the encryption criteria
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

# Deny with a violation message if the encryption field is missing
deny[msg] {
    input.resource_type == "aws_ebs_volume"
    not has_field(input, "encrypted")
    msg := sprintf("EBS volume '%v' is missing the 'encrypted' field. All EBS volumes must explicitly set encryption.", [input.id])
}

# Helper function to check if a field exists in the input
has_field(obj, field) {
    _ = obj[field]
}