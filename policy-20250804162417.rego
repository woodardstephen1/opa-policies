package aws.ebs

# Import the future keywords
import future.keywords

# Define the default rule to deny
default allow := false

# Allow only if the volume is encrypted
allow {
    input.encrypted == true
}

# Deny if the volume is not encrypted
deny[msg] {
    input.encrypted == false
    msg := sprintf("EBS volume %v is not encrypted", [input.id])
}

# Warn if encryption status is not specified
warn[msg] {
    not input.encrypted
    msg := sprintf("Encryption status for EBS volume %v is not specified", [input.id])
}