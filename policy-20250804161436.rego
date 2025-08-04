package aws.ebs

# Import the future keywords
import future.keywords

# Define the rule to check if EBS volumes are encrypted
deny[msg] {
    # Check if the input resource is an EBS volume
    input.resource_type == "aws_ebs_volume"
    
    # Check if the encryption is not set or set to false
    not input.resource.encrypted
    
    # If the above conditions are met, deny with a message
    msg := sprintf("EBS volume '%v' is not encrypted. All EBS volumes must be encrypted.", [input.resource.id])
}

# Alternative rule if 'encrypted' is explicitly set to false
deny[msg] {
    input.resource_type == "aws_ebs_volume"
    input.resource.encrypted == false
    
    msg := sprintf("EBS volume '%v' has encryption explicitly set to false. All EBS volumes must be encrypted.", [input.resource.id])
}

# Rule to ensure the KMS key is specified when encryption is enabled
warn[msg] {
    input.resource_type == "aws_ebs_volume"
    input.resource.encrypted == true
    not input.resource.kms_key_id
    
    msg := sprintf("EBS volume '%v' is encrypted but no KMS key is specified. It's recommended to specify a KMS key for better control.", [input.resource.id])
}