package aws.s3

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    bucket := input.resource_changes[_]
    bucket.type == "aws_s3_bucket"

    public_access := bucket.change.after.public_access_block
    not public_access
    
    msg := sprintf("S3 bucket '%v' is not configured with public access block", [bucket.name])
}