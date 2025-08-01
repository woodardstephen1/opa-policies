package aws.s3

deny[msg] {
    bucket := input.resource.aws_s3_bucket[_]
    public_access(bucket)
    msg := sprintf("S3 bucket '%v' should not be public", [bucket.bucket])
}