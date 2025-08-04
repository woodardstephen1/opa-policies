package aws.s3

deny[msg] {
    input.resource.aws_s3_bucket
    bucket := input.resource.aws_s3_bucket[_]
    public_access(bucket)
    msg := sprintf("S3 bucket '%v' is public and should be private", [bucket.bucket])
}