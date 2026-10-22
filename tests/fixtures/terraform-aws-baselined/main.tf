# Deliberately insecure fixture: public SSH and an unencrypted, public-readable bucket
resource "aws_security_group" "ssh" {
  name        = "open-ssh"
  description = "SSH from anywhere"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "fixture-open-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
