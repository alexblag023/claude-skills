resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
  acl    = "public-read"
}
resource "aws_security_group" "sg" {
  name = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
