resource "aws_vpc" "app" {
  count                = var.provision_enabled ? 1 : 0
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
}
resource "aws_subnet" "private" {
  count                   = var.provision_enabled ? 2 : 0
  vpc_id                  = aws_vpc.app[0].id
  cidr_block              = cidrsubnet("10.42.0.0/16", 8, count.index)
  availability_zone       = "${var.region}${count.index == 0 ? "a" : "c"}"
  map_public_ip_on_launch  = false
}
resource "aws_security_group" "app" {
  count  = var.provision_enabled ? 1 : 0
  name   = "atlas-app"
  vpc_id = aws_vpc.app[0].id
  # No inbound rule; supply explicit service ingress in the reviewed deployment.
}
resource "aws_security_group" "database" {
  count  = var.provision_enabled ? 1 : 0
  name   = "atlas-database"
  vpc_id = aws_vpc.app[0].id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app[0].id]
  }
}
resource "aws_db_subnet_group" "private" {
  count      = var.provision_enabled ? 1 : 0
  subnet_ids = aws_subnet.private[*].id
}
resource "aws_db_instance" "app" {
  count                        = var.provision_enabled ? 1 : 0
  identifier                   = "atlas-synthetic"
  engine                       = "postgres"
  instance_class               = "db.t4g.micro"
  allocated_storage            = 20
  username                     = "atlas_bootstrap"
  manage_master_user_password  = true
  storage_encrypted            = true
  kms_key_id                   = aws_kms_key.app[0].arn
  publicly_accessible          = false
  db_subnet_group_name         = aws_db_subnet_group.private[0].name
  vpc_security_group_ids       = [aws_security_group.database[0].id]
  backup_retention_period      = 14
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "atlas-reviewed-final"
}
