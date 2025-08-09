variable "aws_profile" {
  type    = string
  default = null
}

variable "region" {
  type    = string
  default = "ap-northeast-1"
}

variable "aws_tags" {
  type = map(string)
  default = {
    project = "kaita"
  }
}

variable "prefix" {
  type    = string
  default = "kaita"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}
