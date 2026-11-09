variable "region" {
  type    = string
  default = "us-east-1"
}

variable "owner" { type = string }
variable "alert_email" { type = string }

variable "dry_run" {
  type        = bool
  default     = false
  description = "true logs what would be fixed without changing buckets"
}
