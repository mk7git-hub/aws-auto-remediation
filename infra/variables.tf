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

variable "reserved_concurrency" {
  type        = number
  default     = -1
  description = "Reserved concurrency to cap blast radius. -1 = unreserved (required on new accounts: AWS keeps 10 unreserved and new accounts start at 10)."
}
