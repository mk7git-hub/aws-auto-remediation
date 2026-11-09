output "function_name" { value = aws_lambda_function.fn.function_name }
output "dashboard_url" { value = "https://console.aws.amazon.com/cloudwatch/home#dashboards:name=${aws_cloudwatch_dashboard.this.dashboard_name}" }
