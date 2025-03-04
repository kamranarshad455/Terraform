resource "aws_instance" "ec2" {
  ami           = "ami-"  
  instance_type = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.cloudwatch_profile.name

  user_data = <<-EOF
    #!/bin/bash
    yum install -y amazon-cloudwatch-agent
    cat <<EOT > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
    {
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              {
                "file_path": "/var/log/auth.log",
                "log_group_name": "auth-logs",
                "log_stream_name": "{instance_id}"
              },
              {
                "file_path": "/var/log/syslog",
                "log_group_name": "syslog",
                "log_stream_name": "{instance_id}"
              }
            ]
          }
        }
      },
      "metrics": {
        "append_dimensions": { "InstanceId": "$${aws:InstanceId}" },
        "metrics_collected": {
          "cpu": { "measurement": ["cpu_usage_active"], "metrics_collection_interval": 60 },
          "disk": { "measurement": ["used_percent"], "resources": ["*"], "metrics_collection_interval": 60 },
          "mem": { "measurement": ["mem_used_percent"], "metrics_collection_interval": 60 },
          "net": { "measurement": ["bytes_sent", "bytes_recv"], "metrics_collection_interval": 60 }
        }
      }
    }
    EOT
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
  EOF
}

# IAM Role for CloudWatch Agent
resource "aws_iam_role" "cloudwatch_role" {
  name = "CloudWatchAgentRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy_attachment" "cloudwatch_policy_attachment" {
  name       = "cloudwatch-policy-attach"
  roles      = [aws_iam_role.cloudwatch_role.name]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "cloudwatch_profile" {
  name = "CloudWatchInstanceProfile"
  role = aws_iam_role.cloudwatch_role.name
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "auth_logs" {
  name              = "auth-logs"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "syslog" {
  name              = "syslog"
  retention_in_days = 30
}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "ec2_dashboard" {
  dashboard_name = "EC2-Monitoring-Dashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        x    = 0
        y    = 0
        width = 6
        height = 6
        properties = {
          metrics = [["AWS/EC2", "CPUUtilization", "InstanceId", aws_instance.ec2.id]]
          title = "CPU Utilization"
          view = "timeSeries"
          stacked = false
        }
      },
      {
        type = "metric"
        x    = 6
        y    = 0
        width = 6
        height = 6
        properties = {
          metrics = [["CWAgent", "mem_used_percent", "InstanceId", aws_instance.ec2.id]]
          title = "Memory Utilization"
          view = "timeSeries"
          stacked = false
        }
      },
      {
        type = "metric"
        x    = 0
        y    = 6
        width = 6
        height = 6
        properties = {
          metrics = [["CWAgent", "disk_used_percent", "InstanceId", aws_instance.ec2.id]]
          title = "Disk Usage"
          view = "timeSeries"
          stacked = false
        }
      },
      {
        type = "metric"
        x    = 6
        y    = 6
        width = 6
        height = 6
        properties = {
          metrics = [["CWAgent", "bytes_sent", "InstanceId", aws_instance.ec2.id]]
          title = "Network Sent"
          view = "timeSeries"
          stacked = false
        }
      },
      {
        type = "metric"
        x    = 0
        y    = 12
        width = 6
        height = 6
        properties = {
          metrics = [["CWAgent", "bytes_recv", "InstanceId", aws_instance.ec2.id]]
          title = "Network Received"
          view = "timeSeries"
          stacked = false
        }
      },
      {
        type = "log"
        x    = 6
        y    = 12
        width = 6
        height = 6
        properties = {
          query = "fields @timestamp, @message | sort @timestamp desc | limit 20"
          logGroupNames = ["auth-logs"]
          title = "Authentication Logs"
        }
      },
      {
        type = "log"
        x    = 0
        y    = 18
        width = 6
        height = 6
        properties = {
          query = "fields @timestamp, @message | sort @timestamp desc | limit 20"
          logGroupNames = ["syslog"]
          title = "System Logs (Syslog)"
        }
      }
    ]
  })
}
