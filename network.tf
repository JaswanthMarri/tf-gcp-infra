provider "google" {
  credentials = file(var.creds)
  project     = var.project_id
  region      = var.region
}

variable "creds" {}

variable "vpc_name" {
  default = "my-vpc"
}

variable "vpc_instance_name" {
  default = "example-instance"
}

variable "zone" {
  default = "us-east1-c"
}

variable "webapp_subnet_cidr" {
  description = "CIDR range for the webapp subnet"
}

variable "db_subnet_cidr" {
  description = "CIDR range for the db subnet"
}
variable "domain_name" {
  description = "The domain name to be used"
}

variable "dns_zone_name" {
  description = "The domain zone name to be used"
}


variable "project_id" {}
variable "region" {}
variable "webapp_subnet" {}
variable "db_subnet" {}
variable "route_name" {}

variable "ports" {}
variable "routing_mode" {}
variable "firewall_rule_name" {}
variable "custom_image" {}
variable "stack_type" {}

variable "boot_disk_type" {}
variable "boot_disk_size" {}
variable "machine_type" {}
variable "nw_tier" {}
variable "prov_model" {}
variable "boot_disk_mode" {}
variable "on_host_maintenance" {}
variable "ssh_port" {}
variable "deletion_policy" {}
variable "vpc_peering_ip_range" {}
variable "purpose" {}
variable "addr_type" {}
variable "prefix_len" {}
variable "db_ver" {}
variable "sql_name" {}
variable "firewall_rule_deny_name" {}
variable "sql_disk_type" {}
variable "sql_disk_size" {}
variable "avb_type" {}
variable "sql_tier" {}
variable "db_name" {}
variable "firewall_rule_name_allowdb" {}
variable "tag" {}
variable "egress" {}
variable "deny_db_all" {}
variable "aws_region" {}
variable "aws_access" {}
variable "aws_secret" {}
variable "connector_ip_range" {}
variable "connector_name" {}
variable "function_runtime" {}
variable "function_entry" {}
variable "bucket_name" {}
variable "bucket_object" {}
variable "retention_in_secs" {}


resource "google_compute_network" "my_vpc" {
  name                            = var.vpc_name
  auto_create_subnetworks         = false
  routing_mode                    = var.routing_mode
  delete_default_routes_on_create = true
}

resource "google_compute_subnetwork" "webapp_subnet" {
  name = var.webapp_subnet
  region        = var.region
  network       = google_compute_network.my_vpc.self_link
  ip_cidr_range = var.webapp_subnet_cidr
}

# Route for webapp subnet to access internet
resource "google_compute_route" "webapp_route" {
  name             = var.route_name
  network          = google_compute_network.my_vpc.self_link
  dest_range       = "0.0.0.0/0"
  next_hop_gateway = "global/gateways/default-internet-gateway"
  priority         = 1000
}

#Firewall rule to allow traffic to the application port and deny SSH port from the internet
resource "google_compute_firewall" "app_firewall" {
  name    = var.firewall_rule_name
  network = google_compute_network.my_vpc.self_link

  allow {
    protocol = "tcp"
    ports    = [var.ports] # Assuming app_port is a variable defining the application port
  }
  source_ranges = ["0.0.0.0/0"] # Allow traffic from the internet

}

resource "google_compute_firewall" "app_firewall_allow_ssh" {
  name    = "firewall-rule-allow-ssh"
  network = google_compute_network.my_vpc.self_link

  source_ranges = ["0.0.0.0/0"] # Allow traffic from the internet

  # Exclude SSH (port 22) from allowed ports
  allow {
    protocol = "tcp"
    ports    = [var.ssh_port]
  }
    disabled = true
}



resource "google_compute_firewall" "app_firewall_deny_ssh" {
  name    = var.firewall_rule_deny_name
  network = google_compute_network.my_vpc.self_link

  source_ranges = ["0.0.0.0/0"] # Allow traffic from the internet

  # Exclude SSH (port 22) from allowed ports
  deny {
    protocol = "tcp"
    ports    = [var.ssh_port]
  }
    disabled = false

}


resource "google_compute_instance" "vpc-instance-cloud" {
  boot_disk {
    auto_delete = true
    device_name = var.vpc_instance_name
	#depends_on          = [google_service_account.service_account]
    initialize_params {
      image = var.custom_image
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }

    mode = var.boot_disk_mode
  }

  can_ip_forward      = true
  deletion_protection = false
  enable_display      = false

  machine_type = var.machine_type
  name         = var.vpc_instance_name

  network_interface {
    access_config {
      network_tier = var.nw_tier
    }

    queue_count = 0
    stack_type  = var.stack_type
    subnetwork  = google_compute_subnetwork.webapp_subnet.self_link
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = var.on_host_maintenance
    preemptible         = false
    provisioning_model  = var.prov_model
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = false
    enable_vtpm                 = true
  }

  tags = ["http-server", "https-server",var.tag]
  zone = var.zone

  metadata = {
    startup-script = <<-EOT
#!/bin/bash
set -e
application_properties="/opt/application.properties"
if [ ! -f "$application_properties" ]; then
  touch "$application_properties"
	echo "spring.datasource.username=${google_sql_user.cloudsql_user.name}" >> /opt/application.properties
	echo "spring.datasource.password=${random_password.db_password.result}" >> /opt/application.properties
	echo "spring.datasource.url=jdbc:postgresql://${google_sql_database_instance.cloudsql_instance.ip_address.0.ip_address}:5432/${google_sql_database.cloudsql_database.name}" >> /opt/application.properties
	echo "spring.datasource.driver-class-name=org.postgresql.Driver" >> /opt/application.properties
	echo "server.port=8080" >> /opt/application.properties
	echo "spring.jpa.generate-ddl=true" >> /opt/application.properties
	echo "spring.jpa.hibernate.ddl-auto=create-drop" >> /opt/application.properties
	echo "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration" >> /opt/application.properties
	echo "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect" >> /opt/application.properties
	echo "logging.level.org.springframework.security=DEBUG" >> /opt/application.properties
	echo "spring.mvc.throw-exception-if-no-handler-found=true" >> /opt/application.properties
	echo "pubsub.topic=verify_email" >> /opt/application.properties
	echo "gcp.prjt=cloud-nw-dev" >> /opt/application.properties
fi
sudo chown -R csye6225:csye6225 /opt/
EOT
}
  
  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.service_account.email
    scopes = ["cloud-platform","monitoring-write","logging-write","https://www.googleapis.com/auth/logging.admin"]
  }
  allow_stopping_for_update = true
}

# end of compute engine

resource "google_dns_record_set" "app_dns" {
  name    = var.domain_name
  type    = "A"
  ttl     = 30 # Adjust TTL as needed
  rrdatas = [google_compute_instance.vpc-instance-cloud.network_interface[0].access_config[0].nat_ip]
  managed_zone = var.dns_zone_name
}



resource "google_compute_global_address" "private_ip_alloc" {
  name          = "private-ip-alloc"
  purpose       = var.purpose
  address_type  = var.addr_type
  prefix_length = var.prefix_len
  network       = google_compute_network.my_vpc.id
  address       = var.vpc_peering_ip_range

}

resource "google_service_networking_connection" "default2" {
  network                 = google_compute_network.my_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc.name]
  deletion_policy		  = var.deletion_policy

}

# CloudSQL instance
resource "google_sql_database_instance" "cloudsql_instance" {
  name                = var.sql_name
  region              = var.region
  database_version    = var.db_ver
  deletion_protection = false
  depends_on          = [google_service_networking_connection.default2]

  settings {
	backup_configuration{
		enabled = true
		point_in_time_recovery_enabled = true
	}
	ip_configuration {
		ipv4_enabled = false
		private_network = google_compute_network.my_vpc.id
		enable_private_path_for_google_cloud_services = true
    }
    disk_type         = var.sql_disk_type
    disk_size         = var.sql_disk_size
    availability_type = var.avb_type
    tier              = var.sql_tier # You can adjust the tier according to your needs
  }
}

# CloudSQL database
resource "google_sql_database" "cloudsql_database" {
  name     = var.db_name
  instance = google_sql_database_instance.cloudsql_instance.name
}

# Random password generation
resource "random_password" "db_password" {
  length  = 16
  special = false
}

# CloudSQL database user
resource "google_sql_user" "cloudsql_user" {
  name     = random_string.db_user.result
  instance = google_sql_database_instance.cloudsql_instance.name
  password = random_password.db_password.result
}

resource "random_string" "db_user" {
  length           = 16
  special          = false
  numeric			= false
}

#Firewall rule to allow traffic to the application port and deny SSH port from the internet
resource "google_compute_firewall" "app_firewall_allowdb" {
  name    = var.firewall_rule_name_allowdb
  network = google_compute_network.my_vpc.self_link 
  priority = 999
  direction	= var.egress
  target_tags =	[var.tag]
  allow {
    protocol = "tcp"
    ports    = ["5432"] 
  }
  destination_ranges = [var.db_subnet_cidr]
}

resource "google_compute_firewall" "app_firewall_deny_db_all" {
  name    = var.deny_db_all
  priority = 1000
  network = google_compute_network.my_vpc.self_link
  direction	= var.egress
  destination_ranges = [var.db_subnet_cidr]
  disabled = true
  deny {
    protocol = "all"
  }
}


resource "google_service_account" "service_account" {
  account_id   = "service-account-id"
  display_name = "Service Account"
  create_ignore_already_exists = true
}

resource "google_project_iam_binding" "logging_admin_binding" {
  project = var.project_id
  role    = "roles/logging.admin"
  
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

resource "google_project_iam_binding" "monitoring_metric_writer_binding" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

resource "google_project_iam_binding" "publisher_binding" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}


resource "google_pubsub_topic" "verify_email_topic" {
  name = "verify_email"
   message_retention_duration = var.retention_in_secs
}

resource "google_pubsub_subscription" "verify_email_subscription" {
depends_on = [google_cloudfunctions_function.verify_email_function]
  name   = "verify_email_subscription"
  topic  = google_pubsub_topic.verify_email_topic.name
  ack_deadline_seconds = 10 // Adjust as needed

}

resource "google_cloudfunctions_function" "verify_email_function" {
  name        = "verify-email-function"
  runtime     = var.function_runtime
  entry_point = var.function_entry
  source_archive_bucket = var.bucket_name
  source_archive_object = var.bucket_object
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.verify_email_topic.name
  }
  ingress_settings	= "ALLOW_ALL"
	vpc_connector = google_vpc_access_connector.connector.id
	vpc_connector_egress_settings = "PRIVATE_RANGES_ONLY"
  environment_variables = {
    INSTANCE_CONNECTION_NAME = google_sql_database_instance.cloudsql_instance.connection_name
    DB_USER       = google_sql_user.cloudsql_user.name
	DB_PASS		= random_password.db_password.result
	DB_NAME		= google_sql_database.cloudsql_database.name
	AWS_REGION	= var.aws_region
	AWS_ACCESS_KEY = var.aws_access
	AWS_SECRET	= var.aws_secret
  }
}


resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.verify_email_function.project
  region         = google_cloudfunctions_function.verify_email_function.region
  cloud_function = google_cloudfunctions_function.verify_email_function.name

  role   = "roles/cloudfunctions.invoker"
  member = "allUsers"
}

resource "google_vpc_access_connector" "connector" {
  name          = var.connector_name
  ip_cidr_range = var.connector_ip_range
  network       = google_compute_network.my_vpc.self_link
}