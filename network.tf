provider "google" {
  credentials = file(var.creds)
  project     = var.project_id
  region      = var.region
}

provider "google-beta" {
  credentials = file(var.creds)
  project     = var.project_id
  region      = var.region
}

#############################################
data "google_service_account" "provider_account" {
  account_id = "1027887585503-compute@developer.gserviceaccount.com"  # Replace with your service account ID
}


###########################################################################

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

#############################################################################################

#Iam Binding for service role

resource "google_project_iam_binding" "provider_service_account_binding" {
  project = var.project_id
  role    = "roles/cloudfunctions.admin"  # Replace [IAM_ROLE] with the desired IAM role, e.g., roles/storage.admin

  members = [    "serviceAccount:${data.google_service_account.provider_account.email}"]
}

resource "google_project_iam_binding" "sql_admin_provider_service_account_binding" {
  project = var.project_id
  role    = "roles/cloudsql.admin"  # Replace [IAM_ROLE] with the desired IAM role, e.g., roles/storage.admin

  members = [
    "serviceAccount:${data.google_service_account.provider_account.email}"
  ]
}

resource "google_project_iam_binding" "sql_client_provider_service_account_binding" {
  project = var.project_id
  role    = "roles/cloudsql.client"  # Replace [IAM_ROLE] with the desired IAM role, e.g., roles/storage.admin

  members = [
    "serviceAccount:${data.google_service_account.provider_account.email}"
  ]
}


resource "google_project_iam_binding" "nw_admin_provider_service_account_binding" {
  project = var.project_id
  role    = "roles/compute.networkAdmin"  # Replace [IAM_ROLE] with the desired IAM role, e.g., roles/storage.admin

  members = [
    "serviceAccount:${data.google_service_account.provider_account.email}"
  ]
}
/*
resource "google_project_iam_binding" "iam_admin_provider_service_account_binding" {
  project = var.project_id
  role    = "roles/resourcemanager.projectIamAdmin"  # Replace [IAM_ROLE] with the desired IAM role, e.g., roles/storage.admin

  members = [
    "serviceAccount:${data.google_service_account.provider_account.email}"
  ]
}
*/


resource "google_project_iam_binding" "token_creator_provider_service_account_binding" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"  # Replace [IAM_ROLE] with the desired IAM role, e.g., roles/storage.admin

  members = [
    "serviceAccount:${data.google_service_account.provider_account.email}"
  ]
}

/*
resource "google_project_iam_binding" "secret_provider_service_account_binding" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  members = ["serviceAccount:${data.google_service_account.provider_account.email}","serviceAccount:github-actions@cloud-nw-dev.iam.gserviceaccount.com"]
  
}
*/

###########################################################################

resource "google_service_account" "service_account" {
  account_id   = "service-account-id"
  display_name = "Service Account"
  create_ignore_already_exists = true
}

###########################################################################

resource "google_project_iam_binding" "logging_admin_binding" {
  project = var.project_id
  role    = "roles/logging.admin"
  
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

###########################################################################

resource "google_project_iam_binding" "monitoring_metric_writer_binding" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

###########################################################################

resource "google_project_iam_binding" "publisher_binding" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  
  members = [
    "serviceAccount:${google_service_account.service_account.email}"
  ]
}

###############################################################################
#SSL Certification

resource "google_compute_managed_ssl_certificate" "lb_default" {

  provider = google
  name     = "myservice-ssl-cert1"
  lifecycle {
    create_before_destroy = true
  }
  managed {
    domains = ["jaswanthmarri.com"]
  }
}

###########################################################################

resource "google_compute_network" "my_vpc" {
  name                            = var.vpc_name
  auto_create_subnetworks         = false
  routing_mode                    = var.routing_mode
  delete_default_routes_on_create = true
}

###########################################################################

resource "google_compute_subnetwork" "webapp_subnet" {
  name = var.webapp_subnet
  region        = var.region
  network       = google_compute_network.my_vpc.self_link
  ip_cidr_range = var.webapp_subnet_cidr
}

###########################################################################

# Route for webapp subnet to access internet
resource "google_compute_route" "webapp_route" {
  name             = var.route_name
  network          = google_compute_network.my_vpc.self_link
  dest_range       = "0.0.0.0/0"
  next_hop_gateway = "global/gateways/default-internet-gateway"
  priority         = 1000
}


#############################################################################
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

###########################################################################

resource "google_compute_global_address" "private_ip_alloc" {
  name          = "private-ip-alloc"
  purpose       = var.purpose
  address_type  = var.addr_type
  prefix_length = var.prefix_len
  network       = google_compute_network.my_vpc.id
  address       = var.vpc_peering_ip_range

}
###########################################################################

resource "google_service_networking_connection" "default2" {
  network                 = google_compute_network.my_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc.name]
  deletion_policy		  = var.deletion_policy
}

###########################################################################

resource "random_string" "random-key-ring" {
  length           = 16
  special          = false

}

# Create a Key Ring
resource "google_kms_key_ring" "example1" {
  name     = "webapp-key-ring-${random_string.random-key-ring.result}"
  location = var.region
}

# Create Customer-Managed Encryption Keys for CloudSQL Instances
resource "google_kms_crypto_key" "cloudsql_key" {
  name            = "cloudsql-cmek-key"
  key_ring        = google_kms_key_ring.example1.id
  rotation_period = "2592000s"
}


# Create Customer-Managed Encryption Keys for Virtual Machines
resource "google_kms_crypto_key" "vm_key" {
  name            = "vm-cmek-key"
  key_ring        = google_kms_key_ring.example1.id
  rotation_period = "2592000s"
}

# Create Customer-Managed Encryption Keys for Cloud Storage Buckets
resource "google_kms_crypto_key" "storage_key" {
  name            = "storage-cmek-key"
  key_ring        = google_kms_key_ring.example1.id
  rotation_period = "2592000s"
}

###################################################

resource "google_project_service_identity" "gcp_sa_cloud_sql" {
  provider = google-beta
  service  = "sqladmin.googleapis.com"
}

/*
resource "google_project_iam_binding" "crypto_key" {
  #provider      = google
  #crypto_key_id = google_kms_crypto_key.cloudsql_key.id
  project = var.project_id
  role          = "roles/cloudkms.admin"

  #members = ["serviceAccount:${data.google_service_account.provider_account.email}"]
  members = ["serviceAccount:${google_project_service_identity.gcp_sa_cloud_sql.email}"]
}
*/

resource "google_kms_crypto_key_iam_binding" "de_crypto_key" {
  provider      = google
  crypto_key_id = google_kms_crypto_key.cloudsql_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  #members = ["serviceAccount:${data.google_service_account.provider_account.email}"]
  members = ["serviceAccount:${google_project_service_identity.gcp_sa_cloud_sql.email}"]
}


data "google_kms_key_ring" "my_key_ring" {
  name     = "webapp"
  location = "us-east1"
}

/*
data "google_kms_crypto_key" "my_crypto_key" {
  name     = "cloudsql-key"
  key_ring = data.google_kms_key_ring.my_key_ring.id
}
*/

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
  encryption_key_name = google_kms_crypto_key.cloudsql_key.id
}

###########################################################################

# CloudSQL database
resource "google_sql_database" "cloudsql_database" {
  name     = var.db_name
  instance = google_sql_database_instance.cloudsql_instance.name
}

###########################################################################

# Random password generation
resource "random_password" "db_password" {
  length  = 16
  special = false
}

###########################################################################

# CloudSQL database user
resource "google_sql_user" "cloudsql_user" {
  name     = random_string.db_user.result
  instance = google_sql_database_instance.cloudsql_instance.name
  password = random_password.db_password.result
}

###########################################################################

resource "random_string" "db_user" {
  length           = 16
  special          = false
  numeric			= false
}

###########################################################################

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

###########################################################################

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

###########################################################################

resource "google_pubsub_topic" "verify_email_topic" {
  name = "verify_email"
   message_retention_duration = var.retention_in_secs
}

###########################################################################

resource "google_pubsub_subscription" "verify_email_subscription" {
depends_on = [google_cloudfunctions_function.verify_email_function]
  name   = "verify_email_subscription"
  topic  = google_pubsub_topic.verify_email_topic.name
  ack_deadline_seconds = 10 // Adjust as needed

}

###########################################################################

resource "google_cloudfunctions_function" "verify_email_function" {

  depends_on  = [google_storage_bucket_object.default,google_project_iam_binding.provider_service_account_binding]
  service_account_email  = data.google_service_account.provider_account.email
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

###########################################################################
#Invoker for serverless

resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.verify_email_function.project
  region         = google_cloudfunctions_function.verify_email_function.region
  cloud_function = google_cloudfunctions_function.verify_email_function.name

  role   = "roles/cloudfunctions.invoker"
  member = "allUsers"
}

###########################################################################
# Vpc access connector for serverless

resource "google_vpc_access_connector" "connector" {
  name          = var.connector_name
  ip_cidr_range = var.connector_ip_range
  network       = google_compute_network.my_vpc.self_link
}

###########################################################################
#Bucket config

data "google_storage_project_service_account" "gcs_account" {
}


resource "google_kms_crypto_key_iam_binding" "de_crypto_bucket_key" {
  provider      = google
  crypto_key_id = google_kms_crypto_key.storage_key.id
  #project = var.project_id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  members = ["serviceAccount:${data.google_storage_project_service_account.gcs_account.email_address}"]
}

resource "google_storage_bucket" "example_bucket" {
  name     = var.bucket_name
  location = var.region
  depends_on  = [google_kms_crypto_key_iam_binding.de_crypto_bucket_key]

  encryption {
    default_kms_key_name = google_kms_crypto_key.storage_key.id
  }
}

# Upload a text file as an object
# to the storage bucket

resource "google_storage_bucket_object" "default" {
 name         = var.bucket_object
 source       = "./${var.bucket_object}"
 bucket       = google_storage_bucket.example_bucket.id
}

####################################################################

resource "google_kms_crypto_key_iam_binding" "de_crypto_vm_key" {
  provider      = google
  crypto_key_id = google_kms_crypto_key.vm_key.id
  #project = var.project_id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = ["serviceAccount:service-1027887585503@compute-system.iam.gserviceaccount.com"]
}

####################################################################

# intance template
resource "google_compute_region_instance_template" "vpc-instance-cloud" {

  disk {
    source_image  = var.custom_image
	disk_size_gb  = var.boot_disk_size
    disk_type  = var.boot_disk_type
    auto_delete       = true
    boot              = true
	disk_name		= var.vpc_instance_name
    #resource_policies = [google_compute_resource_policy.daily_backup.id]
    mode = var.boot_disk_mode
	
	disk_encryption_key{
		kms_key_self_link = google_kms_crypto_key.vm_key.id
	}
  }

  can_ip_forward      = true
  #enable_display      = false

  machine_type = var.machine_type
  name         = var.vpc_instance_name
	#deletion_protection = false
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

  tags = ["http-server", "https-server",var.tag,"load-balanced-backend"]

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
	echo "spring.jpa.hibernate.ddl-auto=update" >> /opt/application.properties
	echo "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration" >> /opt/application.properties
	echo "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect" >> /opt/application.properties
	echo "logging.level.org.springframework.security=DEBUG" >> /opt/application.properties
	echo "spring.mvc.throw-exception-if-no-handler-found=true" >> /opt/application.properties
	echo "pubsub.topic=verify_email" >> /opt/application.properties
	echo "gcp.prjt=cloud-nw-dev" >> /opt/application.properties
	echo "spring.datasource.hikari.max-lifetime=12000" >> /opt/application.properties
	echo "spring.datasource.hikari.maximumPoolSize=4" >> /opt/application.properties
fi
sudo chown -R csye6225:csye6225 /opt/
EOT
}
    service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email  = google_service_account.service_account.email
    scopes = ["cloud-platform","monitoring-write","logging-write","https://www.googleapis.com/auth/logging.admin"]
  }
  #allow_stopping_for_update = true
  
}


###################################################################
# health check 
resource "google_compute_health_check" "autohealing" {
  name                = "autohealing-health-check"
  check_interval_sec  = 30
  timeout_sec         = 5
  healthy_threshold   = 1
  unhealthy_threshold = 2
  #region  = "us-east1"

  http_health_check {
    request_path = "/healthz"
	port = 8080
	port_specification = "USE_FIXED_PORT"
    proxy_header       = "NONE"
  }
  log_config{
	enable	= true
  }
}


###############################################

# External Ip reserved for Load balancer
resource "google_compute_global_address" "default" {
    name         = "lb-ip-global"
  address_type = "EXTERNAL"
}

########################################################
#Autoscaler
resource "google_compute_region_autoscaler" "foobar" {
  name   = "my-region-autoscaler"
  region = var.region
  target = google_compute_region_instance_group_manager.default.id

  autoscaling_policy {
  
    max_replicas    = 2
    min_replicas    = 1
    cooldown_period = 60

    cpu_utilization {
      target = 0.05
    }
  }
}


##########################################################
# IGM for the VMs

resource "google_compute_region_instance_group_manager" "default" {
  name = "appserver-igm"

  base_instance_name         = "app"
  region                     =  var.region
  distribution_policy_zones  = ["us-east1-b", "us-east1-c", "us-east1-d"]

  version {
    instance_template = google_compute_region_instance_template.vpc-instance-cloud.id
  }

  all_instances_config {
    metadata = {
      metadata_key = "metadata_value"
    }
    labels = {
      label_key = "label_value"
    }
  }

  #target_pools = [google_compute_target_pool.appserver.id]
  #target_size  = 2

  named_port {
    name = "http"
    port = 8080
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.autohealing.id
    initial_delay_sec = 180
  }
}

#####################################################
# DNS Record points to load balancer 
resource "google_dns_record_set" "app_dns" {
  name    = var.domain_name
  type    = "A"
  ttl     = 30 # Adjust TTL as needed
  rrdatas = [google_compute_global_address.default.address] #load balancer ip addr
  managed_zone = var.dns_zone_name
}


########################################################
# Firewall rule for health check
resource "google_compute_firewall" "default" {
  name = "fw-allow-health-check"
  allow {
    protocol = "tcp"
  }
  direction     = "INGRESS"
  network       = google_compute_network.my_vpc.id
  priority      = 999
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["load-balanced-backend"]
}
########################################################
# Firewall rules to allow trffic from proxy subnet to webapp subnet
resource "google_compute_firewall" "allow_proxy" {
  name = "fw-allow-proxies"
  allow {
    ports    = ["443"]
    protocol = "tcp"
  }
  allow {
    ports    = ["80"]
    protocol = "tcp"
  }
  allow {
    ports    = ["8080"]
    protocol = "tcp"
  }
  direction     = "INGRESS"
  network       = google_compute_network.my_vpc.id
  priority      = 999
  source_ranges = ["10.129.0.0/23"]
  target_tags   = ["load-balanced-backend"]
}
########################################################
#Proxy subnet, traffic needs to go through this!
resource "google_compute_subnetwork" "proxy_only" {
  name          = "proxy-only-subnet"
  ip_cidr_range = "10.129.0.0/23"
  network       = google_compute_network.my_vpc.id
  purpose       = "REGIONAL_MANAGED_PROXY"
  region        = "us-east1"
  role          = "ACTIVE"
}


###########################################################################

#Deny all traffic to webapp
resource "google_compute_firewall" "app_firewall_deny" {
  name    = var.firewall_rule_deny_name
  network = google_compute_network.my_vpc.self_link
  source_ranges = ["0.0.0.0/0"] 
  deny {
    protocol = "all"
  }
    disabled = false
}


##################################################
# Proxy definition

resource "google_compute_target_https_proxy" "default" {
  name    = "l7-xlb-proxy"
  #region  = "us-east1"
    http_keep_alive_timeout_sec = 610
  url_map = google_compute_url_map.default.id
  ssl_certificates = [
	google_compute_managed_ssl_certificate.lb_default.name
  ]
  depends_on = [
    google_compute_managed_ssl_certificate.lb_default
  ]
}
##############################################


# rule to forward traffic to proxy 
resource "google_compute_global_forwarding_rule" "default" {
  name       = "l7-xlb-forwarding-rule"
  depends_on = [google_compute_subnetwork.proxy_only]
  #region     = "us-east1"

  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.default.id
  #network               = google_compute_network.my_vpc.id
  ip_address            = google_compute_global_address.default.id
  #network_tier          = "STANDARD"
}

# rule to forward traffic to proxy 
resource "google_compute_global_forwarding_rule" "default_8080" {
  name       = "l7-xlb-8080-forwarding-rule"
  depends_on = [google_compute_subnetwork.proxy_only]
  #region     = "us-east1"

  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "8080"
  target                = google_compute_target_https_proxy.default.id
  #network               = google_compute_network.my_vpc.id
  ip_address            = google_compute_global_address.default.id
  #network_tier          = "STANDARD"
}


###############################################
#Url map for load balancer

resource "google_compute_url_map" "default" {
  name            = "regional-l7-xlb-map"
  #region          = "us-east1"
  default_service = google_compute_backend_service.default.id
}

#############################################################
# backend for load balancer

resource "google_compute_backend_service" "default" {
  name                  = "l7-xlb-backend-service"
  #region                = "us-east1"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  health_checks         = [google_compute_health_check.autohealing.id]
  protocol              = "HTTP"
  session_affinity      = "NONE"
  timeout_sec           = 30
  backend {
    group           = google_compute_region_instance_group_manager.default.instance_group
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
  cdn_policy {
  cache_key_policy {
      include_host = true
      include_protocol = true
      include_query_string = true
	  }
	}
  log_config{
  enable	= true
  sample_rate	= 1
  }
}

##################################################################################


resource "google_secret_manager_secret" "secret-basic-sql-username" {
  secret_id = "sql-username"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "sql-username-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-sql-username.id
  secret_data = google_sql_user.cloudsql_user.name

}

##################################################################################


resource "google_secret_manager_secret" "secret-basic-sql-password" {
  secret_id = "sql-password"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "sql-password-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-sql-password.id
  secret_data = random_password.db_password.result

}
##################################################################################


resource "google_secret_manager_secret" "secret-basic-sql-db-ip" {
  secret_id = "sql-db-ip"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "db-ip-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-sql-db-ip.id
  secret_data = google_sql_database_instance.cloudsql_instance.ip_address.0.ip_address

}


##################################################################################


resource "google_secret_manager_secret" "secret-basic-sql-db-name" {
  secret_id = "sql-db-name"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "db-name-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-sql-db-name.id
  secret_data = google_sql_database.cloudsql_database.name

}

##################################################################################


resource "google_secret_manager_secret" "secret-basic-vm-sa" {
  secret_id = "vm-sa"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "sa-vm-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-vm-sa.id
  secret_data = google_service_account.service_account.email

}
##################################################################################

resource "google_secret_manager_secret" "secret-basic-vm-kms" {
  secret_id = "vm-kms"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "kms-vm-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-vm-kms.id
  secret_data = google_kms_crypto_key.vm_key.id

}

##################################################################################

resource "google_secret_manager_secret" "secret-basic-vpc-name" {
  secret_id = "vpc-name"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "vpc-name-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-vpc-name.id
  secret_data = google_compute_network.my_vpc.self_link

}

##################################################################################


resource "google_secret_manager_secret" "secret-basic-vpc-subnet-name" {
  secret_id = "vpc-subnet-name"
  replication {
  user_managed {
    replicas {
	location = "us-east1"
  }
  }
  }
}

resource "google_secret_manager_secret_version" "vpc-subnet-name-secret" {
  #depends_on = [google_project_iam_binding.secret_provider_service_account_binding]
  secret = google_secret_manager_secret.secret-basic-vpc-subnet-name.id
  secret_data = google_compute_subnetwork.webapp_subnet.self_link
}
