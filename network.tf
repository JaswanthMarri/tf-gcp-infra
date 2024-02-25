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
variable "firewall_rule_deny_name" {}

resource "google_compute_network" "my_vpc" {
  name                            = var.vpc_name
  auto_create_subnetworks         = false
  routing_mode                    = var.routing_mode
  delete_default_routes_on_create = true
}

resource "google_compute_subnetwork" "webapp_subnet" {
  name          = var.webapp_subnet

  region        = var.region
  network       = google_compute_network.my_vpc.self_link
  ip_cidr_range = var.webapp_subnet_cidr
}

#resource "google_compute_subnetwork" "db_subnet" {
#  name          = var.db_subnet
#  region        = var.region
#  network       = google_compute_network.my_vpc.self_link
#  ip_cidr_range = var.db_subnet_cidr
#  private_ip_google_access = true

#}


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
    ports    = [var.ports]  # Assuming app_port is a variable defining the application port
  }
  
  source_ranges = ["0.0.0.0/0"]  # Allow traffic from the internet
  
}

resource "google_compute_firewall" "app_firewall_deny_ssh" {
  name    = var.firewall_rule_deny_name
  network = google_compute_network.my_vpc.self_link

  source_ranges = ["0.0.0.0/0"]  # Allow traffic from the internet
  
    # Exclude SSH (port 22) from allowed ports
  deny {
    protocol = "tcp"
    ports    = [var.ssh_port]
  }
}


resource "google_compute_instance" "vpc-instance-cloud" {
  boot_disk {
    auto_delete = true
    device_name = var.vpc_instance_name

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

  tags = ["http-server", "https-server"]
  zone = var.zone
}


# [START compute_internal_ip_private_access]
#resource "google_compute_global_address" "db-ip" {
#  name         = "db-ip"
#  address_type = "INTERNAL"
#  purpose      = "PRIVATE_SERVICE_CONNECT"
#  network      = google_compute_network.my_vpc.id
#  address		= "10.3.0.5"
  #prefix_length = 24 
#}
# [END compute_internal_ip_private_access]

# [START compute_forwarding_rule_private_access]
#resource "google_compute_global_forwarding_rule" "default1" {
#  name                  = "globalrule"
#  target                =  "all-apis"	  #google_sql_database_instance.cloudsql_instance.self_link
#  network               = google_compute_network.my_vpc.id
#  ip_address            = google_compute_global_address.db-ip.id
#  load_balancing_scheme = ""
#}
# [END compute_forwarding_rule_private_access]

resource "google_compute_global_address" "private_ip_alloc" {
  name          = "private-ip-alloc"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 24
  network       = google_compute_network.my_vpc.id
  address		= "10.0.4.0"
}

resource "google_service_networking_connection" "default2" {
  network                 = google_compute_network.my_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_alloc.name] 
  #reserved_peering_ranges = ["10.0.5.0/24"]
}

# CloudSQL instance
resource "google_sql_database_instance" "cloudsql_instance" {
  name             = "my-cloudsql-instance"
  region           = var.region
  database_version = "POSTGRES_9_6"
  deletion_protection = false
	depends_on = [google_service_networking_connection.default2]
  settings {
	backup_configuration{
		enabled = true
		point_in_time_recovery_enabled = true
	}
	ip_configuration {
		ipv4_enabled = false
		private_network = google_compute_network.my_vpc.id
		#private_network = google_compute_subnetwork.db_subnet.id
		enable_private_path_for_google_cloud_services = true

    }
	disk_type           = "pd-ssd"
	disk_size           = 100
	availability_type = "REGIONAL"
    tier = "db-f1-micro"  # You can adjust the tier according to your needs
  }
  
}

# CloudSQL database
resource "google_sql_database" "cloudsql_database" {
  name     = "test_db"
  instance = google_sql_database_instance.cloudsql_instance.name
}

# Random password generation
resource "random_password" "db_password" {
  length  = 16
  special = true
}

# CloudSQL database user
resource "google_sql_user" "cloudsql_user" {
  name     = "user"
  instance = google_sql_database_instance.cloudsql_instance.name
  password = "password"		#random_password.db_password.result
}
