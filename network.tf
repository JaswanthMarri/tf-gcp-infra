provider "google" {
  credentials = file("cloud-nw-dev-creds.json")
  project     = var.project_id
  region      = var.region
}

variable "webapp_subnet_cidr" {
  description = "CIDR range for the webapp subnet"
}

variable "db_subnet_cidr" {
  description = "CIDR range for the db subnet"
}

variable "project_id" {}
variable "region" {}

resource "google_compute_network" "my_vpc" {
  name                  = "my-vpc"
  auto_create_subnetworks = false
  routing_mode          = "REGIONAL"
}


resource "google_compute_subnetwork" "webapp_subnet" {
  name          = "webapp-subnet"
  region        = var.region
  network       = google_compute_network.my_vpc.self_link
  ip_cidr_range = var.webapp_subnet_cidr
}

resource "google_compute_subnetwork" "db_subnet" {
  name          = "db-subnet"
  region        = var.region
  network       = google_compute_network.my_vpc.self_link
  ip_cidr_range = var.db_subnet_cidr
}

# Route for webapp subnet to access internet
resource "google_compute_route" "webapp_route" {
  name             = "webapp-to-internet"
  network          = google_compute_network.my_vpc.self_link
  dest_range       = "0.0.0.0/0"
  next_hop_ip      = google_compute_network.my_vpc.gateway_ipv4
  priority         = 1000
}
