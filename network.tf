provider "google" {
  credentials = file(var.creds)
  project     = var.project_id
  region      = var.region
}

variable "creds" {}}


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

resource "google_compute_network" "my_vpc" {
  name                            = var.vpc_name
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = true
}

resource "google_compute_subnetwork" "webapp_subnet" {
  name          = var.webapp_subnet

  region        = var.region
  network       = google_compute_network.my_vpc.self_link
  ip_cidr_range = var.webapp_subnet_cidr
}

resource "google_compute_subnetwork" "db_subnet" {
  name          = var.db_subnet

  region        = var.region
  network       = google_compute_network.my_vpc.self_link
  ip_cidr_range = var.db_subnet_cidr
}


# Route for webapp subnet to access internet
resource "google_compute_route" "webapp_route" {
  name             = var.route_name
  network          = google_compute_network.my_vpc.self_link
  dest_range       = "0.0.0.0/0"
  next_hop_gateway = "global/gateways/default-internet-gateway"

  priority         = 1000
}
