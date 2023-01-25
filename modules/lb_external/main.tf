terraform {
  required_providers {
    google = { version = "~> 3.30" }
  }
}

data "google_client_config" "this" {}

locals {
  # If we were told an exact region, use it, otherwise fall back to a client-default region
  region = coalesce(var.region, data.google_client_config.this.region)

  # Check for `L3_DEFAULT` as this requires `google_compute_backend_service` and `google_compute_health_check` resources.
  backend_service_needed = contains([for k, v in var.rules : lookup(v, "ip_protocol", null)], "L3_DEFAULT")

  # Check for protocols that require a `google_compute_target_pool` backend and `google_compute_http_health_check` health check
  target_pool_protocols = ["TCP", "UDP", "ESP", "AH", "SCTP", "ICMP"]
  target_pool_needed    = contains([for k, v in var.rules : contains(local.target_pool_protocols, lookup(v, "ip_protocol", "TCP"))], true)
}

# Create external IP addresses if non-specified
resource "google_compute_address" "this" {
  for_each = { for k, v in var.rules : k => v if !can(v.ip_address) }

  name         = each.key
  address_type = "EXTERNAL"
  region       = var.region
  project      = var.project
}

# Create forwarding rule for each specified rule
# resource "google_compute_forwarding_rule" "rule" {
#   for_each = var.rules

#   name    = each.key
#   project = var.project
#   region  = local.region

#   # Check if `ip_protocol` is specified (if not assume default of `TCP`) != `L3_DEFAULT` if true then use `google_compute_target_pool` as backend
#   target = lookup(each.value, "ip_protocol", "TCP") != "L3_DEFAULT" ? google_compute_target_pool.this[0].self_link : null

#   # Check if `ip_protocol` is specified (if not assume default of `TCP`) == `L3_DEFAULT` if true then use `google_compute_backend_service` as backend
#   backend_service       = lookup(each.value, "ip_protocol", "TCP") == "L3_DEFAULT" ? google_compute_backend_service.this[0].self_link : null
#   load_balancing_scheme = "EXTERNAL"

#   # Check if `ip_protocol` is specified (if not assume default of `TCP`) == `L3_DEFAULT`.
#   #   If true then set `all_ports` to `true`.
#   #   If false set value to the value of `all_ports`. If `all_ports` isn't specified, then set the value to `null`.
#   all_ports = lookup(each.value, "ip_protocol", "TCP") == "L3_DEFAULT" ? true : lookup(each.value, "all_ports", null)

#   # Check if `ip_protocol` is specified (if not assume default of `TCP`) == `L3_DEFAULT`.
#   #   If true then set `port_range` to `null`.
#   #   If false set value to the value of `port_range`. If `port_range` isn't specified, then set the value to `null`.
#   port_range = lookup(each.value, "ip_protocol", "TCP") == "L3_DEFAULT" ? null : lookup(each.value, "port_range", null)

#   ip_address  = try(each.value.ip_address, google_compute_address.this[each.key].address)
#   ip_protocol = lookup(each.value, "ip_protocol", "TCP")
# }

# resource "google_compute_forwarding_rule" "rule" {
#   for_each = var.rules
#   provider              = google-beta

#   project = var.project
#   name                  = each.key
#   region                = "us-central1"
#   port_range            = 80
#   backend_service       = google_compute_backend_service.this[0].self_link
# }

# Front end of the load balancer
resource "google_compute_global_forwarding_rule" "rule" {
  for_each = var.rules
  name       = each.key
  target     = google_compute_target_http_proxy.default.self_link
  port_range = "80"
}

resource "google_compute_target_http_proxy" "default" {
  name    = "armor-proxy"
  url_map = google_compute_url_map.default.self_link
}

resource "google_compute_url_map" "default" {
  name            = var.name
  default_service = google_compute_backend_service.this[0].self_link

  host_rule {
    hosts        = ["mysite.com"]
    path_matcher = "allpaths"
  }

  path_matcher {
    name            = "allpaths"
    default_service = google_compute_backend_service.this[0].self_link

    path_rule {
      paths   = ["/*"]
      service = google_compute_backend_service.this[0].self_link
    }
  }
}









# Create `google_compute_target_pool` if required by `var.rules`
resource "google_compute_target_pool" "this" {
  count            = local.target_pool_needed ? 1 : 0
  name             = var.name
  session_affinity = var.session_affinity
  instances        = var.instances
  health_checks    = var.create_health_check ? [google_compute_http_health_check.this[0].self_link] : []
  region           = var.region
  project          = var.project

  lifecycle {
    # Ignore changes because autoscaler changes this in the background.
    ignore_changes = [instances]
  }
}

# Create `google_compute_http_health_check` if required by `var.rules`
resource "google_compute_http_health_check" "this" {
  count = var.create_health_check && local.target_pool_needed ? 1 : 0

  name                = "${var.name}-${local.region}"
  check_interval_sec  = var.health_check_interval_sec
  healthy_threshold   = var.health_check_healthy_threshold
  timeout_sec         = var.health_check_timeout_sec
  unhealthy_threshold = var.health_check_unhealthy_threshold
  port                = var.health_check_http_port
  request_path        = var.health_check_http_request_path
  host                = var.health_check_http_host
  project             = var.project
}

# Create `google_compute_backend_service` if require by `var.rules`
resource "google_compute_backend_service" "this" {
  provider = google-beta

  count = local.backend_service_needed ? 1 : 0

  name                  = var.name
  # region                = local.region
  load_balancing_scheme = "EXTERNAL"
  health_checks         = var.create_health_check ? [google_compute_health_check.this[0].self_link] : []
  protocol              = "HTTP" #"UNSPECIFIED"
  project               = var.project

  # dynamic "backend" {
  #   for_each = var.backend_instance_groups
  #   content {
  #     group = backend.value
  #     # balancing_mode = "CONNECTION"
  #     # max_rate = 1
  #   }
  # }

  backend {
    group = google_compute_instance_group.lb-external-vmseries.id
  }

  security_policy = google_compute_security_policy.security-policy-1.self_link

  # this section requires the google-beta provider as of 2022-04-13
  # connection_tracking_policy {
  #   tracking_mode                                = var.connection_tracking_mode
  #   connection_persistence_on_unhealthy_backends = var.connection_persistence_on_unhealthy_backends
  #   idle_timeout_sec                             = var.idle_timeout_sec
  # }
}

# Create `google_compute_backend_service` if require by `var.rules`
resource "google_compute_health_check" "this" {
  count = var.create_health_check && local.backend_service_needed ? 1 : 0

  name                = "${var.name}-${local.region}"
  project             = var.project
  # region              = local.region
  check_interval_sec  = var.health_check_interval_sec
  healthy_threshold   = var.health_check_healthy_threshold
  timeout_sec         = var.health_check_timeout_sec
  unhealthy_threshold = var.health_check_unhealthy_threshold

  http_health_check {
    port         = var.health_check_http_port
    request_path = var.health_check_http_request_path
    host         = var.health_check_http_host
  }
}

# Cloud Armor Security policies
resource "google_compute_security_policy" "security-policy-1" {
  name        = "armor-security-policy"
  description = "example security policy"

  # Reject all traffic that hasn't been whitelisted.
  rule {
    action   = "deny(403)"
    priority = "2147483647"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = ["*"]
      }
    }

    description = "Default rule, higher priority overrides it"
  }

  # Whitelist traffic from certain ip address
  rule {
    action   = "allow"
    priority = "1000"

    match {
      versioned_expr = "SRC_IPS_V1"

      config {
        src_ip_ranges = var.ip_white_list
      }
    }

    description = "allow traffic from 192.0.2.0/24"
  }
}

variable "ip_white_list" {
  description = "A list of ip addresses that can be white listed through security policies"
  default     = ["192.0.2.0/24", "162.95.216.224/32", "98.160.240.196/32"]
}



## Creating an instance group with the vmseries instances in it
## so that we can control it here instead of in the vmseries autoscaling module
data "google_compute_instance" "lb-external-vmseries" {
  name = "vmseries-p1p9"
  zone = "us-central1-f"
}

resource "google_compute_instance_group" "lb-external-vmseries" {
  name        = "lb-external-vmseries"
  description = "Terraform test instance group"

  instances = [
    data.google_compute_instance.lb-external-vmseries.self_link,
  ]

  named_port {
    name = "http"
    port = "80"
  }

  named_port {
    name = "https"
    port = "443"
  }

  zone = "us-central1-f"
}
