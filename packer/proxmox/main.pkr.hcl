packer {
  required_version = ">= 1.11.0"
  required_plugins {
    proxmox = {
      source  = "github.com/hashicorp/proxmox"
      version = "= 1.2.4"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "= 1.1.6"
    }
  }
}

variable "os_profile" {
  type = string
  validation {
    condition     = contains(["debian-13", "ubuntu-26.04"], var.os_profile)
    error_message = "Select debian-13 or ubuntu-26.04."
  }
}
variable "ssh_user" { type = string }
variable "proxmox_url" {
  type = string
  validation {
    condition     = can(regex("^https://[^/]+/api2/json$", var.proxmox_url))
    error_message = "Use a TLS-verified HTTPS Proxmox API URL ending in /api2/json."
  }
}
variable "proxmox_username" { type = string }
variable "node" { type = string }
variable "storage_pool" { type = string }
variable "bridge" { type = string }
variable "cpu_type" { type = string }
variable "vlan_tag" { type = string }
variable "ssh_host" { type = string }
variable "ip_address" { type = string }
variable "gateway" { type = string }
variable "nameserver" { type = string }
variable "seed_vm_id" {
  type = number
  validation {
    condition     = var.seed_vm_id >= 100 && var.seed_vm_id <= 999999999 && floor(var.seed_vm_id) == var.seed_vm_id
    error_message = "Reserve a valid integer seed VMID."
  }
}
variable "template_vm_id" {
  type = number
  validation {
    condition     = var.template_vm_id >= 100 && var.template_vm_id <= 999999999 && floor(var.template_vm_id) == var.template_vm_id
    error_message = "Reserve a valid integer build/template VMID."
  }
}
variable "image_version" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{8}(-[a-z0-9]+)?$", var.image_version))
    error_message = "Use YYYYMMDD or YYYYMMDD-revision."
  }
}
variable "source_commit" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{40}$", var.source_commit))
    error_message = "Supply the clean build configuration Git commit."
  }
}
variable "source_image_url" {
  type = string
  validation {
    condition     = can(regex("^https://", var.source_image_url))
    error_message = "Use a versioned vendor HTTPS cloud-image URL."
  }
}
variable "source_image_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.source_image_sha256))
    error_message = "Provide the independently verified vendor SHA256 digest."
  }
}

source "proxmox-clone" "server" {
  proxmox_url                         = var.proxmox_url
  username                            = var.proxmox_username
  insecure_skip_tls_verify            = false
  node                                = var.node
  clone_vm_id                         = var.seed_vm_id
  vm_id                               = var.template_vm_id
  full_clone                          = true
  vm_name                             = "zs-${var.os_profile}-${var.image_version}"
  template_name                       = "zs-${var.os_profile}-${var.image_version}"
  template_description                = "Experimental base; profile=${var.os_profile}; commit=${var.source_commit}; sha256=${var.source_image_sha256}"
  cores                               = 2
  sockets                             = 1
  memory                              = 2048
  cpu_type                            = var.cpu_type
  onboot                              = false
  qemu_agent                          = true
  scsi_controller                     = "virtio-scsi-pci"
  cloud_init                          = true
  cloud_init_storage_pool             = var.storage_pool
  cloud_init_disable_upgrade_packages = true
  ssh_username                        = var.ssh_user
  ssh_host                            = var.ssh_host
  ssh_timeout                         = "15m"
  ssh_clear_authorized_keys           = true
  nameserver                          = var.nameserver
  network_adapters {
    model    = "virtio"
    bridge   = var.bridge
    vlan_tag = var.vlan_tag
    firewall = true
  }
  ipconfig {
    ip      = var.ip_address
    gateway = var.gateway
  }
}

build {
  sources = ["source.proxmox-clone.server"]
  provisioner "shell" {
    inline = ["sudo cloud-init status --wait"]
  }
  provisioner "ansible" {
    playbook_file = "${path.root}/../../ansible/playbooks/10-build-base.yml"
    roles_path    = "${path.root}/../../ansible/roles"
    user          = var.ssh_user
    extra_arguments = ["--become", "--extra-vars", jsonencode({
      golden_profile             = var.os_profile
      golden_source_commit       = var.source_commit
      golden_source_image_url    = var.source_image_url
      golden_source_image_sha256 = var.source_image_sha256
    })]
  }
  provisioner "shell" {
    script          = "${path.root}/../../scripts/sanitize-guest.sh"
    execute_command = "sudo bash {{ .Path }}"
    skip_clean      = true
  }
  post-processor "manifest" {
    output     = "artifacts/${var.os_profile}-${var.image_version}.json"
    strip_path = true
    custom_data = {
      source_commit       = var.source_commit
      source_image_url    = var.source_image_url
      source_image_sha256 = var.source_image_sha256
      status              = "experimental-unaccepted"
    }
  }
}
