# Optional demonstration of Conditional-Access-as-code via the azuread
# provider, entirely separate from the PowerShell-managed groups/policies
# elsewhere in this repo. Disabled by default (see var.enable_demo_terraform_ca_policy)
# to avoid creating objects that collide with Setup-TestTenant.ps1's output.

resource "azuread_group" "tf_demo_admins" {
  count            = var.enable_demo_terraform_ca_policy ? 1 : 0
  display_name     = "SG-TF-Demo-Admins"
  security_enabled = true
  description      = "Terraform-managed demo group, target of TF-DEMO-Block-LegacyAuthentication. Not part of the PowerShell-managed group set."
}

resource "azuread_conditional_access_policy" "tf_demo_block_legacy_auth" {
  count        = var.enable_demo_terraform_ca_policy ? 1 : 0
  display_name = "TF-DEMO-Block-LegacyAuthentication"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    client_app_types    = ["exchangeActiveSync", "other"]
    sign_in_risk_levels = []
    user_risk_levels    = []

    applications {
      included_applications = ["All"]
    }

    users {
      included_groups = [azuread_group.tf_demo_admins[0].object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}
