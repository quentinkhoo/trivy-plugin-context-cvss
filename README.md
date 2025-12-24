# trivy-plugin-context-cvss

Because sometimes a "Critical" is just a drama queen.

This project is basically a [Trivy](https://trivy.dev/) plugin that lets you introduce contextual metrics like [CVSS environmental metrics](https://www.first.org/cvss/v3-1/specification-document#Environmental-Metrics) into your Trivy scan results.

## 🧐 Why use this?
Standard CVSS scores assume the "worst-case scenario." This plugin lets you adjust scores based on your actual infrastructure:
- High Availability Clusters: If your app runs in a K8s cluster with 10 replicas behind a load balancer, a denial-of-service attack might be annoying, but it isn't catastrophic.
  - Solution: Recalculate with Modified Availability: Low (-ma=L).

- Private Networks / VPNs: If your server is sitting safely behind a corporate VPN or is air-gapped, a "Network" based attack is significantly harder to execute.
  - Solution: Recalculate with Modified Attack Vector: Adjacent (-mav=A).

🚀 Installation
```bash
trivy plugin install github.com/quentinkhoo/trivy-plugin-context-cvss
```

🛠 Usage
Example: Recalculate for a High Availability environment behind a secure VPN
```bash
trivy image local-app:latest -f json --output plugin=context-cvss --output-plugin-arg "-ma=N -mav=A"
```


## 📊Output
The plugin injects a new EnvironmentalMetrics object into the Custom field of the JSON report. It preserves the original Trivy finding while providing the context-aware score.
```json
{
  ...
  "Results": [
    ...
    "Vulnerabilities": [
      ...
      {
        "VulnerabilityID":"CVE-2025-49795",
        ...
        "Custom": {
          "ContextualMetrics": {
            "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/MAV:A/MA:N",
            "TemporalScore": 7.5,
            "TemporalRating": "HIGH",
            "EnvironmentalScore": 0,
            "EnvironmentalRating": "NONE"
          }
        },
        "CVSS": {
          "redhat": {
            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "V3Score": 7.5
          }
        }
      }
      ...
    ],
  ],
  ...
}
```