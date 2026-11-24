# Security policy

GoldenHoop is pre-release software. Published capability and verification matrices define the tested scope.

Please use GitHub's private vulnerability reporting for sensitive findings. Do not include live credentials or unrelated private data in reports.

The trusted boundary includes the host, administrators, control plane, worker, and gateway. Workload code, images, files, and model output are untrusted. Runtime escape resistance requires real-backend validation; language memory safety does not prove containment.
