import { execFileSync } from "node:child_process";

// Copy our custom generated Nginx HTTPS certificate so we can trust it and client etc won't get HTTPS errors.
execFileSync(
  "docker",
  [
    "compose",
    "-f",
    "conformance/proxy-compose.yml",
    "cp",
    "nginx-auth-server:/etc/nginx/tls.crt",
    "conformance/tls.crt",
  ],
  { stdio: "inherit" },
);
