data "http-bin" "example" {
  url = "https://example.com/objects/artifact.zip"

  # Optional request headers
  request_headers = {
    Accept = "application/zip"
  }
}

resource "null_resource" "example" {
  # On success, this will attempt to execute the true command in the
  # shell environment running terraform.
  # On failure, this will attempt to execute the false command in the
  # shell environment running terraform.
  provisioner "local-exec" {
    command = contains([201, 204], data.http-bin.example.status_code)
  }
}