data "http-bin" "example" {
  url = "https://example.com/objects/artifact.zip"

  # Optional request headers
  request_headers = {
    Accept = "application/zip"
  }

  lifecycle {
    postcondition {
      condition     = contains([201, 204], self.status_code)
      error_message = "Status code invalid"
    }
  }
}