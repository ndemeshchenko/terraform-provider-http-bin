data "http-bin" "example" {
  url = "https://example.com/objects/artifact.zip"

  # Optional request headers
  request_headers = {
    Accept = "application/zip"
  }
}

resource "random_uuid" "example" {
  lifecycle {
    precondition {
      condition     = contains([201, 204], data.http-bin.example.status_code)
      error_message = "Status code invalid"
    }
  }
}