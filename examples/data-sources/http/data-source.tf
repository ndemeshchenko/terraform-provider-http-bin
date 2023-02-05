# The following example shows how to issue an HTTP GET request supplying
# an optional request header.
data "http-bin" "example" {
  url = "https://example.com/objects/artifact.zip"

  # Optional request headers
  request_headers = {
    Accept = "application/zip"
  }
}