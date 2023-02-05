package provider

import (
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var mockZipBase64 = "UEsDBAoAAAAAAKmCRFb0Ng0/BwAAAAcAAAAJABwAdGVzdC5maWxlVVQJAAPud95j8HfeY3V4CwABBPUBAAAEFAAAAHRlc3RtZQpQSwECHgMKAAAAAACpgkRW9DYNPwcAAAAHAAAACQAYAAAAAAABAAAApIEAAAAAdGVzdC5maWxlVVQFAAPud95jdXgLAAEE9QEAAAQUAAAAUEsFBgAAAAABAAEATwAAAEoAAAAAAA=="

func TestDataSource_zip(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(false)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
						data "http-bin" "this" {
							url = "%s/zip"
						}`, testHttpMock.server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.http-bin.this", "response_body", mockZipBase64),
				),
			},
		},
	})
}

func TestDataSource_404(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(false)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
						data "http-bin" "this" {
							url = "%s/404"
						}`, testHttpMock.server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.http-bin.this", "response_body", ""),
					resource.TestCheckResourceAttr("data.http-bin.this", "status_code", "404"),
				),
			},
		},
	})
}

func TestDataSource_withAuthorizationRequestHeader_200(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(false)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
								url = "%s/restricted"

								request_headers = {
									"Authorization" = "Zm9vOmJhcg=="
								}
							}`, testHttpMock.server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.http-bin.this", "response_body", mockZipBase64),
					resource.TestCheckResourceAttr("data.http-bin.this", "status_code", "200"),
				),
			},
		},
	})
}

func TestDataSource_withAuthorizationRequestHeader_403(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(false)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
  								url = "%s/restricted"

  								request_headers = {
    								"Authorization" = "unauthorized"
  								}
							}`, testHttpMock.server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.http-bin.this", "response_body", ""),
					resource.TestCheckResourceAttr("data.http-bin.this", "status_code", "403"),
				),
			},
		},
	})
}

func TestDataSource_UnsupportedMethod(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(false)

	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
 								url = "%s/200"
								method = "OPTIONS" 
							}`, testHttpMock.server.URL),
				ExpectError: regexp.MustCompile(`.*value must be one of: \["\\"GET\\"" "\\"POST\\"" "\\"HEAD\\""`),
			},
		},
	})
}

func TestDataSource_Provisioner(t *testing.T) {
	t.Parallel()

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A Content-Type that does not raise a warning in the Read function must be set in
		// order to prevent test failure under TF 0.14.x as warnings result in no output
		// being written which causes the local-exec command to fail with "Error:
		// local-exec provisioner command must be a non-empty string".
		// See https://github.com/hashicorp/terraform-provider-http/pull/74
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.Close()

	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		ExternalProviders: map[string]resource.ExternalProvider{
			"null": {
				VersionConstraint: "3.1.1",
				Source:            "hashicorp/null",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
								url = "%s"
							}
							resource "null_resource" "example" {
  								provisioner "local-exec" {
    								command = contains([201, 204], data.http-bin.this.status_code)
  								}
							}`, svr.URL),
				ExpectError: regexp.MustCompile(`Error running command 'false': exit status 1. Output:`),
			},
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
								url = "%s"
							}
							resource "null_resource" "example" {
  								provisioner "local-exec" {
    								command = contains([200], data.http-bin.this.status_code)
  								}
							}`, svr.URL),
				Check: resource.TestCheckResourceAttr("data.http-bin.this", "status_code", "200"),
			},
		},
	})
}

func TestDataSource_WithCACertificate(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(true)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
  								url = "%s/zip"

  								ca_cert_pem = <<EOF
%s
EOF
							}`, testHttpMock.server.URL, CertToPEM(testHttpMock.server.Certificate())),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.http-bin.this", "status_code", "200"),
				),
			},
		},
	})
}

func TestDataSource_WithCACertificateFalse(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(true)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
  								url = "%s/zip"

  								ca_cert_pem = "invalid"
							}`, testHttpMock.server.URL),
				ExpectError: regexp.MustCompile(`Can't add the CA certificate to certificate pool. Only PEM encoded\ncertificates are supported.`),
			},
		},
	})
}

func TestDataSource_InsecureTrue(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(true)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
  								url = "%s/zip"

  								insecure = true
							}`, testHttpMock.server.URL),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.http-bin.this", "status_code", "200"),
				),
			},
		},
	})
}

func TestDataSource_InsecureFalse(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(true)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
  								url = "%s/zip"

  								insecure = false
							}`, testHttpMock.server.URL),
				ExpectError: regexp.MustCompile(fmt.Sprintf(`Error making request: Get "%s/zip": x509: `, testHttpMock.server.URL)),
			},
		},
	})
}

func TestDataSource_InsecureUnconfigured(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(true)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
  								url = "%s/zip"
							}`, testHttpMock.server.URL),
				ExpectError: regexp.MustCompile(fmt.Sprintf(`Error making request: Get "%s/zip": x509: `, testHttpMock.server.URL)),
			},
		},
	})
}

func TestDataSource_UnsupportedInsecureCaCert(t *testing.T) {
	testHttpMock := setUpMockHTTPServer(true)
	defer testHttpMock.server.Close()

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
							data "http-bin" "this" {
 								url = "%s/zip"
								insecure = true
								ca_cert_pem = "invalid"
							}`, testHttpMock.server.URL),
				ExpectError: regexp.MustCompile(`Attribute "insecure" cannot be specified when "ca_cert_pem" is specified`),
			},
		},
	})
}

type TestHttpMock struct {
	server *httptest.Server
}

func setUpMockHTTPServer(tls bool) *TestHttpMock {
	var Server *httptest.Server

	if tls {
		Server = httptest.NewTLSServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpReqHandler(w, r)
			}),
		)
	} else {
		Server = httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpReqHandler(w, r)
			}),
		)
	}

	return &TestHttpMock{
		server: Server,
	}
}

func httpReqHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Add("X-Single", "foobar")
	w.Header().Add("X-Double", "1")
	w.Header().Add("X-Double", "2")

	switch r.URL.Path {
	case "/head":
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusOK)
		}
	case "/zip":
		w.WriteHeader(http.StatusOK)
		b64ResponseBody, _ := b64.StdEncoding.DecodeString(mockZipBase64)
		_, _ = w.Write(b64ResponseBody)
	case "/restricted":
		if r.Header.Get("Authorization") == "Zm9vOmJhcg==" {
			w.WriteHeader(http.StatusOK)
			b64ResponseBody, _ := b64.StdEncoding.DecodeString(mockZipBase64)
			_, _ = w.Write(b64ResponseBody)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// CertToPEM is a utility function returns a PEM encoded x509 Certificate.
func CertToPEM(cert *x509.Certificate) string {
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	return strings.Trim(certPem, "\n")
}
