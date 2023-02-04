package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func New() provider.Provider {
	return &httpBinProvider{}
}

var _ provider.Provider = (*httpBinProvider)(nil)

type httpBinProvider struct{}

func (p *httpBinProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "http-bin"
}

func (p *httpBinProvider) Schema(context.Context, provider.SchemaRequest, *provider.SchemaResponse) {

}

func (p *httpBinProvider) Configure(context.Context, provider.ConfigureRequest, *provider.ConfigureResponse) {
}

func (p *httpBinProvider) Resources(context.Context) []func() resource.Resource {
	return nil
}

func (p *httpBinProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewHttpBinDataSource,
	}
}
