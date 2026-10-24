package vercel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/vercel/terraform-provider-vercel/v5/client"
)

func TestResponseToLogDrainPreservesLegacySecret(t *testing.T) {
	t.Parallel()

	result, diags := responseToLogDrain(
		context.Background(),
		logDrainResponse("api-generated-signing-secret-that-must-be-persisted"),
		types.StringNull(),
		types.Int64Null(),
	)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if got := result.Secret.ValueString(); got != "api-generated-signing-secret-that-must-be-persisted" {
		t.Fatalf("Secret = %q, want API-generated legacy secret", got)
	}
	if !result.SecretWO.IsNull() {
		t.Fatalf("SecretWO = %s, want null", result.SecretWO)
	}
	if !result.SecretWOVersion.IsNull() {
		t.Fatalf("SecretWOVersion = %s, want null", result.SecretWOVersion)
	}
}

func TestResponseToLogDrainOmitsWriteOnlySecret(t *testing.T) {
	t.Parallel()

	result, diags := responseToLogDrain(
		context.Background(),
		logDrainResponse("api-secret-that-must-never-enter-terraform-state"),
		types.StringValue("configured-secret-that-must-never-enter-terraform-state"),
		types.Int64Value(7),
	)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if !result.Secret.IsNull() {
		t.Fatalf("Secret = %s, want null", result.Secret)
	}
	if !result.SecretWO.IsNull() {
		t.Fatalf("SecretWO = %s, want null", result.SecretWO)
	}
	if got := result.SecretWOVersion.ValueInt64(); got != 7 {
		t.Fatalf("SecretWOVersion = %d, want 7", got)
	}
}

func TestLogDrainWriteOnlySchema(t *testing.T) {
	t.Parallel()

	var response resource.SchemaResponse
	newLogDrainResource().Schema(context.Background(), resource.SchemaRequest{}, &response)
	if response.Diagnostics.HasError() {
		t.Fatal(response.Diagnostics)
	}
	if diags := response.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatal(diags)
	}

	secretWO, ok := response.Schema.Attributes["secret_wo"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("secret_wo attribute has unexpected type %T", response.Schema.Attributes["secret_wo"])
	}
	if !secretWO.Optional || !secretWO.Sensitive || !secretWO.WriteOnly || secretWO.Computed || secretWO.Required {
		t.Fatalf("unexpected secret_wo schema: %#v", secretWO)
	}

	version, ok := response.Schema.Attributes["secret_wo_version"].(schema.Int64Attribute)
	if !ok {
		t.Fatalf("secret_wo_version attribute has unexpected type %T", response.Schema.Attributes["secret_wo_version"])
	}
	if !version.Optional || version.Sensitive || version.WriteOnly || version.Computed || version.Required {
		t.Fatalf("unexpected secret_wo_version schema: %#v", version)
	}
	if len(version.PlanModifiers) == 0 {
		t.Fatal("secret_wo_version has no replacement plan modifier")
	}
}

func TestLogDrainCreateSendsWriteOnlySecretWithoutPersistingIt(t *testing.T) {
	t.Parallel()

	const configuredSecret = "configured-write-only-secret-at-least-thirty-two-characters"
	var receivedSecret string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/drains" || req.URL.Query().Get("teamId") != "team_123" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL)
			http.NotFound(w, req)
			return
		}
		var payload struct {
			Delivery struct {
				Secret string `json:"secret"`
			} `json:"delivery"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Errorf("decoding request: %s", err)
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		receivedSecret = payload.Delivery.Secret
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"id":"ld_123",
			"ownerId":"team_123",
			"name":"example",
			"projectIds":["prj_123"],
			"delivery":{"type":"http","endpoint":"https://example.com/logs","encoding":"ndjson","headers":{},"secret":"api-secret-that-must-never-enter-terraform-state"},
			"filterV2":{"version":"v2","filter":{"type":"basic","log":{"sources":["static"]},"deployment":{"environments":["production"]}}},
			"sampling":[]
		}`)
	}))
	defer server.Close()

	ctx := context.Background()
	providerResource := &logDrainResource{client: client.New("test").WithBaseURL(server.URL)}
	var schemaResponse resource.SchemaResponse
	providerResource.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	plan, config := logDrainCreatePlanAndConfig(t, schemaResponse.Schema, types.StringValue(configuredSecret))
	createResponse := resource.CreateResponse{State: tfsdk.State{Schema: schemaResponse.Schema}}
	providerResource.Create(ctx, resource.CreateRequest{Plan: plan, Config: config}, &createResponse)
	if createResponse.Diagnostics.HasError() {
		t.Fatal(createResponse.Diagnostics)
	}
	if receivedSecret != configuredSecret {
		t.Fatalf("API secret = %q, want configured write-only secret", receivedSecret)
	}

	var state LogDrain
	if diags := createResponse.State.Get(ctx, &state); diags.HasError() {
		t.Fatal(diags)
	}
	if !state.Secret.IsNull() {
		t.Fatalf("Secret = %s, want null", state.Secret)
	}
	if !state.SecretWO.IsNull() {
		t.Fatalf("SecretWO = %s, want null", state.SecretWO)
	}
	if got := state.SecretWOVersion.ValueInt64(); got != 7 {
		t.Fatalf("SecretWOVersion = %d, want 7", got)
	}
}

func TestLogDrainCreateRejectsUnknownWriteOnlySecret(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"id":"ld_123",
			"ownerId":"team_123",
			"name":"example",
			"projectIds":["prj_123"],
			"delivery":{"type":"http","endpoint":"https://example.com/logs","encoding":"ndjson","headers":{},"secret":"generated-secret"},
			"filterV2":{"version":"v2","filter":{"type":"basic","log":{"sources":["static"]},"deployment":{"environments":["production"]}}},
			"sampling":[]
		}`)
	}))
	defer server.Close()

	ctx := context.Background()
	providerResource := &logDrainResource{client: client.New("test").WithBaseURL(server.URL)}
	var schemaResponse resource.SchemaResponse
	providerResource.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)
	plan, config := logDrainCreatePlanAndConfig(t, schemaResponse.Schema, types.StringUnknown())
	createResponse := resource.CreateResponse{State: tfsdk.State{Schema: schemaResponse.Schema}}
	providerResource.Create(ctx, resource.CreateRequest{Plan: plan, Config: config}, &createResponse)

	if !createResponse.Diagnostics.HasError() {
		t.Fatal("Create() accepted an unknown secret_wo value")
	}
	if got := createResponse.Diagnostics.Errors()[0].Summary(); got != "Unknown write-only Log Drain secret" {
		t.Fatalf("Create() diagnostic summary = %q", got)
	}
	if requests != 0 {
		t.Fatalf("Create() sent %d API requests with an unknown secret_wo value", requests)
	}
}

func TestLogDrainImportSecretHandling(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/drains/ld_123" || req.URL.Query().Get("teamId") != "team_123" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL)
			http.NotFound(w, req)
			return
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{
			"id":"ld_123",
			"ownerId":"team_123",
			"name":"example",
			"projectIds":["prj_123"],
			"delivery":{"type":"http","endpoint":"https://example.com/logs","encoding":"ndjson","headers":{},"secret":"api-returned-signing-secret-at-least-thirty-two-characters"},
			"filterV2":{"version":"v2","filter":{"type":"basic","log":{"sources":["static"]},"deployment":{"environments":["production"]}}},
			"sampling":[]
		}`)
	}))
	defer server.Close()

	ctx := context.Background()
	providerResource := &logDrainResource{client: client.New("test").WithBaseURL(server.URL)}
	var schemaResponse resource.SchemaResponse
	providerResource.Schema(ctx, resource.SchemaRequest{}, &schemaResponse)

	for _, tc := range []struct {
		name                string
		importID            string
		wantSecret          string
		wantVersionNull     bool
		wantWriteOnlyMarker int64
	}{
		{
			name:            "legacy import preserves API secret",
			importID:        "team_123/ld_123",
			wantSecret:      "api-returned-signing-secret-at-least-thirty-two-characters",
			wantVersionNull: true,
		},
		{
			name:                "write-only import omits API secret",
			importID:            "write-only:team_123/ld_123",
			wantWriteOnlyMarker: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			importResponse := resource.ImportStateResponse{State: tfsdk.State{Schema: schemaResponse.Schema}}
			providerResource.ImportState(ctx, resource.ImportStateRequest{ID: tc.importID}, &importResponse)
			if importResponse.Diagnostics.HasError() {
				t.Fatal(importResponse.Diagnostics)
			}

			var state LogDrain
			if diags := importResponse.State.Get(ctx, &state); diags.HasError() {
				t.Fatal(diags)
			}
			if tc.wantSecret == "" {
				if !state.Secret.IsNull() {
					t.Fatalf("Secret = %s, want null", state.Secret)
				}
			} else if got := state.Secret.ValueString(); got != tc.wantSecret {
				t.Fatalf("Secret = %q, want %q", got, tc.wantSecret)
			}
			if !state.SecretWO.IsNull() {
				t.Fatalf("SecretWO = %s, want null", state.SecretWO)
			}
			if tc.wantVersionNull {
				if !state.SecretWOVersion.IsNull() {
					t.Fatalf("SecretWOVersion = %s, want null", state.SecretWOVersion)
				}
			} else if got := state.SecretWOVersion.ValueInt64(); got != tc.wantWriteOnlyMarker {
				t.Fatalf("SecretWOVersion = %d, want import marker %d", got, tc.wantWriteOnlyMarker)
			}
			if got := state.ID.ValueString(); got != "ld_123" {
				t.Fatalf("ID = %q, want ld_123", got)
			}
		})
	}
}

func logDrainCreatePlanAndConfig(t *testing.T, resourceSchema schema.Schema, secretWO types.String) (tfsdk.Plan, tfsdk.Config) {
	t.Helper()

	ctx := context.Background()
	planModel := LogDrain{
		ID:             types.StringUnknown(),
		TeamID:         types.StringValue("team_123"),
		Name:           types.StringValue("example"),
		DeliveryFormat: types.StringValue("ndjson"),
		Environments: types.SetValueMust(types.StringType, []attr.Value{
			types.StringValue("production"),
		}),
		Headers: types.MapValueMust(types.StringType, map[string]attr.Value{}),
		ProjectIDs: types.SetValueMust(types.StringType, []attr.Value{
			types.StringValue("prj_123"),
		}),
		SamplingRate:    types.Float64Null(),
		Secret:          types.StringUnknown(),
		SecretWO:        types.StringNull(),
		SecretWOVersion: types.Int64Value(7),
		Sources: types.SetValueMust(types.StringType, []attr.Value{
			types.StringValue("static"),
		}),
		Endpoint: types.StringValue("https://example.com/logs"),
	}
	plan := tfsdk.Plan{Schema: resourceSchema}
	if diags := plan.Set(ctx, planModel); diags.HasError() {
		t.Fatal(diags)
	}

	configModel := planModel
	configModel.ID = types.StringNull()
	configModel.Secret = types.StringNull()
	configModel.SecretWO = secretWO
	configState := tfsdk.State{Schema: resourceSchema}
	if diags := configState.Set(ctx, configModel); diags.HasError() {
		t.Fatal(diags)
	}

	return plan, tfsdk.Config{Schema: resourceSchema, Raw: configState.Raw}
}

func logDrainResponse(secret string) client.LogDrain {
	return client.LogDrain{
		ID:             "ld_123",
		TeamID:         "team_123",
		Name:           "example",
		DeliveryFormat: "ndjson",
		Environments:   []string{"production"},
		Headers:        map[string]string{},
		ProjectIDs:     []string{"prj_123"},
		Secret:         secret,
		Sources:        []string{"static"},
		Endpoint:       "https://example.com/logs",
	}
}
