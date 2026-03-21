package certysign

// DashboardResource provides analytics and reporting endpoints.
type DashboardResource struct {
	http *httpClient
}

func newDashboardResource(hc *httpClient) *DashboardResource {
	return &DashboardResource{http: hc}
}

// GetStats returns signing statistics for the authenticated subscriber.
//
// GET /sdk/v1/dashboard/stats
func (r *DashboardResource) GetStats(params map[string]string) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := r.http.get("/sdk/v1/dashboard/stats", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetRecipients returns a list of signing recipients.
//
// GET /sdk/v1/dashboard/recipients
func (r *DashboardResource) GetRecipients(params map[string]string) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := r.http.get("/sdk/v1/dashboard/recipients", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetDocuments returns a list of signed documents.
//
// GET /sdk/v1/dashboard/documents
func (r *DashboardResource) GetDocuments(params map[string]string) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := r.http.get("/sdk/v1/dashboard/documents", params, &result); err != nil {
		return nil, err
	}
	return result, nil
}
