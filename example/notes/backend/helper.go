package notes

import (
	"encoding/json"
	"net/http"
	"strings"
)

func ParseErrorValidationMessage(message string) map[string]string {
	errorMap := make(map[string]string)
	parts := strings.Split(message, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		fieldError := strings.Split(part, ":")
		if len(fieldError) == 2 {
			field := strings.TrimSpace(fieldError[0])
			errorMsg := strings.TrimSpace(fieldError[1])
			errorMap[field] = errorMsg
		}
	}

	return errorMap
}

func WriteJsonResponse(w http.ResponseWriter, response interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(response)
}

func WriteJsonErrorResponse(w http.ResponseWriter, message any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	json.NewEncoder(w).Encode(map[string]any{
		"error": message,
	})
}

func WriteJsonErrorResponseWithStatus(w http.ResponseWriter, message any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(map[string]any{
		"error": message,
	})
}
