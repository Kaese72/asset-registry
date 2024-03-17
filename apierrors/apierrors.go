package apierrors

import (
	"encoding/json"
	"fmt"
)

type APIError struct {
	// Code indicates semantics based on HTTP status codes
	Code         int   `json:"code"`
	WrappedError error `json:"error"`
}

func (apierror APIError) MarshalJSON() ([]byte, error) {
	intermediary := struct {
		Code  int    `json:"code"`
		Error string `json:"error"`
	}{
		Code:  apierror.Code,
		Error: apierror.WrappedError.Error(),
	}
	bytes, err := json.Marshal(intermediary)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

func (apierror APIError) UnWrap() error {
	return apierror.WrappedError
}

func (apierror APIError) Error() string {
	return fmt.Sprintf("APIError: %s", apierror.WrappedError.Error())
}
