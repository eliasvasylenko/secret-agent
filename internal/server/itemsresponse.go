package server

type ItemsResponse[T any] struct {
	Items T `json:"items"`
}
